"""storage.py — the ONLY interface layers above storage may depend on.

Three backends implement the same `Backend` protocol (same method
names/signatures) so nothing above this module needs to change
depending on which one is active:

- `InMemoryStore` — process-local, wiped on exit. Used by the test
  suite (constructed directly, never via the module-level default) and
  available as an explicit opt-out (`ATTACKMAPPER_STORAGE=memory`) for
  quick throwaway sessions.
- `SQLiteStore` — file-backed, stdlib-only (`sqlite3`). Persists to a
  single file (default `./attackmapper.db`, override with
  `ATTACKMAPPER_DB_PATH`), so a `attackmapper serve` session, or a
  `scan-nmap` + `infer` + `analyze` sequence of separate CLI
  invocations, all see the same data without needing a real database
  server. This is what makes "scan a real target, close the UI,
  reopen it later" actually work end to end -- previously (Phase A-G)
  `_default_store` was always a fresh in-memory instance, silently
  discarded on every process exit. The right choice when the process
  has a durable local disk to write to.
- `PostgresStore` — same protocol, backed by a real Postgres database
  (e.g. Neon) via `psycopg2`, for deployments (Render, etc.) where the
  filesystem is ephemeral and there's no persistent disk attached.
  Selected with `ATTACKMAPPER_STORAGE=postgres` plus a `DATABASE_URL`
  (Neon's own env var name, so no renaming needed) or
  `ATTACKMAPPER_DATABASE_URL`. Row ids are UUID-suffixed rather than a
  per-process counter, since a Postgres-backed deployment can restart
  or scale to more than one process and a resettable counter would
  collide with rows an earlier process already wrote.

Neither backend auto-loads the hand-verified demo topology by default
any more (`seed_demo_data` defaults to False on both). The demo
topology is still available on request -- `storage.seed_demo_data()`
(wired to `attackmapper seed-demo` / the UI's "load demo network"
action) -- for people who want the worked example from
ATTACKMAPPER_MASTER.md, but a fresh install now starts empty and ready
for a real target instead of looking pre-populated with fake hosts.

One structural node is still created automatically by both backends on
first use, demo data or not: `external` (the public internet / an
unauthenticated attacker), per the spec's fixed vocabulary for
Node.type and the convention every prompt/CLI example already assumes
("analyze --start external --target ..."). Without it, a fresh real
scan would have no valid `--start` node to analyze from until someone
manually poked at storage internals -- which is exactly what the
Phase B-G example scripts had to do by hand
(`storage._default_store._nodes["external"] = Node(...)`) before this
was made a first-class part of both backends' initialization.

No LLM calls happen anywhere in this file.
"""

from __future__ import annotations

import itertools
import json
import os
import sqlite3
import threading
import uuid
from typing import Protocol

import psycopg2
import psycopg2.extras

from .models import Edge, Node


class Backend(Protocol):
    """The shape any storage backend (in-memory, sqlite, ...) must
    implement. Module-level functions below delegate to whichever
    backend instance is currently active."""

    def load_graph(self, min_confidence: float) -> tuple[list[Node], list[Edge]]: ...
    def save_finding(self, finding: dict) -> None: ...
    def save_relationship(self, edge: Edge) -> str: ...
    def confirm_relationship(self, edge_id: str) -> None: ...
    def list_relationships(self, confirmed: bool | None) -> list[dict]: ...
    # Phase B additions: not in the original spec's four-function list
    # (that list is "the ONLY interface layers ABOVE storage may depend
    # on" — i.e. graph/path-finder/CLI/narration). Discovery sits below
    # storage and writes into it, so these are additive, not a change
    # to the contract layers 4+ rely on.
    def save_host(self, host: dict) -> str: ...
    def save_service(self, service: dict) -> None: ...
    def list_hosts(self) -> list[dict]: ...
    def list_services(self, host_id: str | None) -> list[dict]: ...
    def list_findings(self) -> list[dict]: ...
    # Live-network-usability additions (see module docstring): a clean
    # public way to add a non-host Node (an "external"/"account"/
    # "asset" node) instead of a caller reaching into a backend's
    # private attributes, and an explicit, opt-in way to load the demo
    # topology on top of whatever a backend already holds.
    def save_node(self, node: Node) -> None: ...
    def seed_demo_data(self) -> None: ...
    def reset(self) -> None: ...


# The demo topology (see the old inline docstring on _seed_demo_data
# for the full story): a small hand-verified lab -- external attacker
# -> internet-facing web server -> internal app server -> service
# account -> db -> crown-jewel asset -- plus one unconfirmed
# LLM-proposed shortcut edge to demonstrate confidence filtering.
# Factored out as module-level constants so both backends'
# seed_demo_data() insert the exact same data through their own
# storage representation, rather than one copy living only in
# InMemoryStore the way it used to.
DEMO_NODES: list[Node] = [
    Node(id="external", type="external", label="Internet"),
    Node(id="web", type="host", label="web01 (10.0.1.10)"),
    Node(id="app", type="host", label="app01 (10.0.2.10)"),
    Node(id="svc_account", type="account", label="svc_app (DB login role)"),
    Node(id="db", type="host", label="db01 (10.0.3.10)"),
    Node(id="customer_db", type="asset", label="customers table (crown jewel)"),
]

DEMO_EDGES: list[Edge] = [
    Edge(
        source="external",
        target="web",
        relationship="CAN_REACH",
        evidence="Port 443 open on web01, no source-IP ACL (nmap scan)",
        confirmed=True,
        confidence=1.0,
        proposed_by="discovery",
    ),
    Edge(
        source="web",
        target="app",
        relationship="CAN_REACH",
        evidence="web01 observed calling app01:8080 (netstat capture)",
        confirmed=True,
        confidence=1.0,
        proposed_by="discovery",
    ),
    Edge(
        source="app",
        target="svc_account",
        relationship="RUNS_AS",
        evidence="app01's process runs as svc_app per systemd unit file",
        confirmed=True,
        confidence=1.0,
        proposed_by="discovery",
    ),
    Edge(
        source="svc_account",
        target="db",
        relationship="CAN_ACCESS",
        evidence="svc_app has a login role in pg_hba.conf on db01",
        confirmed=True,
        confidence=1.0,
        proposed_by="discovery",
    ),
    Edge(
        source="db",
        target="customer_db",
        relationship="CAN_ACCESS",
        evidence="customers table is in the default schema db01 serves",
        confirmed=True,
        confidence=1.0,
        proposed_by="discovery",
    ),
    # An unconfirmed, LLM-proposed shortcut: not yet verified, so it
    # only shows up when the caller asks for min_confidence below 1.0.
    Edge(
        source="app",
        target="db",
        relationship="CAN_ACCESS",
        evidence="finding #7: app's ORM config embeds a DB password "
        "directly, suggesting it can reach db01 without going "
        "through svc_account's role",
        confirmed=False,
        confidence=0.65,
        proposed_by="llm",
    ),
]

# The one node every fresh store gets even without the demo topology
# -- see the module docstring for why.
_STRUCTURAL_NODES: list[Node] = [Node(id="external", type="external", label="Internet")]


class InMemoryStore:
    """Process-local backend. Holds nodes/edges/findings in plain dicts.
    Nothing here survives process exit -- use SQLiteStore (the default
    for real usage) for anything you want to persist.

    Edge identity: the public `Edge` dataclass (per spec) has no `id`
    field — that's a storage-internal concept. Internally every stored
    relationship gets a generated id so `confirm_relationship(edge_id)`
    has something to key off of; `list_relationships()` exposes those
    ids for CLI/review tooling, but `load_graph()` returns plain `Edge`
    objects exactly matching the spec's shape.
    """

    def __init__(self, seed_demo_data: bool = False) -> None:
        self._nodes: dict[str, Node] = {}
        self._relationships: dict[str, Edge] = {}  # id -> Edge
        self._findings: dict[str, dict] = {}
        self._hosts: dict[str, dict] = {}       # id -> raw host record
        self._services: dict[str, dict] = {}    # id -> raw service record
        self._id_counter = itertools.count(1)
        for n in _STRUCTURAL_NODES:
            self._nodes[n.id] = n
        if seed_demo_data:
            self.seed_demo_data()

    # -- internal helpers ------------------------------------------------

    def _new_id(self, prefix: str) -> str:
        return f"{prefix}-{next(self._id_counter)}"

    def seed_demo_data(self) -> None:
        """Load the hand-verified demo topology (see module-level
        DEMO_NODES/DEMO_EDGES) on top of whatever this store already
        holds. Additive and idempotent-ish: re-running it just
        re-inserts the same nodes (overwriting by id, same as any
        other save_node call) and appends another copy of the demo
        edges -- fine for its intended "load the worked example"
        use case, not meant to be called repeatedly in a real session.
        """
        for n in DEMO_NODES:
            self._nodes[n.id] = n
        for e in DEMO_EDGES:
            self._relationships[self._new_id("rel")] = e

    def reset(self) -> None:
        """Wipe every node/edge/finding/host/service back to a fresh,
        un-seeded store (still keeping the structural `external` node).
        Backs the UI/CLI "reset" action -- deliberately separate from
        `__init__` so a caller doesn't need to reconstruct the whole
        object (and, for SQLiteStore, drop and recreate its file) just
        to start over against the same target.
        """
        self._nodes = {n.id: n for n in _STRUCTURAL_NODES}
        self._relationships = {}
        self._findings = {}
        self._hosts = {}
        self._services = {}
        self._id_counter = itertools.count(1)

    # -- Backend protocol --------------------------------------------------

    def load_graph(self, min_confidence: float = 1.0) -> tuple[list[Node], list[Edge]]:
        nodes = list(self._nodes.values())
        edges = [
            e for e in self._relationships.values() if e.confidence >= min_confidence
        ]
        return nodes, edges

    def save_finding(self, finding: dict) -> None:
        required = {"host_id", "type", "severity", "description", "evidence"}
        missing = required - finding.keys()
        if missing:
            raise ValueError(f"finding missing required fields: {missing}")
        finding_id = finding.get("id") or self._new_id("finding")
        stored = dict(finding)
        stored["id"] = finding_id
        stored.setdefault("source", "scanner")
        stored.setdefault("confidence", 1.0)
        self._findings[finding_id] = stored

    def save_relationship(self, edge: Edge) -> str:
        edge_id = self._new_id("rel")
        self._relationships[edge_id] = edge
        return edge_id

    def confirm_relationship(self, edge_id: str) -> None:
        if edge_id not in self._relationships:
            raise KeyError(f"no relationship with id {edge_id!r}")
        old = self._relationships[edge_id]
        # Confirming resolves the uncertainty this edge was hedging on,
        # so confidence goes to 1.0 along with confirmed=True (see the
        # invariant enforced in Edge.__post_init__).
        self._relationships[edge_id] = Edge(
            source=old.source,
            target=old.target,
            relationship=old.relationship,
            evidence=old.evidence,
            confirmed=True,
            confidence=1.0,
            proposed_by=old.proposed_by,
        )

    def list_relationships(self, confirmed: bool | None = None) -> list[dict]:
        out = []
        for rel_id, edge in self._relationships.items():
            if confirmed is not None and edge.confirmed != confirmed:
                continue
            out.append({"id": rel_id, **edge.__dict__})
        return out

    def list_findings(self) -> list[dict]:
        return list(self._findings.values())

    # -- Phase B: hosts/services (feed discovery output into the graph) --

    def save_host(self, host: dict) -> str:
        """Insert-or-update by IP: re-scanning a known host updates its
        record (os, hostname, last_seen-style bookkeeping is left to a
        real DB's triggers in Phase B+; here we just overwrite) rather
        than creating duplicate Node/host entries every run.
        """
        required = {"hostname", "ip"}
        missing = required - host.keys()
        if missing:
            raise ValueError(f"host missing required fields: {missing}")

        existing_id = next(
            (hid for hid, h in self._hosts.items() if h["ip"] == host["ip"]), None
        )
        host_id = existing_id or self._new_id("host")
        stored = dict(host)
        stored["id"] = host_id
        stored.setdefault("os", None)
        self._hosts[host_id] = stored

        label = f"{host['hostname']} ({host['ip']})"
        self._nodes[host_id] = Node(id=host_id, type="host", label=label)
        return host_id

    def save_service(self, service: dict) -> None:
        required = {"host_id", "port", "protocol", "service_name"}
        missing = required - service.keys()
        if missing:
            raise ValueError(f"service missing required fields: {missing}")
        if service["host_id"] not in self._hosts:
            raise KeyError(f"no host with id {service['host_id']!r}")
        service_id = self._new_id("svc")
        stored = dict(service)
        stored["id"] = service_id
        self._services[service_id] = stored

    def list_hosts(self) -> list[dict]:
        return list(self._hosts.values())

    def list_services(self, host_id: str | None = None) -> list[dict]:
        services = list(self._services.values())
        if host_id is not None:
            services = [s for s in services if s["host_id"] == host_id]
        return services

    def save_node(self, node: Node) -> None:
        """Add (or overwrite by id) an arbitrary Node -- the clean,
        public replacement for the `store._nodes[id] = Node(...)`
        hack the Phase B-G example scripts used to reach for. Mainly
        for 'external'/'account'/'asset' nodes discovery doesn't
        create on its own (save_host already handles type='host')."""
        self._nodes[node.id] = node


class SQLiteStore:
    """Default backend for real (CLI/webapp) usage: same Backend
    protocol as InMemoryStore, persisted to a single sqlite3 file so
    state survives process restarts -- e.g. `attackmapper scan-nmap`,
    then quitting, then `attackmapper serve` later, both see the same
    hosts/findings/relationships.

    Deliberately stdlib-only (`sqlite3`), so persistence doesn't cost
    an extra dependency or a real database server the way the
    originally-planned Postgres backend would have. A single
    `threading.Lock` serializes access -- `attackmapper serve` runs a
    `ThreadingHTTPServer`, and sqlite3 connections aren't safe to share
    across threads without one.
    """

    def __init__(self, db_path: str, seed_demo_data: bool = False) -> None:
        self.db_path = db_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._id_counter = itertools.count(1)
        with self._lock:
            self._create_schema()
            self._ensure_structural_nodes()
        if seed_demo_data:
            self.seed_demo_data()

    # -- internal helpers ------------------------------------------------

    def _create_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS nodes (
                id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                label TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS edges (
                id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                target TEXT NOT NULL,
                relationship TEXT NOT NULL,
                evidence TEXT NOT NULL DEFAULT '',
                confirmed INTEGER NOT NULL,
                confidence REAL NOT NULL,
                proposed_by TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                host_id TEXT NOT NULL,
                type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                evidence TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT 'scanner',
                confidence REAL NOT NULL DEFAULT 1.0
            );
            CREATE TABLE IF NOT EXISTS hosts (
                id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                ip TEXT NOT NULL UNIQUE,
                os TEXT,
                extra TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS services (
                id TEXT PRIMARY KEY,
                host_id TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                service_name TEXT NOT NULL,
                extra TEXT NOT NULL DEFAULT '{}'
            );
            """
        )
        self._conn.commit()

    def _ensure_structural_nodes(self) -> None:
        for n in _STRUCTURAL_NODES:
            self._conn.execute(
                "INSERT OR IGNORE INTO nodes (id, type, label) VALUES (?, ?, ?)",
                (n.id, n.type, n.label),
            )
        self._conn.commit()

    def _new_id(self, prefix: str) -> str:
        # Prefixed monotonic counter, same convention as InMemoryStore,
        # but namespaced per-process; uniqueness within the db file is
        # what matters and PRIMARY KEY enforces that regardless.
        return f"{prefix}-{next(self._id_counter)}"

    def seed_demo_data(self) -> None:
        with self._lock:
            for n in DEMO_NODES:
                self._conn.execute(
                    "INSERT OR REPLACE INTO nodes (id, type, label) VALUES (?, ?, ?)",
                    (n.id, n.type, n.label),
                )
            for e in DEMO_EDGES:
                self._conn.execute(
                    "INSERT INTO edges (id, source, target, relationship, evidence, "
                    "confirmed, confidence, proposed_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        self._new_id("rel"),
                        e.source,
                        e.target,
                        e.relationship,
                        e.evidence,
                        int(e.confirmed),
                        e.confidence,
                        e.proposed_by,
                    ),
                )
            self._conn.commit()

    def reset(self) -> None:
        with self._lock:
            self._conn.executescript(
                "DELETE FROM nodes; DELETE FROM edges; DELETE FROM findings; "
                "DELETE FROM hosts; DELETE FROM services;"
            )
            self._conn.commit()
            self._ensure_structural_nodes()

    # -- Backend protocol --------------------------------------------------

    def load_graph(self, min_confidence: float = 1.0) -> tuple[list[Node], list[Edge]]:
        with self._lock:
            node_rows = self._conn.execute("SELECT id, type, label FROM nodes").fetchall()
            edge_rows = self._conn.execute(
                "SELECT source, target, relationship, evidence, confirmed, "
                "confidence, proposed_by FROM edges WHERE confidence >= ?",
                (min_confidence,),
            ).fetchall()
        nodes = [Node(id=r["id"], type=r["type"], label=r["label"]) for r in node_rows]
        edges = [
            Edge(
                source=r["source"],
                target=r["target"],
                relationship=r["relationship"],
                evidence=r["evidence"],
                confirmed=bool(r["confirmed"]),
                confidence=r["confidence"],
                proposed_by=r["proposed_by"],
            )
            for r in edge_rows
        ]
        return nodes, edges

    def save_finding(self, finding: dict) -> None:
        required = {"host_id", "type", "severity", "description", "evidence"}
        missing = required - finding.keys()
        if missing:
            raise ValueError(f"finding missing required fields: {missing}")
        with self._lock:
            finding_id = finding.get("id") or self._new_id("finding")
            self._conn.execute(
                "INSERT OR REPLACE INTO findings (id, host_id, type, severity, "
                "description, evidence, source, confidence) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    finding_id,
                    finding["host_id"],
                    finding["type"],
                    finding["severity"],
                    finding["description"],
                    finding["evidence"],
                    finding.get("source", "scanner"),
                    finding.get("confidence", 1.0),
                ),
            )
            self._conn.commit()

    def save_relationship(self, edge: Edge) -> str:
        with self._lock:
            edge_id = self._new_id("rel")
            self._conn.execute(
                "INSERT INTO edges (id, source, target, relationship, evidence, "
                "confirmed, confidence, proposed_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    edge_id,
                    edge.source,
                    edge.target,
                    edge.relationship,
                    edge.evidence,
                    int(edge.confirmed),
                    edge.confidence,
                    edge.proposed_by,
                ),
            )
            self._conn.commit()
        return edge_id

    def confirm_relationship(self, edge_id: str) -> None:
        with self._lock:
            row = self._conn.execute(
                "SELECT proposed_by FROM edges WHERE id = ?", (edge_id,)
            ).fetchone()
            if row is None:
                raise KeyError(f"no relationship with id {edge_id!r}")
            # Same invariant as InMemoryStore: confirming resolves the
            # hedge, so confidence jumps to 1.0 alongside confirmed=1.
            self._conn.execute(
                "UPDATE edges SET confirmed = 1, confidence = 1.0 WHERE id = ?",
                (edge_id,),
            )
            self._conn.commit()

    def list_relationships(self, confirmed: bool | None = None) -> list[dict]:
        with self._lock:
            if confirmed is None:
                rows = self._conn.execute(
                    "SELECT id, source, target, relationship, evidence, confirmed, "
                    "confidence, proposed_by FROM edges"
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT id, source, target, relationship, evidence, confirmed, "
                    "confidence, proposed_by FROM edges WHERE confirmed = ?",
                    (int(confirmed),),
                ).fetchall()
        return [
            {
                "id": r["id"],
                "source": r["source"],
                "target": r["target"],
                "relationship": r["relationship"],
                "evidence": r["evidence"],
                "confirmed": bool(r["confirmed"]),
                "confidence": r["confidence"],
                "proposed_by": r["proposed_by"],
            }
            for r in rows
        ]

    def list_findings(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, host_id, type, severity, description, evidence, "
                "source, confidence FROM findings"
            ).fetchall()
        return [dict(r) for r in rows]

    # -- Phase B: hosts/services (feed discovery output into the graph) --

    def save_host(self, host: dict) -> str:
        """Insert-or-update by IP, same semantics as InMemoryStore.
        Any extra keys beyond hostname/ip/os are round-tripped through
        a JSON 'extra' column rather than dropped, so callers aren't
        limited to exactly the three columns this schema has native
        fields for.
        """
        required = {"hostname", "ip"}
        missing = required - host.keys()
        if missing:
            raise ValueError(f"host missing required fields: {missing}")

        extra = {k: v for k, v in host.items() if k not in {"hostname", "ip", "os", "id"}}
        with self._lock:
            existing = self._conn.execute(
                "SELECT id FROM hosts WHERE ip = ?", (host["ip"],)
            ).fetchone()
            host_id = existing["id"] if existing else self._new_id("host")
            self._conn.execute(
                "INSERT OR REPLACE INTO hosts (id, hostname, ip, os, extra) "
                "VALUES (?, ?, ?, ?, ?)",
                (host_id, host["hostname"], host["ip"], host.get("os"), json.dumps(extra)),
            )
            label = f"{host['hostname']} ({host['ip']})"
            self._conn.execute(
                "INSERT OR REPLACE INTO nodes (id, type, label) VALUES (?, 'host', ?)",
                (host_id, label),
            )
            self._conn.commit()
        return host_id

    def save_service(self, service: dict) -> None:
        required = {"host_id", "port", "protocol", "service_name"}
        missing = required - service.keys()
        if missing:
            raise ValueError(f"service missing required fields: {missing}")
        extra = {
            k: v
            for k, v in service.items()
            if k not in {"host_id", "port", "protocol", "service_name", "id"}
        }
        with self._lock:
            host_exists = self._conn.execute(
                "SELECT 1 FROM hosts WHERE id = ?", (service["host_id"],)
            ).fetchone()
            if not host_exists:
                raise KeyError(f"no host with id {service['host_id']!r}")
            service_id = self._new_id("svc")
            self._conn.execute(
                "INSERT INTO services (id, host_id, port, protocol, service_name, extra) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    service_id,
                    service["host_id"],
                    service["port"],
                    service["protocol"],
                    service["service_name"],
                    json.dumps(extra),
                ),
            )
            self._conn.commit()

    def list_hosts(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, hostname, ip, os, extra FROM hosts"
            ).fetchall()
        out = []
        for r in rows:
            record = {"id": r["id"], "hostname": r["hostname"], "ip": r["ip"], "os": r["os"]}
            record.update(json.loads(r["extra"] or "{}"))
            out.append(record)
        return out

    def list_services(self, host_id: str | None = None) -> list[dict]:
        with self._lock:
            if host_id is None:
                rows = self._conn.execute(
                    "SELECT id, host_id, port, protocol, service_name, extra FROM services"
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT id, host_id, port, protocol, service_name, extra "
                    "FROM services WHERE host_id = ?",
                    (host_id,),
                ).fetchall()
        out = []
        for r in rows:
            record = {
                "id": r["id"],
                "host_id": r["host_id"],
                "port": r["port"],
                "protocol": r["protocol"],
                "service_name": r["service_name"],
            }
            record.update(json.loads(r["extra"] or "{}"))
            out.append(record)
        return out

    def save_node(self, node: Node) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO nodes (id, type, label) VALUES (?, ?, ?)",
                (node.id, node.type, node.label),
            )
            self._conn.commit()


class PostgresStore:
    """Same `Backend` protocol as `SQLiteStore`, backed by a real
    Postgres database (e.g. Neon) via `psycopg2` instead of a local
    file -- for deployments where the filesystem is ephemeral (Render
    without a persistent disk, most serverless-ish PaaS setups) and a
    `.db` file would be wiped on every restart/redeploy.

    Schema and method-by-method behavior deliberately mirror
    `SQLiteStore` exactly (same tables, same required-field checks,
    same insert-or-update-by-ip semantics for hosts) so switching
    `ATTACKMAPPER_STORAGE` doesn't change what any caller above this
    module sees -- only where the bytes live.

    One real difference: id generation. `SQLiteStore._new_id` is a
    per-process monotonic counter, which is safe there because a
    sqlite file and the process reading/writing it are 1:1. A
    Postgres-backed deployment doesn't have that guarantee -- a
    restart, redeploy, or a second instance would restart the counter
    at 1 and collide with rows an earlier process already committed.
    So ids here are `<prefix>-<uuid4 hex>` instead.
    """

    def __init__(self, dsn: str, seed_demo_data: bool = False) -> None:
        self.dsn = dsn
        self._lock = threading.Lock()
        self._conn = psycopg2.connect(dsn)
        self._conn.autocommit = False
        with self._lock:
            self._create_schema()
            self._ensure_structural_nodes()
        if seed_demo_data:
            self.seed_demo_data()

    # -- internal helpers ------------------------------------------------

    def _cursor(self):
        return self._conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    def _create_schema(self) -> None:
        with self._cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS nodes (
                    id TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    label TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS edges (
                    id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    target TEXT NOT NULL,
                    relationship TEXT NOT NULL,
                    evidence TEXT NOT NULL DEFAULT '',
                    confirmed BOOLEAN NOT NULL,
                    confidence DOUBLE PRECISION NOT NULL,
                    proposed_by TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    host_id TEXT NOT NULL,
                    type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT NOT NULL,
                    evidence TEXT NOT NULL,
                    source TEXT NOT NULL DEFAULT 'scanner',
                    confidence DOUBLE PRECISION NOT NULL DEFAULT 1.0
                );
                CREATE TABLE IF NOT EXISTS hosts (
                    id TEXT PRIMARY KEY,
                    hostname TEXT NOT NULL,
                    ip TEXT NOT NULL UNIQUE,
                    os TEXT,
                    extra TEXT NOT NULL DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS services (
                    id TEXT PRIMARY KEY,
                    host_id TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    service_name TEXT NOT NULL,
                    extra TEXT NOT NULL DEFAULT '{}'
                );
                """
            )
        self._conn.commit()

    def _ensure_structural_nodes(self) -> None:
        with self._cursor() as cur:
            for n in _STRUCTURAL_NODES:
                cur.execute(
                    "INSERT INTO nodes (id, type, label) VALUES (%s, %s, %s) "
                    "ON CONFLICT (id) DO NOTHING",
                    (n.id, n.type, n.label),
                )
        self._conn.commit()

    def _new_id(self, prefix: str) -> str:
        return f"{prefix}-{uuid.uuid4().hex[:12]}"

    def seed_demo_data(self) -> None:
        with self._lock:
            with self._cursor() as cur:
                for n in DEMO_NODES:
                    cur.execute(
                        "INSERT INTO nodes (id, type, label) VALUES (%s, %s, %s) "
                        "ON CONFLICT (id) DO UPDATE SET type = EXCLUDED.type, "
                        "label = EXCLUDED.label",
                        (n.id, n.type, n.label),
                    )
                for e in DEMO_EDGES:
                    cur.execute(
                        "INSERT INTO edges (id, source, target, relationship, evidence, "
                        "confirmed, confidence, proposed_by) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                        (
                            self._new_id("rel"),
                            e.source,
                            e.target,
                            e.relationship,
                            e.evidence,
                            e.confirmed,
                            e.confidence,
                            e.proposed_by,
                        ),
                    )
            self._conn.commit()

    def reset(self) -> None:
        with self._lock:
            with self._cursor() as cur:
                cur.execute(
                    "TRUNCATE nodes, edges, findings, hosts, services"
                )
            self._conn.commit()
            self._ensure_structural_nodes()

    # -- Backend protocol --------------------------------------------------

    def load_graph(self, min_confidence: float = 1.0) -> tuple[list[Node], list[Edge]]:
        with self._lock:
            with self._cursor() as cur:
                cur.execute("SELECT id, type, label FROM nodes")
                node_rows = cur.fetchall()
                cur.execute(
                    "SELECT source, target, relationship, evidence, confirmed, "
                    "confidence, proposed_by FROM edges WHERE confidence >= %s",
                    (min_confidence,),
                )
                edge_rows = cur.fetchall()
        nodes = [Node(id=r["id"], type=r["type"], label=r["label"]) for r in node_rows]
        edges = [
            Edge(
                source=r["source"],
                target=r["target"],
                relationship=r["relationship"],
                evidence=r["evidence"],
                confirmed=bool(r["confirmed"]),
                confidence=r["confidence"],
                proposed_by=r["proposed_by"],
            )
            for r in edge_rows
        ]
        return nodes, edges

    def save_finding(self, finding: dict) -> None:
        required = {"host_id", "type", "severity", "description", "evidence"}
        missing = required - finding.keys()
        if missing:
            raise ValueError(f"finding missing required fields: {missing}")
        with self._lock:
            finding_id = finding.get("id") or self._new_id("finding")
            with self._cursor() as cur:
                cur.execute(
                    "INSERT INTO findings (id, host_id, type, severity, description, "
                    "evidence, source, confidence) VALUES (%s, %s, %s, %s, %s, %s, %s, %s) "
                    "ON CONFLICT (id) DO UPDATE SET host_id = EXCLUDED.host_id, "
                    "type = EXCLUDED.type, severity = EXCLUDED.severity, "
                    "description = EXCLUDED.description, evidence = EXCLUDED.evidence, "
                    "source = EXCLUDED.source, confidence = EXCLUDED.confidence",
                    (
                        finding_id,
                        finding["host_id"],
                        finding["type"],
                        finding["severity"],
                        finding["description"],
                        finding["evidence"],
                        finding.get("source", "scanner"),
                        finding.get("confidence", 1.0),
                    ),
                )
            self._conn.commit()

    def save_relationship(self, edge: Edge) -> str:
        with self._lock:
            edge_id = self._new_id("rel")
            with self._cursor() as cur:
                cur.execute(
                    "INSERT INTO edges (id, source, target, relationship, evidence, "
                    "confirmed, confidence, proposed_by) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                    (
                        edge_id,
                        edge.source,
                        edge.target,
                        edge.relationship,
                        edge.evidence,
                        edge.confirmed,
                        edge.confidence,
                        edge.proposed_by,
                    ),
                )
            self._conn.commit()
        return edge_id

    def confirm_relationship(self, edge_id: str) -> None:
        with self._lock:
            with self._cursor() as cur:
                cur.execute("SELECT proposed_by FROM edges WHERE id = %s", (edge_id,))
                row = cur.fetchone()
                if row is None:
                    raise KeyError(f"no relationship with id {edge_id!r}")
                cur.execute(
                    "UPDATE edges SET confirmed = TRUE, confidence = 1.0 WHERE id = %s",
                    (edge_id,),
                )
            self._conn.commit()

    def list_relationships(self, confirmed: bool | None = None) -> list[dict]:
        with self._lock:
            with self._cursor() as cur:
                if confirmed is None:
                    cur.execute(
                        "SELECT id, source, target, relationship, evidence, confirmed, "
                        "confidence, proposed_by FROM edges"
                    )
                else:
                    cur.execute(
                        "SELECT id, source, target, relationship, evidence, confirmed, "
                        "confidence, proposed_by FROM edges WHERE confirmed = %s",
                        (confirmed,),
                    )
                rows = cur.fetchall()
        return [
            {
                "id": r["id"],
                "source": r["source"],
                "target": r["target"],
                "relationship": r["relationship"],
                "evidence": r["evidence"],
                "confirmed": bool(r["confirmed"]),
                "confidence": r["confidence"],
                "proposed_by": r["proposed_by"],
            }
            for r in rows
        ]

    def list_findings(self) -> list[dict]:
        with self._lock:
            with self._cursor() as cur:
                cur.execute(
                    "SELECT id, host_id, type, severity, description, evidence, "
                    "source, confidence FROM findings"
                )
                rows = cur.fetchall()
        return [dict(r) for r in rows]

    # -- Phase B: hosts/services (feed discovery output into the graph) --

    def save_host(self, host: dict) -> str:
        required = {"hostname", "ip"}
        missing = required - host.keys()
        if missing:
            raise ValueError(f"host missing required fields: {missing}")

        extra = {k: v for k, v in host.items() if k not in {"hostname", "ip", "os", "id"}}
        with self._lock:
            with self._cursor() as cur:
                cur.execute("SELECT id FROM hosts WHERE ip = %s", (host["ip"],))
                existing = cur.fetchone()
                host_id = existing["id"] if existing else self._new_id("host")
                cur.execute(
                    "INSERT INTO hosts (id, hostname, ip, os, extra) "
                    "VALUES (%s, %s, %s, %s, %s) "
                    "ON CONFLICT (id) DO UPDATE SET hostname = EXCLUDED.hostname, "
                    "ip = EXCLUDED.ip, os = EXCLUDED.os, extra = EXCLUDED.extra",
                    (host_id, host["hostname"], host["ip"], host.get("os"), json.dumps(extra)),
                )
                label = f"{host['hostname']} ({host['ip']})"
                cur.execute(
                    "INSERT INTO nodes (id, type, label) VALUES (%s, 'host', %s) "
                    "ON CONFLICT (id) DO UPDATE SET type = 'host', label = EXCLUDED.label",
                    (host_id, label),
                )
            self._conn.commit()
        return host_id

    def save_service(self, service: dict) -> None:
        required = {"host_id", "port", "protocol", "service_name"}
        missing = required - service.keys()
        if missing:
            raise ValueError(f"service missing required fields: {missing}")
        extra = {
            k: v
            for k, v in service.items()
            if k not in {"host_id", "port", "protocol", "service_name", "id"}
        }
        with self._lock:
            with self._cursor() as cur:
                cur.execute("SELECT 1 FROM hosts WHERE id = %s", (service["host_id"],))
                host_exists = cur.fetchone()
                if not host_exists:
                    raise KeyError(f"no host with id {service['host_id']!r}")
                service_id = self._new_id("svc")
                cur.execute(
                    "INSERT INTO services (id, host_id, port, protocol, service_name, extra) "
                    "VALUES (%s, %s, %s, %s, %s, %s)",
                    (
                        service_id,
                        service["host_id"],
                        service["port"],
                        service["protocol"],
                        service["service_name"],
                        json.dumps(extra),
                    ),
                )
            self._conn.commit()

    def list_hosts(self) -> list[dict]:
        with self._lock:
            with self._cursor() as cur:
                cur.execute("SELECT id, hostname, ip, os, extra FROM hosts")
                rows = cur.fetchall()
        out = []
        for r in rows:
            record = {"id": r["id"], "hostname": r["hostname"], "ip": r["ip"], "os": r["os"]}
            record.update(json.loads(r["extra"] or "{}"))
            out.append(record)
        return out

    def list_services(self, host_id: str | None = None) -> list[dict]:
        with self._lock:
            with self._cursor() as cur:
                if host_id is None:
                    cur.execute(
                        "SELECT id, host_id, port, protocol, service_name, extra FROM services"
                    )
                else:
                    cur.execute(
                        "SELECT id, host_id, port, protocol, service_name, extra "
                        "FROM services WHERE host_id = %s",
                        (host_id,),
                    )
                rows = cur.fetchall()
        out = []
        for r in rows:
            record = {
                "id": r["id"],
                "host_id": r["host_id"],
                "port": r["port"],
                "protocol": r["protocol"],
                "service_name": r["service_name"],
            }
            record.update(json.loads(r["extra"] or "{}"))
            out.append(record)
        return out

    def save_node(self, node: Node) -> None:
        with self._lock:
            with self._cursor() as cur:
                cur.execute(
                    "INSERT INTO nodes (id, type, label) VALUES (%s, %s, %s) "
                    "ON CONFLICT (id) DO UPDATE SET type = EXCLUDED.type, "
                    "label = EXCLUDED.label",
                    (node.id, node.type, node.label),
                )
            self._conn.commit()


def _build_default_store() -> Backend:
    """Choose the module-level default backend at import time.

    ATTACKMAPPER_STORAGE selects the backend: "sqlite" (default) for a
    persistent local file, "postgres"/"postgresql" for a real Postgres
    database (e.g. Neon), or "memory" for a process-local store that's
    wiped on exit -- useful for CI-style throwaway runs or quickly
    trying something without leaving a .db file behind.

    ATTACKMAPPER_DB_PATH overrides the sqlite file location (default:
    "attackmapper.db" in the current working directory). Only read
    when backend_kind is "sqlite".

    For "postgres"/"postgresql", the connection string is read from
    DATABASE_URL (Neon's own env var name, so a Neon-provisioned
    integration needs no renaming) or, if that's unset,
    ATTACKMAPPER_DATABASE_URL. Missing both raises immediately rather
    than silently falling back to sqlite, since that fallback would
    look like persistence working right up until the next redeploy
    wipes an ephemeral filesystem.

    ATTACKMAPPER_SEED_DEMO=1 additionally loads the demo topology into
    whichever backend gets picked, for anyone who wants the worked
    example available immediately without a separate CLI/UI action.

    Never used by the test suite, which always constructs its own
    InMemoryStore explicitly and either uses it standalone or
    monkeypatches `_default_store` -- so nothing here affects test
    behavior regardless of how these env vars happen to be set.
    """
    seed = os.environ.get("ATTACKMAPPER_SEED_DEMO", "").lower() in {"1", "true", "yes"}
    backend_kind = os.environ.get("ATTACKMAPPER_STORAGE", "sqlite").lower()
    if backend_kind == "memory":
        return InMemoryStore(seed_demo_data=seed)
    if backend_kind in {"postgres", "postgresql"}:
        dsn = os.environ.get("DATABASE_URL") or os.environ.get("ATTACKMAPPER_DATABASE_URL")
        if not dsn:
            raise RuntimeError(
                "ATTACKMAPPER_STORAGE=postgres requires DATABASE_URL "
                "(or ATTACKMAPPER_DATABASE_URL) to be set to a Postgres "
                "connection string, e.g. Neon's pooled connection string."
            )
        return PostgresStore(dsn, seed_demo_data=seed)
    db_path = os.environ.get("ATTACKMAPPER_DB_PATH", "attackmapper.db")
    return SQLiteStore(db_path, seed_demo_data=seed)


# Module-level default backend + delegating functions. This is the
# surface every other layer imports from (`from attackmapper import
# storage`), keeping the persistent-vs-in-memory choice (and, before
# that, the swap-to-Postgres-that-never-shipped choice) confined to
# this file.
_default_store: Backend = _build_default_store()


def load_graph(min_confidence: float = 1.0) -> tuple[list[Node], list[Edge]]:
    """Return all nodes, and edges with confidence >= min_confidence.
    Passing min_confidence=1.0 (default) returns only confirmed,
    deterministic edges — i.e. the safe/conservative view."""
    return _default_store.load_graph(min_confidence)


def save_finding(finding: dict) -> None:
    _default_store.save_finding(finding)


def save_relationship(edge: Edge) -> str:
    return _default_store.save_relationship(edge)


def confirm_relationship(edge_id: str) -> None:
    """Promote an LLM-proposed edge to confirmed=True, e.g. after a
    human review or a deterministic verification step."""
    _default_store.confirm_relationship(edge_id)


def list_relationships(confirmed: bool | None = None) -> list[dict]:
    return _default_store.list_relationships(confirmed)


def save_host(host: dict) -> str:
    return _default_store.save_host(host)


def save_service(service: dict) -> None:
    _default_store.save_service(service)


def list_hosts() -> list[dict]:
    return _default_store.list_hosts()


def list_services(host_id: str | None = None) -> list[dict]:
    return _default_store.list_services(host_id)


def list_findings() -> list[dict]:
    return _default_store.list_findings()


def save_node(node: Node) -> None:
    """Add (or overwrite by id) an arbitrary Node -- see
    Backend.save_node / InMemoryStore.save_node for why this exists."""
    _default_store.save_node(node)


def seed_demo_data() -> None:
    """Load the hand-verified demo topology into the current store.
    Opt-in only (see module docstring) -- wired to `attackmapper
    seed-demo` and the UI's "load demo network" action."""
    _default_store.seed_demo_data()


def reset() -> None:
    """Wipe the current store back to empty (still keeping the
    structural 'external' node). Wired to `attackmapper reset` and the
    UI's "reset" action."""
    _default_store.reset()


def describe_backend() -> str:
    """A one-line human description of the active backend, for CLI/UI
    startup banners -- e.g. so `attackmapper serve` can tell someone
    exactly which .db file their scan results are landing in (or that
    they picked the non-persistent in-memory backend and everything
    will be lost on exit)."""
    if isinstance(_default_store, SQLiteStore):
        return f"persistent storage at {_default_store.db_path}"
    if isinstance(_default_store, PostgresStore):
        return "persistent storage on Postgres"
    return "in-memory storage (ATTACKMAPPER_STORAGE=memory) -- nothing survives process exit"
