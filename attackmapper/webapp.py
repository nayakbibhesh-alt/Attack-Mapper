"""webapp.py — a browser UI for AttackMapper, served over the same
Layers 3-6 the CLI uses.

This is not a mock: every endpoint here calls the real functions in
`storage.py`, `graph.py`, and (lazily, exactly like `cli.py`) the LLM
modules under `inference/`, `narration/`, and `discovery/`. There is
no separate copy of the data model — the browser is just another
client of the same persistent store (see storage.py's module
docstring: a SQLite file by default) the CLI reads and writes, so
actions taken from one are visible from the other across separate
process runs, not just within one.

Stdlib only (`http.server`), so `python3 -m attackmapper.webapp` works
with zero extra installs beyond what running the CLI already needs.
LLM-backed endpoints (`/api/analyze` with narrate=true, `/api/ask`,
`/api/infer`, `/api/interpret-evidence`, `/api/discover`) require
OPENROUTER_API_KEY exactly as the equivalent CLI commands do; if it's
missing, the endpoint returns the same RuntimeError message the CLI
would print, as JSON, rather than crashing the server.
"""

from __future__ import annotations

import base64
import dataclasses
import hmac
import json
import logging
import os
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, parse_qs

from . import remediation, storage
from .graph import AttackGraph

logger = logging.getLogger(__name__)

WEB_DIR = Path(__file__).parent / "web"

# Basic Auth, gated by two env vars so a Render deployment (or anyone
# else exposing this over the open internet) can lock the whole UI —
# every route, static file included — behind a single shared
# credential. See main()'s startup banner for the un-set case: rather
# than silently running open, it prints a loud warning every time the
# server starts without these set, so "I forgot to set the env vars"
# is never a silent mistake.
AUTH_USER = os.environ.get("ATTACKMAPPER_AUTH_USER")
AUTH_PASS = os.environ.get("ATTACKMAPPER_AUTH_PASS")
AUTH_ENABLED = bool(AUTH_USER and AUTH_PASS)


def _check_basic_auth(header_value: str | None) -> bool:
    """Validate a raw `Authorization` header value against
    AUTH_USER/AUTH_PASS. Returns True (nothing to check) when auth
    isn't configured at all, matching the "off by default in dev,
    opt-in for anything reachable over the network" posture — but note
    main() refuses to silently pretend this is fine (see its startup
    banner). Uses hmac.compare_digest on both the username and
    password separately, rather than comparing the decoded "user:pass"
    string in one shot, so a match on a correct username doesn't leak
    partial timing information about the password via a single
    combined comparison being marginally faster to fail on."""
    if not AUTH_ENABLED:
        return True
    if not header_value or not header_value.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(header_value[len("Basic ") :]).decode("utf-8")
        user, _, password = decoded.partition(":")
    except Exception:
        return False
    return hmac.compare_digest(user, AUTH_USER) and hmac.compare_digest(password, AUTH_PASS)


def jsonable(obj):
    """Recursively convert dataclasses (Edge, Node, Finding) to plain
    dicts so json.dumps can handle them, leaving everything else
    (plain dicts/lists/str/float/bool/None from storage.py's own
    dict-returning methods) untouched."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: jsonable(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, dict):
        return {k: jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [jsonable(v) for v in obj]
    return obj


def serialize_path(path) -> dict:
    return {
        "confidence": AttackGraph.path_confidence(path),
        "hops": jsonable(path),
        "description": _describe(path),
    }


def _describe(path) -> str:
    # Mirrors AttackGraph.describe_path exactly (it only reads the path
    # argument, so this avoids needing a graph instance just to format one).
    if not path:
        return ""
    parts = [path[0].source]
    for edge in path:
        marker = (
            f"--{edge.relationship}-->"
            if edge.confirmed
            else f"~~{edge.relationship}~~(unconfirmed, conf={edge.confidence:.2f})~~>"
        )
        parts.append(marker)
        parts.append(edge.target)
    return " ".join(parts)


class Api:
    """Route handlers. Each returns (status_code, body_dict)."""

    @staticmethod
    def get_state(_qs):
        nodes, _ = storage.load_graph(min_confidence=0.0)
        return 200, {
            "nodes": jsonable(nodes),
            "relationships": jsonable(storage.list_relationships()),
            "hosts": storage.list_hosts(),
            "services": storage.list_services(),
            "findings": [
                {**f, "remedy": remediation.remedy_for(f["type"])}
                for f in storage.list_findings()
            ],
            "backend": storage.describe_backend(),
        }

    @staticmethod
    def get_graph(qs):
        min_confidence = float(qs.get("min_confidence", ["1.0"])[0])
        nodes, edges = storage.load_graph(min_confidence=min_confidence)
        # Enrich with relationship ids (storage-internal, but the UI
        # needs something to key a "confirm" action on) the same way
        # cli.cmd_edges does via list_relationships.
        by_key = {}
        for r in storage.list_relationships():
            by_key[(r["source"], r["target"], r["relationship"], r["evidence"])] = r["id"]
        edge_dicts = []
        for e in edges:
            d = jsonable(e)
            d["id"] = by_key.get((e.source, e.target, e.relationship, e.evidence))
            edge_dicts.append(d)
        return 200, {"nodes": jsonable(nodes), "edges": edge_dicts}

    @staticmethod
    def get_relationships(qs):
        filt = qs.get("filter", ["all"])[0]
        confirmed = {"all": None, "confirmed": True, "unconfirmed": False}.get(filt)
        return 200, {"relationships": storage.list_relationships(confirmed=confirmed)}

    @staticmethod
    def post_confirm(edge_id, _body):
        try:
            storage.confirm_relationship(edge_id)
        except KeyError as exc:
            return 404, {"error": str(exc)}
        return 200, {"confirmed": edge_id}

    @staticmethod
    def get_hosts(_qs):
        return 200, {"hosts": storage.list_hosts()}

    @staticmethod
    def get_services(qs):
        host_id = qs.get("host_id", [None])[0]
        return 200, {"services": storage.list_services(host_id=host_id)}

    @staticmethod
    def get_findings(_qs):
        findings = [
            {**f, "remedy": remediation.remedy_for(f["type"])}
            for f in storage.list_findings()
        ]
        return 200, {"findings": findings}

    @staticmethod
    def post_analyze(body):
        start = body.get("start")
        target = body.get("target")
        min_confidence = float(body.get("min_confidence", 1.0))
        narrate = bool(body.get("narrate", False))

        nodes, edges = storage.load_graph(min_confidence=min_confidence)
        node_ids = {n.id for n in nodes}
        if start not in node_ids:
            return 400, {"error": f"unknown start node {start!r}", "known_nodes": sorted(node_ids)}
        if target not in node_ids:
            return 400, {"error": f"unknown target node {target!r}", "known_nodes": sorted(node_ids)}

        graph = AttackGraph(nodes, edges)
        paths = graph.find_all_paths(start, target)
        ranked = sorted(paths, key=AttackGraph.path_confidence, reverse=True)
        result = {"paths": [serialize_path(p) for p in ranked]}

        if narrate and ranked:
            from .narration import risk_llm

            try:
                narration = risk_llm.narrate_path(ranked[0], nodes)
                result["narration"] = narration
            except RuntimeError as exc:
                result["narration_error"] = str(exc)
        return 200, result

    @staticmethod
    def post_ask(body):
        question = body.get("question", "")
        min_confidence = float(body.get("min_confidence", 1.0))
        from .narration import nl_interface

        try:
            result = nl_interface.ask(question, min_confidence=min_confidence)
        except RuntimeError as exc:
            return 424, {"error": str(exc)}
        return 200, jsonable(result)

    @staticmethod
    def post_infer(body):
        compare = bool(body.get("compare", False))
        from .inference import relationship_llm

        try:
            proposed = relationship_llm.infer_relationships()
        except RuntimeError as exc:
            return 424, {"error": str(exc)}
        out = {"proposed": jsonable(proposed)}
        if compare:
            report = relationship_llm.compare_proposed_to_confirmed(proposed)
            out["comparison"] = jsonable(report)
        return 200, out

    @staticmethod
    def post_interpret_evidence(body):
        host_id = body.get("host_id")
        evidence_type = body.get("evidence_type")
        text = body.get("text", "")
        if not host_id or not evidence_type or not text:
            return 400, {"error": "host_id, evidence_type and text are all required"}
        from .discovery import pipeline

        try:
            summary = pipeline.ingest_ambiguous_evidence(host_id, evidence_type, text)
        except RuntimeError as exc:
            return 424, {"error": str(exc)}
        return 200, summary

    @staticmethod
    def post_scan_nmap(body):
        target = body.get("target")
        ports = body.get("ports", "1-1024")
        if not target:
            return 400, {"error": "target is required"}
        from .discovery import pipeline

        try:
            summary = pipeline.ingest_nmap_scan(target, ports=ports)
        except RuntimeError as exc:
            return 424, {"error": str(exc)}
        return 200, summary

    @staticmethod
    def post_scan_url(body):
        target = body.get("target")
        if not target:
            return 400, {"error": "target is required"}
        run_nmap = bool(body.get("run_nmap", True))
        chain_findings = bool(body.get("chain_findings", True))
        from .discovery import pipeline

        try:
            result = pipeline.scan_target_url(
                target, run_nmap=run_nmap, chain_findings=chain_findings
            )
        except RuntimeError as exc:
            return 424, {"error": str(exc)}

        findings = [
            {**f, "remedy": remediation.remedy_for(f["type"])}
            for f in result["findings"]
        ]
        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        findings.sort(key=lambda f: severity_rank.get(f.get("severity"), 4))

        return 200, {
            "target": result["target"],
            "hostname": result["hostname"],
            "ip": result["ip"],
            "host_id": result["host_id"],
            "findings": findings,
            "paths": [serialize_path(p) for p in result["paths"]],
            "subdomains": result.get("subdomains", []),
            "chains": result.get("chains", []),
            "chains_error": result.get("chains_error"),
            "errors": result["errors"],
        }

    @staticmethod
    def post_chain_findings(body):
        """Standalone attack-chain reasoning, independent of a scan --
        for re-running the analysis after storage.list_findings()
        picked up more findings some other way (a raw nmap scan, the
        discovery loop, a manually-interpreted piece of evidence)
        without re-running every web probe. Optionally scoped to one
        host_id; otherwise reasons over every finding currently in
        storage."""
        host_id = body.get("host_id")
        from .narration import attack_chain_llm

        findings = storage.list_findings()
        hosts = storage.list_hosts()
        services = storage.list_services()
        if host_id:
            findings = [f for f in findings if f["host_id"] == host_id]
            hosts = [h for h in hosts if h["id"] == host_id]
            services = [s for s in services if s["host_id"] == host_id]

        try:
            chains = attack_chain_llm.find_attack_chains(
                findings=findings, hosts=hosts, services=services
            )
        except RuntimeError as exc:
            return 424, {"error": str(exc)}
        return 200, {"chains": chains, "findings_considered": len(findings)}

    @staticmethod
    def post_discover(body):
        scope = body.get("scope") or []
        if isinstance(scope, str):
            scope = [s.strip() for s in scope.split(",") if s.strip()]
        max_iterations = int(body.get("max_iterations", 5))
        max_actions = int(body.get("max_actions", 3))
        review_threshold = float(body.get("review_threshold", 0.75))
        from .discovery import agentic_loop

        try:
            result = agentic_loop.run_discovery_loop(
                scope,
                max_iterations=max_iterations,
                max_actions_per_iteration=max_actions,
                review_threshold=review_threshold,
            )
        except (agentic_loop.ScopeError, RuntimeError) as exc:
            return 400, {"error": str(exc)}
        return 200, result

    @staticmethod
    def post_seed_demo(_body):
        storage.seed_demo_data()
        return 200, {"seeded": True}

    @staticmethod
    def post_reset(body):
        if not body.get("confirm"):
            return 400, {
                "error": "reset requires {\"confirm\": true} in the request "
                "body -- this clears every host, service, finding, and "
                "relationship in the current store"
            }
        storage.reset()
        return 200, {"reset": True}


ROUTES_GET = {
    "/api/state": Api.get_state,
    "/api/graph": Api.get_graph,
    "/api/relationships": Api.get_relationships,
    "/api/hosts": Api.get_hosts,
    "/api/services": Api.get_services,
    "/api/findings": Api.get_findings,
}

ROUTES_POST = {
    "/api/analyze": Api.post_analyze,
    "/api/ask": Api.post_ask,
    "/api/infer": Api.post_infer,
    "/api/interpret-evidence": Api.post_interpret_evidence,
    "/api/scan-nmap": Api.post_scan_nmap,
    "/api/scan-url": Api.post_scan_url,
    "/api/chain-findings": Api.post_chain_findings,
    "/api/discover": Api.post_discover,
    "/api/seed-demo": Api.post_seed_demo,
    "/api/reset": Api.post_reset,
}


class Handler(BaseHTTPRequestHandler):
    server_version = "AttackMapperUI/1.0"

    def log_message(self, fmt, *args):  # quieter default logging
        logger.info("%s - %s", self.address_string(), fmt % args)

    def _send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: Path, content_type: str):
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _require_auth(self) -> bool:
        """Returns True if the request may proceed. Otherwise sends the
        401 challenge itself (so callers can just `return` on False)."""
        if _check_basic_auth(self.headers.get("Authorization")):
            return True
        body = json.dumps({"error": "authentication required"}).encode("utf-8")
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="AttackMapper"')
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        return False

    def do_GET(self):
        if not self._require_auth():
            return
        parsed = urlsplit(self.path)
        qs = parse_qs(parsed.query)

        if parsed.path in ("/", "/index.html"):
            self._send_file(WEB_DIR / "index.html", "text/html; charset=utf-8")
            return

        handler = ROUTES_GET.get(parsed.path)
        if handler is None:
            self._send_json(404, {"error": f"no such route: {parsed.path}"})
            return
        try:
            status, payload = handler(qs)
        except Exception as exc:  # last-resort guard so the server never dies
            logger.exception("unhandled error in %s", parsed.path)
            status, payload = 500, {"error": str(exc)}
        self._send_json(status, payload)

    def do_POST(self):
        if not self._require_auth():
            return
        parsed = urlsplit(self.path)
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            self._send_json(400, {"error": "request body must be JSON"})
            return

        handler = ROUTES_POST.get(parsed.path)
        if handler is None:
            # /api/relationships/<id>/confirm
            parts = parsed.path.strip("/").split("/")
            if len(parts) == 4 and parts[0] == "api" and parts[1] == "relationships" and parts[3] == "confirm":
                try:
                    status, payload = Api.post_confirm(parts[2], body)
                except Exception as exc:
                    logger.exception("unhandled error confirming relationship")
                    status, payload = 500, {"error": str(exc)}
                self._send_json(status, payload)
                return
            self._send_json(404, {"error": f"no such route: {parsed.path}"})
            return

        try:
            status, payload = handler(body)
        except Exception as exc:
            logger.exception("unhandled error in %s", parsed.path)
            status, payload = 500, {"error": str(exc)}
        self._send_json(status, payload)


def main(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True) -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    server = ThreadingHTTPServer((host, port), Handler)
    url = f"http://{host}:{port}/"
    print(f"AttackMapper UI running at {url}  (Ctrl+C to stop)")
    print(f"Backend: {storage.describe_backend()}")
    if AUTH_ENABLED:
        print(f"Access control: Basic Auth required (user={AUTH_USER!r}).")
    else:
        print(
            "*** WARNING: no ATTACKMAPPER_AUTH_USER/ATTACKMAPPER_AUTH_PASS "
            "set -- every route (including /api/reset and every scan "
            "endpoint) is reachable by anyone who can reach this address. "
            "Fine for localhost-only use; set both env vars before "
            "exposing this over a network. ***"
        )
    print(
        "Scan a real target from the Hosts view (or `attackmapper scan-nmap`) "
        "to get started -- nothing is preloaded by default. Want the worked "
        "example instead? `attackmapper seed-demo` or the UI's 'load demo "
        "network' button."
    )
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
        server.shutdown()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Serve the AttackMapper browser UI.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    main(host=args.host, port=args.port, open_browser=not args.no_browser)
