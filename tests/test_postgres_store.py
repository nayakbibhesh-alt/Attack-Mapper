"""Tests for storage.PostgresStore -- same contract as SQLiteStore,
backed by a real Postgres database.

These need a live database to talk to, unlike the rest of the suite,
so they're skipped by default. Run them yourself against your own
Neon database before trusting it in production:

    ATTACKMAPPER_TEST_DATABASE_URL="postgresql://...neon.tech/dbname?sslmode=require" \
        pytest tests/test_postgres_store.py -v

Each test gets a fresh set of tables truncated via reset() up front
(pytest fixture) rather than a fresh database per test, since spinning
up a new Neon database per test is slow -- this is a shared-connection,
truncate-between-tests pattern instead of SQLiteStore's throwaway
temp-file-per-test pattern.
"""

import os

import pytest

from attackmapper.models import Edge, Node

DSN = os.environ.get("ATTACKMAPPER_TEST_DATABASE_URL")

pytestmark = pytest.mark.skipif(
    not DSN,
    reason="set ATTACKMAPPER_TEST_DATABASE_URL to a real Postgres DSN to run these",
)

# Imported lazily / only referenced inside tests so that collecting this
# file doesn't require psycopg2 to successfully connect anywhere -- the
# skipif above already keeps these from running without a DSN, but this
# keeps a plain `pytest` (no DSN set) from even importing storage's
# psycopg2 dependency path differently than the rest of the suite does.
from attackmapper.storage import PostgresStore  # noqa: E402


@pytest.fixture
def store():
    s = PostgresStore(DSN, seed_demo_data=False)
    s.reset()  # start every test from a clean slate on the shared db
    yield s


def test_fresh_store_has_only_the_structural_external_node(store):
    nodes, edges = store.load_graph()
    assert [n.id for n in nodes] == ["external"]
    assert edges == []


def test_seed_demo_data_loads_full_topology(store):
    store.seed_demo_data()
    nodes, edges = store.load_graph(min_confidence=1.0)
    assert {n.id for n in nodes} == {
        "external", "web", "app", "svc_account", "db", "customer_db",
    }
    assert all(e.confidence >= 1.0 for e in edges)


def test_save_and_list_host(store):
    host_id = store.save_host({"hostname": "web01", "ip": "10.0.1.10", "os": "Linux"})
    hosts = store.list_hosts()
    assert len(hosts) == 1
    assert hosts[0]["id"] == host_id
    assert hosts[0]["ip"] == "10.0.1.10"
    nodes, _ = store.load_graph()
    assert any(n.id == host_id and n.type == "host" for n in nodes)


def test_save_host_upserts_by_ip(store):
    id1 = store.save_host({"hostname": "web01", "ip": "10.0.1.10", "os": None})
    id2 = store.save_host({"hostname": "web01-renamed", "ip": "10.0.1.10", "os": "Linux"})
    assert id1 == id2
    hosts = store.list_hosts()
    assert len(hosts) == 1
    assert hosts[0]["hostname"] == "web01-renamed"


def test_save_host_round_trips_extra_fields(store):
    host_id = store.save_host(
        {"hostname": "web01", "ip": "10.0.1.10", "os": None, "notes": "found via subnet sweep"}
    )
    hosts = store.list_hosts()
    assert hosts[0]["id"] == host_id
    assert hosts[0]["notes"] == "found via subnet sweep"


def test_save_service_requires_known_host(store):
    with pytest.raises(KeyError):
        store.save_service(
            {"host_id": "no-such-host", "port": 22, "protocol": "tcp", "service_name": "ssh"}
        )


def test_save_finding_requires_fields(store):
    with pytest.raises(ValueError):
        store.save_finding({"type": "ssrf"})


def test_delete_findings_for_host_scoped_by_source(store):
    host_id = store.save_host({"hostname": "web01", "ip": "10.0.1.10", "os": None})
    store.save_finding(
        {
            "host_id": host_id,
            "type": "exposed_sensitive_path",
            "severity": "critical",
            "description": "stale scanner finding",
            "evidence": "e",
            "source": "scanner",
        }
    )
    store.save_finding(
        {
            "host_id": host_id,
            "type": "analyst_note",
            "severity": "low",
            "description": "manual note",
            "evidence": "e",
            "source": "manual",
        }
    )

    deleted = store.delete_findings_for_host(host_id, source="scanner")
    assert deleted == 1

    remaining = store.list_findings()
    assert len(remaining) == 1
    assert remaining[0]["source"] == "manual"


def test_save_relationship_and_confirm(store):
    edge = Edge(
        source="external", target="web", relationship="CAN_REACH",
        confirmed=False, confidence=0.5, proposed_by="llm",
    )
    edge_id = store.save_relationship(edge)
    unconfirmed = store.list_relationships(confirmed=False)
    assert len(unconfirmed) == 1
    assert unconfirmed[0]["id"] == edge_id

    store.confirm_relationship(edge_id)
    confirmed = store.list_relationships(confirmed=True)
    assert len(confirmed) == 1
    assert confirmed[0]["confidence"] == 1.0


def test_confirm_relationship_raises_on_unknown_id(store):
    with pytest.raises(KeyError):
        store.confirm_relationship("no-such-id")


def test_load_graph_filters_by_min_confidence(store):
    store.save_relationship(
        Edge(source="a", target="b", relationship="CAN_REACH", confirmed=True, confidence=1.0)
    )
    store.save_relationship(
        Edge(
            source="a", target="c", relationship="CAN_REACH",
            confirmed=False, confidence=0.4, proposed_by="llm",
        )
    )
    _, edges_strict = store.load_graph(min_confidence=1.0)
    _, edges_loose = store.load_graph(min_confidence=0.3)
    assert len(edges_strict) == 1
    assert len(edges_loose) == 2


def test_save_node_adds_arbitrary_node(store):
    store.save_node(Node(id="svc_account", type="account", label="svc_app"))
    nodes, _ = store.load_graph()
    assert any(n.id == "svc_account" and n.type == "account" for n in nodes)


def test_reset_clears_everything_but_keeps_external(store):
    store.seed_demo_data()
    store.save_host({"hostname": "web01", "ip": "10.0.1.10", "os": None})
    store.reset()
    nodes, edges = store.load_graph()
    assert [n.id for n in nodes] == ["external"]
    assert edges == []
    assert store.list_hosts() == []
    assert store.list_findings() == []


def test_data_persists_across_separate_store_instances(store):
    """The point of PostgresStore: a brand new PostgresStore pointed
    at the same DSN (simulating a fresh Render process/instance) sees
    everything an earlier instance wrote."""
    host_id = store.save_host({"hostname": "web01", "ip": "10.0.1.10", "os": "Linux"})
    store.save_service(
        {"host_id": host_id, "port": 22, "protocol": "tcp", "service_name": "ssh"}
    )
    store.save_relationship(
        Edge(source="external", target=host_id, relationship="CAN_REACH", confidence=1.0)
    )

    store2 = PostgresStore(DSN, seed_demo_data=False)
    assert len(store2.list_hosts()) == 1
    assert store2.list_hosts()[0]["ip"] == "10.0.1.10"
    assert len(store2.list_services(host_id=host_id)) == 1
    nodes, edges = store2.load_graph()
    assert {n.id for n in nodes} == {"external", host_id}
    assert len(edges) == 1
