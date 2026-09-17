"""Tests for storage.SQLiteStore -- the persistent Backend
implementation used by default for real (CLI/webapp) usage.

Each test gets its own temp-file db path (pytest's tmp_path fixture)
so tests never share state or leave files behind. Runs the same
contract InMemoryStore is tested against in test_storage.py, plus
persistence-specific tests (reopening the same file, JSON round-trip
of extra host/service fields) that only make sense for a file-backed
store.
"""

import pytest

from attackmapper.models import Edge, Node
from attackmapper.storage import SQLiteStore


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test.db")


def test_fresh_store_has_only_the_structural_external_node(db_path):
    store = SQLiteStore(db_path, seed_demo_data=False)
    nodes, edges = store.load_graph()
    assert [n.id for n in nodes] == ["external"]
    assert edges == []


def test_seed_demo_data_loads_full_topology(db_path):
    store = SQLiteStore(db_path, seed_demo_data=True)
    nodes, edges = store.load_graph(min_confidence=1.0)
    assert {n.id for n in nodes} == {
        "external", "web", "app", "svc_account", "db", "customer_db",
    }
    assert all(e.confidence >= 1.0 for e in edges)


def test_save_and_list_host(db_path):
    store = SQLiteStore(db_path, seed_demo_data=False)
    host_id = store.save_host({"hostname": "web01", "ip": "10.0.1.10", "os": "Linux"})
    hosts = store.list_hosts()
    assert len(hosts) == 1
    assert hosts[0]["id"] == host_id
    assert hosts[0]["ip"] == "10.0.1.10"
    # save_host should also add a corresponding graph Node.
    nodes, _ = store.load_graph()
    assert any(n.id == host_id and n.type == "host" for n in nodes)


def test_save_host_upserts_by_ip(db_path):
    store = SQLiteStore(db_path, seed_demo_data=False)
    id1 = store.save_host({"hostname": "web01", "ip": "10.0.1.10", "os": None})
    id2 = store.save_host({"hostname": "web01-renamed", "ip": "10.0.1.10", "os": "Linux"})
    assert id1 == id2
    hosts = store.list_hosts()
    assert len(hosts) == 1
    assert hosts[0]["hostname"] == "web01-renamed"
    assert hosts[0]["os"] == "Linux"


def test_save_host_round_trips_extra_fields(db_path):
    store = SQLiteStore(db_path, seed_demo_data=False)
    host_id = store.save_host(
        {"hostname": "web01", "ip": "10.0.1.10", "os": None, "notes": "found via subnet sweep"}
    )
    hosts = store.list_hosts()
    assert hosts[0]["id"] == host_id
    assert hosts[0]["notes"] == "found via subnet sweep"


def test_save_service_requires_known_host(db_path):
    store = SQLiteStore(db_path, seed_demo_data=False)
    with pytest.raises(KeyError):
        store.save_service(
            {"host_id": "no-such-host", "port": 22, "protocol": "tcp", "service_name": "ssh"}
        )


def test_save_service_and_filter_by_host(db_path):
    store = SQLiteStore(db_path, seed_demo_data=False)
    h1 = store.save_host({"hostname": "web01", "ip": "10.0.1.10", "os": None})
    h2 = store.save_host({"hostname": "app01", "ip": "10.0.2.10", "os": None})
    store.save_service({"host_id": h1, "port": 443, "protocol": "tcp", "service_name": "https"})
    store.save_service({"host_id": h2, "port": 8080, "protocol": "tcp", "service_name": "http"})
    assert len(store.list_services()) == 2
    assert len(store.list_services(host_id=h1)) == 1
    assert store.list_services(host_id=h1)[0]["service_name"] == "https"


def test_save_finding_requires_fields(db_path):
    store = SQLiteStore(db_path, seed_demo_data=False)
    with pytest.raises(ValueError):
        store.save_finding({"type": "ssrf"})


def test_save_finding_defaults_source_and_confidence(db_path):
    store = SQLiteStore(db_path, seed_demo_data=False)
    store.save_finding(
        {
            "host_id": "web",
            "type": "ssrf",
            "severity": "high",
            "description": "d",
            "evidence": "e",
        }
    )
    findings = store.list_findings()
    assert len(findings) == 1
    assert findings[0]["source"] == "scanner"
    assert findings[0]["confidence"] == 1.0


def test_delete_findings_for_host_scoped_by_source(db_path):
    store = SQLiteStore(db_path, seed_demo_data=False)
    store.save_finding(
        {
            "host_id": "web",
            "type": "exposed_sensitive_path",
            "severity": "critical",
            "description": "stale scanner finding",
            "evidence": "e",
            "source": "scanner",
        }
    )
    store.save_finding(
        {
            "host_id": "web",
            "type": "analyst_note",
            "severity": "low",
            "description": "manual note",
            "evidence": "e",
            "source": "manual",
        }
    )

    deleted = store.delete_findings_for_host("web", source="scanner")
    assert deleted == 1

    remaining = store.list_findings()
    assert len(remaining) == 1
    assert remaining[0]["source"] == "manual"


def test_delete_findings_for_host_without_source_clears_all_sources(db_path):
    store = SQLiteStore(db_path, seed_demo_data=False)
    store.save_finding(
        {
            "host_id": "web",
            "type": "a",
            "severity": "low",
            "description": "d",
            "evidence": "e",
            "source": "scanner",
        }
    )
    store.save_finding(
        {
            "host_id": "web",
            "type": "b",
            "severity": "low",
            "description": "d",
            "evidence": "e",
            "source": "manual",
        }
    )
    deleted = store.delete_findings_for_host("web")
    assert deleted == 2
    assert store.list_findings() == []


def test_save_relationship_and_confirm(db_path):
    store = SQLiteStore(db_path, seed_demo_data=False)
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


def test_confirm_relationship_raises_on_unknown_id(db_path):
    store = SQLiteStore(db_path, seed_demo_data=False)
    with pytest.raises(KeyError):
        store.confirm_relationship("no-such-id")


def test_load_graph_filters_by_min_confidence(db_path):
    store = SQLiteStore(db_path, seed_demo_data=False)
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


def test_save_node_adds_arbitrary_node(db_path):
    store = SQLiteStore(db_path, seed_demo_data=False)
    store.save_node(Node(id="svc_account", type="account", label="svc_app"))
    nodes, _ = store.load_graph()
    assert any(n.id == "svc_account" and n.type == "account" for n in nodes)


def test_reset_clears_everything_but_keeps_external(db_path):
    store = SQLiteStore(db_path, seed_demo_data=True)
    store.save_host({"hostname": "web01", "ip": "10.0.1.10", "os": None})
    store.reset()
    nodes, edges = store.load_graph()
    assert [n.id for n in nodes] == ["external"]
    assert edges == []
    assert store.list_hosts() == []
    assert store.list_findings() == []


def test_data_persists_across_separate_store_instances(db_path):
    """The whole point of SQLiteStore over InMemoryStore: reopening
    the same file (simulating a fresh `attackmapper` process) sees
    everything the previous instance wrote."""
    store1 = SQLiteStore(db_path, seed_demo_data=False)
    host_id = store1.save_host({"hostname": "web01", "ip": "10.0.1.10", "os": "Linux"})
    store1.save_service(
        {"host_id": host_id, "port": 22, "protocol": "tcp", "service_name": "ssh"}
    )
    store1.save_finding(
        {
            "host_id": host_id, "type": "outdated_software", "severity": "medium",
            "description": "old openssh", "evidence": "banner",
        }
    )
    store1.save_relationship(
        Edge(source="external", target=host_id, relationship="CAN_REACH", confidence=1.0)
    )

    # Simulate a new process: a brand new SQLiteStore pointed at the
    # same file, with no reference to store1 at all.
    store2 = SQLiteStore(db_path, seed_demo_data=False)
    assert len(store2.list_hosts()) == 1
    assert store2.list_hosts()[0]["ip"] == "10.0.1.10"
    assert len(store2.list_services(host_id=host_id)) == 1
    assert len(store2.list_findings()) == 1
    nodes, edges = store2.load_graph()
    assert {n.id for n in nodes} == {"external", host_id}
    assert len(edges) == 1
