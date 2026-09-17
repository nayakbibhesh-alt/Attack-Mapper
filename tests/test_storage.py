"""Tests for the storage interface. Uses fresh InMemoryStore instances
(not the module-level default) so tests don't leak state into each
other. No live infra required.
"""

import pytest

from attackmapper.models import Edge
from attackmapper.storage import InMemoryStore


def test_seeded_demo_graph_has_confirmed_path_only_by_default():
    store = InMemoryStore(seed_demo_data=True)
    nodes, edges = store.load_graph(min_confidence=1.0)
    assert {n.id for n in nodes} == {
        "external",
        "web",
        "app",
        "svc_account",
        "db",
        "customer_db",
    }
    # All returned edges must meet the confidence floor.
    assert all(e.confidence >= 1.0 for e in edges)
    # The seeded unconfirmed llm edge (app -> db, confidence 0.65)
    # should NOT appear at the default threshold.
    assert not any(
        e.source == "app" and e.target == "db" and e.proposed_by == "llm"
        for e in edges
    )


def test_lower_min_confidence_includes_proposed_edges():
    store = InMemoryStore(seed_demo_data=True)
    _, edges = store.load_graph(min_confidence=0.5)
    assert any(
        e.source == "app" and e.target == "db" and e.proposed_by == "llm"
        for e in edges
    )


def test_empty_store_has_only_the_structural_external_node():
    # A fresh store (even un-seeded) always gets the structural
    # "external" node -- see storage.py's module docstring for why
    # (every analyze/CLI example assumes --start external is valid).
    # No edges, since nothing has actually connected to it yet.
    store = InMemoryStore(seed_demo_data=False)
    nodes, edges = store.load_graph()
    assert [n.id for n in nodes] == ["external"]
    assert edges == []


def test_save_finding_requires_fields():
    store = InMemoryStore(seed_demo_data=False)
    with pytest.raises(ValueError):
        store.save_finding({"type": "ssrf"})  # missing required fields


def test_save_finding_stores_and_defaults():
    store = InMemoryStore(seed_demo_data=False)
    store.save_finding(
        {
            "host_id": "web",
            "type": "ssrf",
            "severity": "high",
            "description": "SSRF in image proxy",
            "evidence": "curl to 169.254.169.254 returned metadata",
        }
    )
    findings = store.list_findings()
    assert len(findings) == 1
    assert findings[0]["source"] == "scanner"  # default applied
    assert findings[0]["confidence"] == 1.0    # default applied
    assert findings[0]["id"]  # generated


def test_delete_findings_for_host_scoped_by_source():
    store = InMemoryStore(seed_demo_data=False)
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
    store.save_finding(
        {
            "host_id": "other-host",
            "type": "exposed_sensitive_path",
            "severity": "critical",
            "description": "different host, same source",
            "evidence": "e",
            "source": "scanner",
        }
    )

    deleted = store.delete_findings_for_host("web", source="scanner")
    assert deleted == 1

    remaining = store.list_findings()
    assert {f["host_id"] for f in remaining} == {"web", "other-host"}
    assert {f["source"] for f in remaining if f["host_id"] == "web"} == {"manual"}


def test_delete_findings_for_host_without_source_clears_all_sources():
    store = InMemoryStore(seed_demo_data=False)
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


def test_save_relationship_then_confirm_promotes_it():
    store = InMemoryStore(seed_demo_data=False)
    proposed = Edge(
        source="x",
        target="y",
        relationship="CAN_ACCESS",
        evidence="inferred from finding #3",
        confirmed=False,
        confidence=0.7,
        proposed_by="llm",
    )
    edge_id = store.save_relationship(proposed)

    unconfirmed = store.list_relationships(confirmed=False)
    assert len(unconfirmed) == 1
    assert unconfirmed[0]["id"] == edge_id

    store.confirm_relationship(edge_id)

    confirmed = store.list_relationships(confirmed=True)
    assert len(confirmed) == 1
    assert confirmed[0]["id"] == edge_id
    assert confirmed[0]["confidence"] == 1.0  # promotion clears the hedge

    assert store.list_relationships(confirmed=False) == []


def test_confirm_unknown_edge_id_raises():
    store = InMemoryStore(seed_demo_data=False)
    with pytest.raises(KeyError):
        store.confirm_relationship("does-not-exist")


def test_edge_invariant_confirmed_requires_full_confidence():
    with pytest.raises(ValueError):
        Edge(
            source="a",
            target="b",
            relationship="CAN_REACH",
            confirmed=True,
            confidence=0.9,  # invalid: confirmed edges can't be hedged
        )


def test_save_host_creates_node_and_record():
    store = InMemoryStore(seed_demo_data=False)
    host_id = store.save_host({"hostname": "web01", "ip": "10.0.1.10", "os": "Linux"})

    hosts = store.list_hosts()
    assert len(hosts) == 1
    assert hosts[0]["id"] == host_id
    assert hosts[0]["ip"] == "10.0.1.10"

    nodes, _ = store.load_graph(min_confidence=0.0)
    assert any(n.id == host_id and n.type == "host" for n in nodes)


def test_save_host_same_ip_twice_updates_not_duplicates():
    store = InMemoryStore(seed_demo_data=False)
    id1 = store.save_host({"hostname": "web01", "ip": "10.0.1.10", "os": None})
    id2 = store.save_host({"hostname": "web01", "ip": "10.0.1.10", "os": "Linux 5.x"})
    assert id1 == id2
    assert len(store.list_hosts()) == 1
    assert store.list_hosts()[0]["os"] == "Linux 5.x"


def test_save_host_requires_fields():
    store = InMemoryStore(seed_demo_data=False)
    with pytest.raises(ValueError):
        store.save_host({"hostname": "web01"})  # missing ip


def test_save_service_requires_known_host():
    store = InMemoryStore(seed_demo_data=False)
    with pytest.raises(KeyError):
        store.save_service(
            {
                "host_id": "does-not-exist",
                "port": 443,
                "protocol": "tcp",
                "service_name": "https",
            }
        )


def test_save_service_and_list_by_host():
    store = InMemoryStore(seed_demo_data=False)
    host_id = store.save_host({"hostname": "web01", "ip": "10.0.1.10"})
    other_id = store.save_host({"hostname": "app01", "ip": "10.0.2.10"})
    store.save_service(
        {"host_id": host_id, "port": 443, "protocol": "tcp", "service_name": "https"}
    )
    store.save_service(
        {"host_id": other_id, "port": 8080, "protocol": "tcp", "service_name": "http"}
    )
    assert len(store.list_services()) == 2
    web_services = store.list_services(host_id)
    assert len(web_services) == 1
    assert web_services[0]["port"] == 443


def test_edge_invariant_rejects_bad_proposed_by():
    with pytest.raises(ValueError):
        Edge(
            source="a",
            target="b",
            relationship="CAN_REACH",
            confirmed=False,
            confidence=0.5,
            proposed_by="not_a_real_source",
        )
