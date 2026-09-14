"""Tests for discovery/pipeline.py — the glue between parsers and
storage. Uses ingest_nmap_xml (fixture text in, no live nmap call) and
swaps in a fresh, empty InMemoryStore for each test so nothing leaks
between tests or collides with the seeded demo data.
"""

from pathlib import Path

import pytest

from attackmapper import storage
from attackmapper.discovery import pipeline
from attackmapper.storage import InMemoryStore

FIXTURES = Path(__file__).parent.parent / "tests" / "fixtures"


@pytest.fixture
def fresh_store(monkeypatch):
    store = InMemoryStore(seed_demo_data=False)
    monkeypatch.setattr(storage, "_default_store", store)
    return store


def test_ingest_nmap_xml_stores_host_and_service(fresh_store):
    xml_text = (FIXTURES / "nmap_localhost_scan.xml").read_text()
    summary = pipeline.ingest_nmap_xml(xml_text)

    assert summary == {"hosts": 1, "services": 1, "findings": 0}

    hosts = fresh_store.list_hosts()
    assert len(hosts) == 1
    assert hosts[0]["ip"] == "127.0.0.1"

    services = fresh_store.list_services(hosts[0]["id"])
    assert len(services) == 1
    assert services[0]["port"] == 8765

    # And the host should be visible to the graph engine as a Node.
    nodes, _ = fresh_store.load_graph(min_confidence=0.0)
    assert any(n.id == hosts[0]["id"] and n.type == "host" for n in nodes)


def test_ingest_nmap_xml_stores_findings_from_synthetic_fixture(fresh_store):
    xml_text = (FIXTURES / "nmap_vsftpd_backdoor_synthetic.xml").read_text()
    summary = pipeline.ingest_nmap_xml(xml_text)

    assert summary["hosts"] == 1
    assert summary["services"] == 2
    assert summary["findings"] == 2  # vsftpd backdoor + old OpenSSH

    findings = fresh_store.list_findings()
    assert all(f["host_id"] for f in findings)  # ip was resolved to host_id
    assert all("ip" not in f for f in findings)  # internal key not leaked


def test_ingest_nmap_xml_rescanning_same_ip_updates_not_duplicates(fresh_store):
    xml_text = (FIXTURES / "nmap_localhost_scan.xml").read_text()
    pipeline.ingest_nmap_xml(xml_text)
    pipeline.ingest_nmap_xml(xml_text)  # simulate a second scan run
    assert len(fresh_store.list_hosts()) == 1


def test_ingest_http_probe_attaches_given_host_id(fresh_store, monkeypatch):
    host_id = fresh_store.save_host({"hostname": "web01", "ip": "10.0.1.10"})

    fake_probe = {
        "url": "http://web01/internal/debug",
        "status_code": 200,
        "headers": {},
        "body": '{"service_account_token": "sa-tok-EXAMPLE1234567890abcdef"}',
    }
    monkeypatch.setattr(pipeline.scanners, "http_probe", lambda url, **kw: fake_probe)

    summary = pipeline.ingest_http_probe("http://web01/internal/debug", host_id)
    assert summary == {"findings": 1}

    findings = fresh_store.list_findings()
    assert findings[0]["host_id"] == host_id
    assert findings[0]["type"] == "leaked_credential"


def test_ingest_postgres_roles_attaches_given_host_id(fresh_store, monkeypatch):
    host_id = fresh_store.save_host({"hostname": "db01", "ip": "10.0.3.10"})

    fake_rows = [
        {
            "rolname": "postgres",
            "rolsuper": True,
            "rolcreaterole": True,
            "rolcreatedb": True,
            "rolcanlogin": True,
        }
    ]
    monkeypatch.setattr(
        pipeline.scanners, "introspect_postgres_roles", lambda dsn, **kw: fake_rows
    )

    summary = pipeline.ingest_postgres_roles("postgresql://x", host_id)
    assert summary == {"findings": 1}
    assert fresh_store.list_findings()[0]["host_id"] == host_id


def test_ingest_ambiguous_evidence_delegates_to_evidence_llm(fresh_store, monkeypatch):
    """Phase D: pipeline.ingest_ambiguous_evidence is a thin wrapper
    around evidence_llm.interpret_evidence that looks up host context
    and reports a summary in the same shape as the other ingest_*
    functions."""
    host_id = fresh_store.save_host({"hostname": "web01", "ip": "10.0.1.10"})

    captured = {}

    def fake_interpret(host_id_arg, evidence_type_arg, raw_evidence_arg, *, host=None):
        captured["host_id"] = host_id_arg
        captured["evidence_type"] = evidence_type_arg
        captured["raw_evidence"] = raw_evidence_arg
        captured["host"] = host
        return [object(), object()]  # two "findings" for the summary count

    monkeypatch.setattr(pipeline.evidence_llm, "interpret_evidence", fake_interpret)

    summary = pipeline.ingest_ambiguous_evidence(
        host_id, "service_banner", "FooServer/9.9 experimental"
    )

    assert summary == {"findings": 2}
    assert captured["host_id"] == host_id
    assert captured["evidence_type"] == "service_banner"
    assert captured["raw_evidence"] == "FooServer/9.9 experimental"
    assert captured["host"]["ip"] == "10.0.1.10"


def test_ingest_ambiguous_evidence_works_with_unknown_host_id(fresh_store, monkeypatch):
    """A host_id not yet in the inventory should still be passed
    through -- interpret_evidence's host param is optional context,
    not a hard requirement."""
    captured = {}

    def fake_interpret(host_id_arg, evidence_type_arg, raw_evidence_arg, *, host=None):
        captured["host"] = host
        return []

    monkeypatch.setattr(pipeline.evidence_llm, "interpret_evidence", fake_interpret)

    summary = pipeline.ingest_ambiguous_evidence(
        "not-a-real-host", "config_snippet", "some config"
    )
    assert summary == {"findings": 0}
    assert captured["host"] is None
