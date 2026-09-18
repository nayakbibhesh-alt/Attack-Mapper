"""tests/test_webapp_auth.py — Basic Auth gate and the new
/api/chain-findings endpoint.

`_check_basic_auth` is a pure function of (env-configured credentials,
header value) so it's tested directly without spinning up a real
HTTP server, matching the rest of this suite's preference for testing
logic beneath the transport layer rather than the transport itself.
"""
from __future__ import annotations

import base64
import importlib

import pytest


def _reload_webapp(monkeypatch, user=None, password=None):
    if user is not None:
        monkeypatch.setenv("ATTACKMAPPER_AUTH_USER", user)
    else:
        monkeypatch.delenv("ATTACKMAPPER_AUTH_USER", raising=False)
    if password is not None:
        monkeypatch.setenv("ATTACKMAPPER_AUTH_PASS", password)
    else:
        monkeypatch.delenv("ATTACKMAPPER_AUTH_PASS", raising=False)
    from attackmapper import webapp

    return importlib.reload(webapp)


def _basic_header(user: str, password: str) -> str:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return f"Basic {token}"


def test_auth_disabled_when_env_vars_unset(monkeypatch):
    webapp = _reload_webapp(monkeypatch, user=None, password=None)
    assert webapp.AUTH_ENABLED is False
    # No credentials required at all when unset.
    assert webapp._check_basic_auth(None) is True
    assert webapp._check_basic_auth("garbage") is True


def test_auth_rejects_missing_or_malformed_header(monkeypatch):
    webapp = _reload_webapp(monkeypatch, user="admin", password="hunter2")
    assert webapp.AUTH_ENABLED is True
    assert webapp._check_basic_auth(None) is False
    assert webapp._check_basic_auth("") is False
    assert webapp._check_basic_auth("Bearer sometoken") is False
    assert webapp._check_basic_auth("Basic not-valid-base64!!!") is False


def test_auth_rejects_wrong_credentials(monkeypatch):
    webapp = _reload_webapp(monkeypatch, user="admin", password="hunter2")
    assert webapp._check_basic_auth(_basic_header("admin", "wrong")) is False
    assert webapp._check_basic_auth(_basic_header("someoneelse", "hunter2")) is False


def test_auth_accepts_correct_credentials(monkeypatch):
    webapp = _reload_webapp(monkeypatch, user="admin", password="hunter2")
    assert webapp._check_basic_auth(_basic_header("admin", "hunter2")) is True


def test_auth_teardown_reload(monkeypatch):
    # Leave the module in its natural (auth-disabled-in-test-env) state
    # for any test that runs after this file, since importlib.reload
    # mutates the shared module object other tests may import fresh.
    _reload_webapp(monkeypatch, user=None, password=None)


# -- /api/chain-findings --------------------------------------------


@pytest.fixture
def store(monkeypatch):
    from attackmapper import storage as storage_module

    fresh = storage_module.InMemoryStore(seed_demo_data=False)
    monkeypatch.setattr(storage_module, "_default_store", fresh)
    return fresh


def test_post_chain_findings_scopes_by_host_id(monkeypatch, store):
    from attackmapper import webapp
    from attackmapper.narration import attack_chain_llm

    host_a = store.save_host({"hostname": "a", "ip": "10.0.0.1"})
    host_b = store.save_host({"hostname": "b", "ip": "10.0.0.2"})
    store.save_finding(
        {"host_id": host_a, "type": "t1", "severity": "high",
         "description": "d1", "evidence": "e1"}
    )
    store.save_finding(
        {"host_id": host_a, "type": "t2", "severity": "medium",
         "description": "d2", "evidence": "e2"}
    )
    store.save_finding(
        {"host_id": host_b, "type": "t3", "severity": "low",
         "description": "d3", "evidence": "e3"}
    )

    seen = {}

    def fake_find_attack_chains(findings, hosts, services):
        seen["findings"] = findings
        seen["hosts"] = hosts
        return []

    monkeypatch.setattr(attack_chain_llm, "find_attack_chains", fake_find_attack_chains)

    status, payload = webapp.Api.post_chain_findings({"host_id": host_a})
    assert status == 200
    assert payload["findings_considered"] == 2
    assert all(f["host_id"] == host_a for f in seen["findings"])
    assert [h["id"] for h in seen["hosts"]] == [host_a]


def test_post_chain_findings_propagates_missing_key_error(monkeypatch, store):
    from attackmapper import webapp
    from attackmapper.narration import attack_chain_llm

    host_a = store.save_host({"hostname": "a", "ip": "10.0.0.1"})
    store.save_finding(
        {"host_id": host_a, "type": "t1", "severity": "high",
         "description": "d1", "evidence": "e1"}
    )

    def raise_missing_key(**kwargs):
        raise RuntimeError("OPENROUTER_API_KEY is not set")

    monkeypatch.setattr(attack_chain_llm, "find_attack_chains", raise_missing_key)

    status, payload = webapp.Api.post_chain_findings({})
    assert status == 424
    assert "OPENROUTER_API_KEY" in payload["error"]
