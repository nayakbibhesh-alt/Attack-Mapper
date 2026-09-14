"""Tests for discovery/agentic_loop.py.

Same approach as tests/test_relationship_llm.py and
tests/test_evidence_llm.py: never test against a live model call, and
never run a live scan/probe. Every test here monkeypatches
agentic_loop.call_llm with a canned string, and either swaps in a
fresh InMemoryStore or monkeypatches discovery.pipeline's ingest_*
functions so nothing real ever gets scanned/probed. Scope enforcement
in particular is exercised directly, since it's the load-bearing
guardrail the master spec calls out for Phase G.
"""

import json

import pytest

from attackmapper import storage
from attackmapper.discovery import agentic_loop
from attackmapper.storage import InMemoryStore

# ---------------------------------------------------------------------
# parse_next_probe_response: schema validation against fixture
# responses, no storage/LLM/scope involved.
# ---------------------------------------------------------------------


def test_parses_well_formed_response():
    raw = json.dumps(
        {
            "actions": [
                {
                    "action_type": "nmap_scan",
                    "target": "10.0.2.10",
                    "rationale": "newly discovered host, no services yet",
                    "ports": "1-1024",
                }
            ]
        }
    )
    result = agentic_loop.parse_next_probe_response(raw)
    assert result == [
        {
            "action_type": "nmap_scan",
            "target": "10.0.2.10",
            "rationale": "newly discovered host, no services yet",
            "ports": "1-1024",
        }
    ]


def test_parses_stop_action_with_no_target():
    raw = json.dumps({"actions": [{"action_type": "stop", "rationale": "done"}]})
    result = agentic_loop.parse_next_probe_response(raw)
    assert result == [{"action_type": "stop", "rationale": "done", "target": None}]


def test_rejects_non_json_entirely():
    assert agentic_loop.parse_next_probe_response("not json at all") == []


def test_rejects_response_missing_top_level_key():
    raw = json.dumps({"probes": []})  # wrong key
    assert agentic_loop.parse_next_probe_response(raw) == []


def test_rejects_actions_that_is_not_a_list():
    raw = json.dumps({"actions": "oops"})
    assert agentic_loop.parse_next_probe_response(raw) == []


def test_skips_items_with_unrecognized_action_type_but_keeps_valid_ones():
    raw = json.dumps(
        {
            "actions": [
                {
                    "action_type": "exploit",  # not in ALLOWED_ACTION_TYPES
                    "target": "10.0.1.10",
                    "rationale": "nope",
                },
                {
                    "action_type": "nmap_scan",
                    "target": "10.0.1.10",
                    "rationale": "ok",
                },
            ]
        }
    )
    result = agentic_loop.parse_next_probe_response(raw)
    assert len(result) == 1
    assert result[0]["action_type"] == "nmap_scan"


def test_skips_non_stop_items_missing_target():
    raw = json.dumps(
        {"actions": [{"action_type": "http_probe", "rationale": "no target given"}]}
    )
    assert agentic_loop.parse_next_probe_response(raw) == []


def test_skips_items_missing_rationale():
    raw = json.dumps(
        {"actions": [{"action_type": "nmap_scan", "target": "10.0.1.10"}]}
    )
    assert agentic_loop.parse_next_probe_response(raw) == []


def test_drops_optional_fields_when_not_strings():
    raw = json.dumps(
        {
            "actions": [
                {
                    "action_type": "nmap_scan",
                    "target": "10.0.1.10",
                    "rationale": "ok",
                    "ports": 1024,  # wrong type, should be dropped not kept
                }
            ]
        }
    )
    result = agentic_loop.parse_next_probe_response(raw)
    assert "ports" not in result[0]


# ---------------------------------------------------------------------
# _target_in_scope: the load-bearing guardrail.
# ---------------------------------------------------------------------


def test_exact_hostname_or_ip_match_is_in_scope():
    assert agentic_loop._target_in_scope("10.0.1.10", ["10.0.1.10"])
    assert agentic_loop._target_in_scope("web01", ["web01", "10.0.2.0/24"])


def test_cidr_containment_is_in_scope():
    assert agentic_loop._target_in_scope("10.0.2.55", ["10.0.2.0/24"])


def test_ip_outside_cidr_is_not_in_scope():
    assert not agentic_loop._target_in_scope("10.0.3.55", ["10.0.2.0/24"])


def test_unrelated_target_is_not_in_scope():
    assert not agentic_loop._target_in_scope("evil.example.com", ["10.0.1.10"])


def test_empty_scope_means_nothing_is_in_scope():
    assert not agentic_loop._target_in_scope("10.0.1.10", [])


def test_hostname_target_against_cidr_scope_does_not_false_positive():
    # A non-IP target should never spuriously match a CIDR scope entry.
    assert not agentic_loop._target_in_scope("web01", ["10.0.2.0/24"])


# ---------------------------------------------------------------------
# run_discovery_loop: end-to-end against a fresh in-memory store, with
# call_llm and the pipeline's real scanners/probes both monkeypatched
# out so nothing real is ever scanned/probed/called.
# ---------------------------------------------------------------------


@pytest.fixture
def fresh_store(monkeypatch):
    store = InMemoryStore(seed_demo_data=False)
    monkeypatch.setattr(storage, "_default_store", store)
    return store


def test_requires_non_empty_scope():
    with pytest.raises(agentic_loop.ScopeError):
        agentic_loop.run_discovery_loop([])


def test_stops_immediately_on_stop_action(fresh_store, monkeypatch):
    stop_response = json.dumps(
        {"actions": [{"action_type": "stop", "rationale": "nothing to do"}]}
    )
    monkeypatch.setattr(agentic_loop, "call_llm", lambda prompt, **kw: stop_response)

    result = agentic_loop.run_discovery_loop(["10.0.1.10"], max_iterations=5)

    assert len(result["iterations"]) == 1
    assert result["iterations"][0]["stopped"] is True
    assert result["iterations"][0]["actions_taken"] == []


def test_executes_in_scope_action_via_pipeline(fresh_store, monkeypatch):
    scan_response = json.dumps(
        {
            "actions": [
                {
                    "action_type": "nmap_scan",
                    "target": "10.0.1.10",
                    "rationale": "unscanned host in scope",
                }
            ]
        }
    )
    stop_response = json.dumps({"actions": [{"action_type": "stop", "rationale": "done"}]})
    # First iteration proposes a scan; second iteration (since something
    # executed) proposes stop, ending the loop.
    responses = iter([scan_response, stop_response])
    monkeypatch.setattr(
        agentic_loop, "call_llm", lambda prompt, **kw: next(responses)
    )

    calls = []

    def fake_ingest_nmap_scan(target, ports="1-1024"):
        calls.append((target, ports))
        return {"hosts": 1, "services": 2, "findings": 0}

    monkeypatch.setattr(
        agentic_loop.pipeline, "ingest_nmap_scan", fake_ingest_nmap_scan
    )
    monkeypatch.setattr(
        agentic_loop.relationship_llm, "infer_relationships", lambda: []
    )

    result = agentic_loop.run_discovery_loop(["10.0.1.10"], max_iterations=5)

    assert calls == [("10.0.1.10", "1-1024")]
    taken = result["iterations"][0]["actions_taken"]
    assert len(taken) == 1
    assert taken[0]["executed"] is True
    assert taken[0]["result"] == {"hosts": 1, "services": 2, "findings": 0}


def test_out_of_scope_action_is_discarded_not_executed(fresh_store, monkeypatch):
    scan_response = json.dumps(
        {
            "actions": [
                {
                    "action_type": "nmap_scan",
                    "target": "172.16.0.5",  # NOT in scope below
                    "rationale": "let's try this other network too",
                }
            ]
        }
    )
    monkeypatch.setattr(agentic_loop, "call_llm", lambda prompt, **kw: scan_response)

    calls = []
    monkeypatch.setattr(
        agentic_loop.pipeline,
        "ingest_nmap_scan",
        lambda target, ports="1-1024": calls.append(target),
    )

    result = agentic_loop.run_discovery_loop(["10.0.1.10"], max_iterations=3)

    assert calls == []  # never executed
    taken = result["iterations"][0]["actions_taken"]
    assert taken[0]["executed"] is False
    assert taken[0]["reason"] == "out_of_scope"
    # Nothing executed -> loop should not keep spinning.
    assert len(result["iterations"]) == 1


def test_http_probe_without_known_host_fails_gracefully(fresh_store, monkeypatch):
    probe_response = json.dumps(
        {
            "actions": [
                {
                    "action_type": "http_probe",
                    "target": "10.0.1.10",
                    "rationale": "check the web root",
                }
            ]
        }
    )
    monkeypatch.setattr(agentic_loop, "call_llm", lambda prompt, **kw: probe_response)

    result = agentic_loop.run_discovery_loop(["10.0.1.10"], max_iterations=3)

    taken = result["iterations"][0]["actions_taken"]
    assert taken[0]["executed"] is False
    assert "no known host" in taken[0]["reason"]


def test_relationship_inference_rerun_only_when_something_executed(
    fresh_store, monkeypatch
):
    scan_response = json.dumps(
        {
            "actions": [
                {
                    "action_type": "nmap_scan",
                    "target": "10.0.1.10",
                    "rationale": "scan it",
                }
            ]
        }
    )
    monkeypatch.setattr(agentic_loop, "call_llm", lambda prompt, **kw: scan_response)
    monkeypatch.setattr(
        agentic_loop.pipeline,
        "ingest_nmap_scan",
        lambda target, ports="1-1024": {"hosts": 1, "services": 0, "findings": 0},
    )

    infer_calls = []

    def fake_infer():
        infer_calls.append(True)
        return []

    monkeypatch.setattr(agentic_loop.relationship_llm, "infer_relationships", fake_infer)

    agentic_loop.run_discovery_loop(["10.0.1.10"], max_iterations=1)

    assert infer_calls == [True]


def test_respects_max_actions_per_iteration_cap(fresh_store, monkeypatch):
    many_actions_response = json.dumps(
        {
            "actions": [
                {
                    "action_type": "nmap_scan",
                    "target": "10.0.1.10",
                    "rationale": f"scan {i}",
                }
                for i in range(5)
            ]
        }
    )
    monkeypatch.setattr(
        agentic_loop, "call_llm", lambda prompt, **kw: many_actions_response
    )
    calls = []
    monkeypatch.setattr(
        agentic_loop.pipeline,
        "ingest_nmap_scan",
        lambda target, ports="1-1024": calls.append(target)
        or {"hosts": 0, "services": 0, "findings": 0},
    )
    monkeypatch.setattr(agentic_loop.relationship_llm, "infer_relationships", lambda: [])

    agentic_loop.run_discovery_loop(
        ["10.0.1.10"], max_iterations=1, max_actions_per_iteration=2
    )

    assert len(calls) == 2


def test_stops_after_max_iterations_even_without_stop_action(fresh_store, monkeypatch):
    scan_response = json.dumps(
        {
            "actions": [
                {
                    "action_type": "nmap_scan",
                    "target": "10.0.1.10",
                    "rationale": "keep scanning",
                }
            ]
        }
    )
    monkeypatch.setattr(agentic_loop, "call_llm", lambda prompt, **kw: scan_response)
    monkeypatch.setattr(
        agentic_loop.pipeline,
        "ingest_nmap_scan",
        lambda target, ports="1-1024": {"hosts": 1, "services": 0, "findings": 0},
    )
    monkeypatch.setattr(agentic_loop.relationship_llm, "infer_relationships", lambda: [])

    result = agentic_loop.run_discovery_loop(["10.0.1.10"], max_iterations=3)

    assert len(result["iterations"]) == 3


def test_pending_review_surfaces_high_confidence_unconfirmed_edges(
    fresh_store, monkeypatch
):
    from attackmapper.models import Edge

    fresh_store.save_relationship(
        Edge(
            source="app",
            target="db",
            relationship="CAN_ACCESS",
            evidence="high-confidence proposal",
            confirmed=False,
            confidence=0.9,
            proposed_by="llm",
        )
    )
    fresh_store.save_relationship(
        Edge(
            source="web",
            target="app",
            relationship="CAN_REACH",
            evidence="low-confidence proposal",
            confirmed=False,
            confidence=0.3,
            proposed_by="llm",
        )
    )

    stop_response = json.dumps({"actions": [{"action_type": "stop", "rationale": "done"}]})
    monkeypatch.setattr(agentic_loop, "call_llm", lambda prompt, **kw: stop_response)

    result = agentic_loop.run_discovery_loop(
        ["10.0.1.10"], max_iterations=1, review_threshold=0.75
    )

    assert len(result["pending_review"]) == 1
    assert result["pending_review"][0]["evidence"] == "high-confidence proposal"


def test_pending_review_never_auto_confirms(fresh_store, monkeypatch):
    from attackmapper.models import Edge

    fresh_store.save_relationship(
        Edge(
            source="app",
            target="db",
            relationship="CAN_ACCESS",
            evidence="proposal",
            confirmed=False,
            confidence=0.95,
            proposed_by="llm",
        )
    )
    stop_response = json.dumps({"actions": [{"action_type": "stop", "rationale": "done"}]})
    monkeypatch.setattr(agentic_loop, "call_llm", lambda prompt, **kw: stop_response)

    agentic_loop.run_discovery_loop(["10.0.1.10"], max_iterations=1)

    # Still unconfirmed after the loop ran -- this module has no path
    # that calls storage.confirm_relationship().
    rels = fresh_store.list_relationships(confirmed=False)
    assert len(rels) == 1
    assert rels[0]["confirmed"] is False


# ---------------------------------------------------------------------
# call_llm: same error-handling contract as the other LLM modules.
# ---------------------------------------------------------------------


def test_call_llm_raises_clear_error_without_api_key(monkeypatch):
    import sys
    import types

    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    fake_openai = types.ModuleType("openai")
    fake_openai.OpenAI = object  # present so the lazy import succeeds
    monkeypatch.setitem(sys.modules, "openai", fake_openai)
    with pytest.raises(RuntimeError, match="OPENROUTER_API_KEY"):
        agentic_loop.call_llm("prompt")


def test_call_llm_raises_clear_error_without_sdk(monkeypatch):
    import sys

    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-fake")
    monkeypatch.setitem(sys.modules, "openai", None)
    with pytest.raises(RuntimeError, match="openai"):
        agentic_loop.call_llm("prompt")
