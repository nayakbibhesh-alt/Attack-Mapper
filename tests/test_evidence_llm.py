"""Tests for discovery/evidence_llm.py.

Same approach as tests/test_relationship_llm.py for Layer 2: never
test against a live model call. Every test here monkeypatches
evidence_llm.call_llm with a canned string instead of hitting a model.
"""

import json

import pytest

from attackmapper import storage
from attackmapper.discovery import evidence_llm
from attackmapper.storage import InMemoryStore

# ---------------------------------------------------------------------
# parse_evidence_response: schema validation against fixture responses,
# no storage or LLM involved.
# ---------------------------------------------------------------------


def test_parses_well_formed_response():
    raw = json.dumps(
        {
            "findings": [
                {
                    "type": "leaked_credential",
                    "severity": "high",
                    "description": "token in response body",
                    "evidence": "body contained service_account_token",
                    "confidence": 0.9,
                }
            ]
        }
    )
    result = evidence_llm.parse_evidence_response(raw)
    assert result == [
        {
            "type": "leaked_credential",
            "severity": "high",
            "description": "token in response body",
            "evidence": "body contained service_account_token",
            "confidence": 0.9,
        }
    ]


def test_rejects_non_json_entirely():
    assert evidence_llm.parse_evidence_response("not json at all") == []


def test_rejects_response_missing_top_level_key():
    raw = json.dumps({"results": []})  # wrong key
    assert evidence_llm.parse_evidence_response(raw) == []


def test_rejects_findings_that_is_not_a_list():
    raw = json.dumps({"findings": "oops"})
    assert evidence_llm.parse_evidence_response(raw) == []


def test_skips_items_missing_required_fields_but_keeps_valid_ones():
    raw = json.dumps(
        {
            "findings": [
                {"type": "ssrf", "severity": "high"},  # missing fields
                {
                    "type": "weak_password",
                    "severity": "medium",
                    "description": "ok",
                    "evidence": "ok",
                    "confidence": 0.5,
                },
            ]
        }
    )
    result = evidence_llm.parse_evidence_response(raw)
    assert len(result) == 1
    assert result[0]["type"] == "weak_password"


def test_skips_items_with_invalid_severity():
    raw = json.dumps(
        {
            "findings": [
                {
                    "type": "ssrf",
                    "severity": "very high",  # not in the enum
                    "description": "d",
                    "evidence": "e",
                    "confidence": 0.5,
                }
            ]
        }
    )
    assert evidence_llm.parse_evidence_response(raw) == []


def test_skips_items_with_out_of_range_confidence():
    raw = json.dumps(
        {
            "findings": [
                {
                    "type": "ssrf",
                    "severity": "high",
                    "description": "d",
                    "evidence": "e",
                    "confidence": 1.5,
                }
            ]
        }
    )
    assert evidence_llm.parse_evidence_response(raw) == []


def test_skips_items_with_non_numeric_confidence():
    raw = json.dumps(
        {
            "findings": [
                {
                    "type": "ssrf",
                    "severity": "high",
                    "description": "d",
                    "evidence": "e",
                    "confidence": "high",
                }
            ]
        }
    )
    assert evidence_llm.parse_evidence_response(raw) == []


def test_skips_items_with_non_string_type():
    raw = json.dumps(
        {
            "findings": [
                {
                    "type": 123,
                    "severity": "high",
                    "description": "d",
                    "evidence": "e",
                    "confidence": 0.5,
                }
            ]
        }
    )
    assert evidence_llm.parse_evidence_response(raw) == []


def test_empty_findings_list_is_valid():
    raw = json.dumps({"findings": []})
    assert evidence_llm.parse_evidence_response(raw) == []


def test_low_confidence_items_are_not_filtered_by_schema_validation():
    raw = json.dumps(
        {
            "findings": [
                {
                    "type": "ssrf",
                    "severity": "low",
                    "description": "d",
                    "evidence": "e",
                    "confidence": 0.02,
                }
            ]
        }
    )
    result = evidence_llm.parse_evidence_response(raw)
    assert len(result) == 1
    assert result[0]["confidence"] == 0.02


# ---------------------------------------------------------------------
# interpret_evidence: the full pipeline, LLM call mocked out.
# ---------------------------------------------------------------------


@pytest.fixture
def fresh_store(monkeypatch):
    store = InMemoryStore(seed_demo_data=False)
    monkeypatch.setattr(storage, "_default_store", store)
    return store


def test_interpret_evidence_stores_valid_findings_as_llm_inferred(
    fresh_store, monkeypatch
):
    host_id = fresh_store.save_host({"hostname": "web01", "ip": "10.0.1.10"})

    fake_response = json.dumps(
        {
            "findings": [
                {
                    "type": "leaked_credential",
                    "severity": "high",
                    "description": "token in banner",
                    "evidence": "banner text",
                    "confidence": 0.7,
                }
            ]
        }
    )
    monkeypatch.setattr(evidence_llm, "call_llm", lambda prompt: fake_response)

    findings = evidence_llm.interpret_evidence(
        host_id, "service_banner", "some odd banner text"
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.host_id == host_id
    assert f.type == "leaked_credential"
    assert f.source == "llm_inferred"
    assert f.confidence == 0.7

    stored = fresh_store.list_findings()
    assert len(stored) == 1
    assert stored[0]["source"] == "llm_inferred"
    assert stored[0]["host_id"] == host_id


def test_interpret_evidence_skips_llm_call_on_empty_evidence(fresh_store, monkeypatch):
    called = []
    monkeypatch.setattr(
        evidence_llm, "call_llm", lambda prompt: called.append(1) or "{}"
    )
    findings = evidence_llm.interpret_evidence("host-1", "service_banner", "   ")
    assert findings == []
    assert called == []  # never even called the model


def test_interpret_evidence_stores_nothing_on_malformed_response(
    fresh_store, monkeypatch
):
    monkeypatch.setattr(evidence_llm, "call_llm", lambda prompt: "not json")
    findings = evidence_llm.interpret_evidence("host-1", "service_banner", "banner")
    assert findings == []
    assert fresh_store.list_findings() == []


def test_interpret_evidence_stores_nothing_when_llm_finds_nothing(
    fresh_store, monkeypatch
):
    monkeypatch.setattr(
        evidence_llm, "call_llm", lambda prompt: json.dumps({"findings": []})
    )
    findings = evidence_llm.interpret_evidence("host-1", "service_banner", "banner")
    assert findings == []


def test_interpret_evidence_passes_host_context_into_prompt(fresh_store, monkeypatch):
    host_id = fresh_store.save_host({"hostname": "app01", "ip": "10.0.2.10"})
    host = next(h for h in fresh_store.list_hosts() if h["id"] == host_id)

    captured_prompts = []

    def fake_call_llm(prompt):
        captured_prompts.append(prompt)
        return json.dumps({"findings": []})

    monkeypatch.setattr(evidence_llm, "call_llm", fake_call_llm)
    evidence_llm.interpret_evidence(
        host_id, "config_snippet", "some config", host=host
    )

    assert len(captured_prompts) == 1
    assert "app01" in captured_prompts[0]
    assert "10.0.2.10" in captured_prompts[0]


def test_call_llm_raises_clear_error_without_api_key(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    import sys
    import types

    fake_openai = types.ModuleType("openai")
    fake_openai.OpenAI = object  # present so the lazy import succeeds
    monkeypatch.setitem(sys.modules, "openai", fake_openai)
    with pytest.raises(RuntimeError, match="OPENROUTER_API_KEY"):
        evidence_llm.call_llm("a prompt")
