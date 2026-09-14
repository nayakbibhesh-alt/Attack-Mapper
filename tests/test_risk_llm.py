"""Tests for narration/risk_llm.py.

Same approach as tests/test_relationship_llm.py and
tests/test_evidence_llm.py: never test against a live model call.
Every test here monkeypatches risk_llm.call_llm with a canned string.
"""

import json

import pytest

from attackmapper.models import Edge
from attackmapper.narration import risk_llm

# ---------------------------------------------------------------------
# parse_narration_response: schema validation against fixture
# responses, no LLM involved. Unlike Layers 1-2, a bad item rejects
# the WHOLE response (returns None), not just that one item.
# ---------------------------------------------------------------------


def _well_formed_response():
    return json.dumps(
        {
            "summary": "An attacker could walk from the internet to the DB.",
            "weakest_link": "app --RUNS_AS--> service_account",
            "remediations": [
                {"priority": 2, "suggestion": "Rotate the service account credential."},
                {"priority": 1, "suggestion": "Scope the DB role to read-only."},
            ],
        }
    )


def test_parses_well_formed_response_and_sorts_by_priority():
    result = risk_llm.parse_narration_response(_well_formed_response())
    assert result is not None
    assert result["summary"].startswith("An attacker")
    assert result["weakest_link"] == "app --RUNS_AS--> service_account"
    assert [r["priority"] for r in result["remediations"]] == [1, 2]
    assert result["remediations"][0]["suggestion"] == "Scope the DB role to read-only."


def test_rejects_non_json_entirely():
    assert risk_llm.parse_narration_response("not json at all") is None


def test_rejects_non_object_response():
    assert risk_llm.parse_narration_response(json.dumps([1, 2, 3])) is None


def test_rejects_response_missing_a_top_level_field():
    raw = json.dumps({"summary": "s", "weakest_link": "a --X--> b"})  # no remediations
    assert risk_llm.parse_narration_response(raw) is None


def test_rejects_empty_summary():
    raw = json.dumps(
        {
            "summary": "   ",
            "weakest_link": "a --X--> b",
            "remediations": [{"priority": 1, "suggestion": "do it"}],
        }
    )
    assert risk_llm.parse_narration_response(raw) is None


def test_rejects_empty_weakest_link():
    raw = json.dumps(
        {
            "summary": "s",
            "weakest_link": "",
            "remediations": [{"priority": 1, "suggestion": "do it"}],
        }
    )
    assert risk_llm.parse_narration_response(raw) is None


def test_rejects_empty_remediations_list():
    raw = json.dumps({"summary": "s", "weakest_link": "a --X--> b", "remediations": []})
    assert risk_llm.parse_narration_response(raw) is None


def test_rejects_remediations_that_is_not_a_list():
    raw = json.dumps(
        {"summary": "s", "weakest_link": "a --X--> b", "remediations": "oops"}
    )
    assert risk_llm.parse_narration_response(raw) is None


def test_one_malformed_remediation_rejects_whole_response():
    raw = json.dumps(
        {
            "summary": "s",
            "weakest_link": "a --X--> b",
            "remediations": [
                {"priority": 1, "suggestion": "fine"},
                {"priority": "high", "suggestion": "bad priority type"},
            ],
        }
    )
    assert risk_llm.parse_narration_response(raw) is None


def test_rejects_remediation_missing_suggestion():
    raw = json.dumps(
        {
            "summary": "s",
            "weakest_link": "a --X--> b",
            "remediations": [{"priority": 1}],
        }
    )
    assert risk_llm.parse_narration_response(raw) is None


def test_rejects_remediation_with_empty_suggestion():
    raw = json.dumps(
        {
            "summary": "s",
            "weakest_link": "a --X--> b",
            "remediations": [{"priority": 1, "suggestion": "  "}],
        }
    )
    assert risk_llm.parse_narration_response(raw) is None


def test_rejects_remediation_item_that_is_not_an_object():
    raw = json.dumps(
        {
            "summary": "s",
            "weakest_link": "a --X--> b",
            "remediations": ["just a string"],
        }
    )
    assert risk_llm.parse_narration_response(raw) is None


# ---------------------------------------------------------------------
# narrate_path: the full pipeline, LLM call mocked out.
# ---------------------------------------------------------------------


def _sample_path():
    return [
        Edge(
            source="external",
            target="app",
            relationship="CAN_REACH",
            evidence="ev",
            confirmed=True,
            confidence=1.0,
            proposed_by="discovery",
        )
    ]


def test_narrate_path_returns_parsed_dict_on_success(monkeypatch):
    monkeypatch.setattr(risk_llm, "call_llm", lambda prompt: _well_formed_response())
    result = risk_llm.narrate_path(_sample_path())
    assert result is not None
    assert result["weakest_link"] == "app --RUNS_AS--> service_account"


def test_narrate_path_returns_none_on_empty_path_without_calling_llm(monkeypatch):
    called = []
    monkeypatch.setattr(
        risk_llm, "call_llm", lambda prompt: called.append(1) or _well_formed_response()
    )
    result = risk_llm.narrate_path([])
    assert result is None
    assert called == []


def test_narrate_path_returns_none_on_malformed_response(monkeypatch):
    monkeypatch.setattr(risk_llm, "call_llm", lambda prompt: "not json")
    result = risk_llm.narrate_path(_sample_path())
    assert result is None


def test_narrate_path_passes_nodes_through_to_prompt(monkeypatch):
    from attackmapper.models import Node

    captured = {}

    def fake_call_llm(prompt):
        captured["prompt"] = prompt
        return _well_formed_response()

    monkeypatch.setattr(risk_llm, "call_llm", fake_call_llm)
    nodes = [
        Node(id="external", type="external", label="Internet"),
        Node(id="app", type="host", label="app01 (10.0.2.10)"),
    ]
    risk_llm.narrate_path(_sample_path(), nodes=nodes)
    assert "app01 (10.0.2.10)" in captured["prompt"]


def test_call_llm_raises_clear_error_without_api_key(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    import sys
    import types

    fake_openai = types.ModuleType("openai")
    fake_openai.OpenAI = object  # present so the lazy import succeeds
    monkeypatch.setitem(sys.modules, "openai", fake_openai)
    with pytest.raises(RuntimeError, match="OPENROUTER_API_KEY"):
        risk_llm.call_llm("a prompt")
