"""Tests for narration/nl_interface.py (Layer 8).

Per the master spec's testing strategy for Phases C-F: never test
against a live model call. Every test here monkeypatches
nl_interface.call_llm (intent parsing) and/or risk_llm.narrate_path
(answer phrasing) with canned values. `ask()` itself calls the real,
unmocked `AttackGraph.find_all_paths` against a fresh in-memory store,
which is the point: this file checks that Layer 8 actually delegates
to the real Layers 4/5 rather than reimplementing graph logic of its
own.
"""

import json

import pytest

from attackmapper import storage
from attackmapper.models import Edge, Node
from attackmapper.narration import nl_interface, risk_llm
from attackmapper.storage import InMemoryStore

# ---------------------------------------------------------------------
# parse_intent_response: schema validation against fixture responses,
# no LLM or storage involved.
# ---------------------------------------------------------------------


def test_parses_well_formed_find_path_response():
    raw = json.dumps({"intent": "find_path", "start": "external", "target": "db"})
    result = nl_interface.parse_intent_response(raw)
    assert result == {"intent": "find_path", "start": "external", "target": "db"}


def test_parses_well_formed_unknown_response():
    raw = json.dumps(
        {
            "intent": "unknown",
            "start": None,
            "target": None,
            "clarification": "not sure what you mean",
        }
    )
    result = nl_interface.parse_intent_response(raw)
    assert result == {
        "intent": "unknown",
        "start": None,
        "target": None,
        "clarification": "not sure what you mean",
    }


def test_unknown_response_without_clarification_defaults_to_empty_string():
    raw = json.dumps({"intent": "unknown"})
    result = nl_interface.parse_intent_response(raw)
    assert result == {
        "intent": "unknown",
        "start": None,
        "target": None,
        "clarification": "",
    }


def test_rejects_non_json_entirely():
    assert nl_interface.parse_intent_response("not json at all") is None


def test_rejects_non_object_response():
    assert nl_interface.parse_intent_response(json.dumps([1, 2, 3])) is None


def test_rejects_unrecognized_intent():
    raw = json.dumps({"intent": "delete_everything", "start": "a", "target": "b"})
    assert nl_interface.parse_intent_response(raw) is None


def test_rejects_missing_intent_field():
    raw = json.dumps({"start": "a", "target": "b"})
    assert nl_interface.parse_intent_response(raw) is None


def test_rejects_find_path_missing_start():
    raw = json.dumps({"intent": "find_path", "target": "db"})
    assert nl_interface.parse_intent_response(raw) is None


def test_rejects_find_path_with_empty_target():
    raw = json.dumps({"intent": "find_path", "start": "external", "target": "  "})
    assert nl_interface.parse_intent_response(raw) is None


def test_rejects_find_path_with_non_string_start():
    raw = json.dumps({"intent": "find_path", "start": 123, "target": "db"})
    assert nl_interface.parse_intent_response(raw) is None


def test_rejects_non_string_clarification():
    raw = json.dumps({"intent": "unknown", "clarification": 5})
    assert nl_interface.parse_intent_response(raw) is None


def test_parses_well_formed_list_findings_response_with_target():
    raw = json.dumps({"intent": "list_findings", "target": "web"})
    result = nl_interface.parse_intent_response(raw)
    assert result == {"intent": "list_findings", "start": None, "target": "web"}


def test_parses_well_formed_list_findings_response_without_target():
    raw = json.dumps({"intent": "list_findings", "target": None})
    result = nl_interface.parse_intent_response(raw)
    assert result == {"intent": "list_findings", "start": None, "target": None}


def test_parses_list_findings_response_missing_target_key():
    # "target" omitted entirely is the same as explicit null -- an
    # environment-wide question.
    raw = json.dumps({"intent": "list_findings"})
    result = nl_interface.parse_intent_response(raw)
    assert result == {"intent": "list_findings", "start": None, "target": None}


def test_rejects_list_findings_with_empty_target():
    raw = json.dumps({"intent": "list_findings", "target": "   "})
    assert nl_interface.parse_intent_response(raw) is None


def test_rejects_list_findings_with_non_string_target():
    raw = json.dumps({"intent": "list_findings", "target": 42})
    assert nl_interface.parse_intent_response(raw) is None


# ---------------------------------------------------------------------
# ask(): the full pipeline. Real storage + real AttackGraph, only the
# two LLM calls (intent parsing, then Layer 7's narration) are mocked.
# ---------------------------------------------------------------------


@pytest.fixture
def demo_store(monkeypatch):
    store = InMemoryStore(seed_demo_data=True)
    monkeypatch.setattr(storage, "_default_store", store)
    return store


def _find_path_response(start="external", target="customer_db"):
    return json.dumps({"intent": "find_path", "start": start, "target": target})


def _well_formed_narration():
    return json.dumps(
        {
            "summary": "An attacker could walk from the internet to the DB.",
            "weakest_link": "app --RUNS_AS--> svc_account",
            "remediations": [{"priority": 1, "suggestion": "Scope the DB role."}],
        }
    )


def test_ask_returns_narrated_answer_for_a_real_path(demo_store, monkeypatch):
    monkeypatch.setattr(nl_interface, "call_llm", lambda prompt: _find_path_response())
    monkeypatch.setattr(risk_llm, "call_llm", lambda prompt: _well_formed_narration())

    result = nl_interface.ask("how could someone reach the customer db?")

    assert result["intent"] == "find_path"
    assert result["start"] == "external"
    assert result["target"] == "customer_db"
    assert result["answered"] is True
    assert result["paths_found"] == 1  # confirmed-only subgraph has exactly one
    assert result["top_path"] is not None
    assert result["top_path"][0].source == "external"
    assert result["narration"]["weakest_link"] == "app --RUNS_AS--> svc_account"
    assert "An attacker could walk from the internet to the DB." in result["answer"]


def test_ask_returns_unresolved_for_unknown_intent(demo_store, monkeypatch):
    called = []
    raw = json.dumps(
        {
            "intent": "unknown",
            "start": None,
            "target": None,
            "clarification": "which database do you mean?",
        }
    )
    monkeypatch.setattr(nl_interface, "call_llm", lambda prompt: raw)
    monkeypatch.setattr(
        risk_llm, "call_llm", lambda prompt: called.append(1) or _well_formed_narration()
    )

    result = nl_interface.ask("tell me about databases")

    assert result["intent"] == "unknown"
    assert result["answered"] is False
    assert result["answer"] == "which database do you mean?"
    assert result["top_path"] is None
    assert called == []  # Layer 7 never even called


def test_ask_returns_unresolved_on_malformed_intent_response(demo_store, monkeypatch):
    monkeypatch.setattr(nl_interface, "call_llm", lambda prompt: "not json")
    result = nl_interface.ask("some question")
    assert result["answered"] is False
    assert result["top_path"] is None


def test_ask_declines_when_model_invents_an_unknown_node_id(demo_store, monkeypatch):
    monkeypatch.setattr(
        nl_interface,
        "call_llm",
        lambda prompt: _find_path_response(start="external", target="not_a_real_node"),
    )
    called = []
    monkeypatch.setattr(
        risk_llm, "call_llm", lambda prompt: called.append(1) or _well_formed_narration()
    )

    result = nl_interface.ask("reach the thingamajig")

    assert result["answered"] is False
    assert "not_a_real_node" in result["answer"]
    assert called == []  # never reached the graph or Layer 7


def test_ask_handles_start_equal_to_target(demo_store, monkeypatch):
    monkeypatch.setattr(
        nl_interface,
        "call_llm",
        lambda prompt: _find_path_response(start="db", target="db"),
    )
    result = nl_interface.ask("can db reach itself?")
    assert result["answered"] is False
    assert "same node" in result["answer"]


def test_ask_reports_no_path_found_without_calling_layer_7(demo_store, monkeypatch):
    # 'external' and 'customer_db' are connected in the seeded demo
    # data, but 'svc_account' alone has no outgoing confirmed edge back
    # to 'external', so this direction has no path.
    monkeypatch.setattr(
        nl_interface,
        "call_llm",
        lambda prompt: _find_path_response(start="customer_db", target="external"),
    )
    called = []
    monkeypatch.setattr(
        risk_llm, "call_llm", lambda prompt: called.append(1) or _well_formed_narration()
    )

    result = nl_interface.ask("can the db reach the internet?")

    assert result["answered"] is True
    assert result["paths_found"] == 0
    assert result["top_path"] is None
    assert "don't see a way" in result["answer"]
    assert called == []


def test_ask_falls_back_to_raw_path_when_layer_7_fails(demo_store, monkeypatch):
    monkeypatch.setattr(nl_interface, "call_llm", lambda prompt: _find_path_response())
    monkeypatch.setattr(risk_llm, "call_llm", lambda prompt: "not json")

    result = nl_interface.ask("how could someone reach the customer db?")

    assert result["answered"] is True
    assert result["narration"] is None
    assert result["top_path"] is not None
    assert "couldn't generate a narrative" in result["answer"]
    assert "external" in result["answer"]


def test_ask_respects_min_confidence(demo_store, monkeypatch):
    """The seeded demo data has an unconfirmed app->db shortcut edge.
    At min_confidence=1.0 (default) app->db should not exist as a
    direct hop; passing a lower threshold should surface a shorter
    path. This exercises that ask() actually threads min_confidence
    through to storage.load_graph rather than hardcoding 1.0."""
    monkeypatch.setattr(
        nl_interface,
        "call_llm",
        lambda prompt: _find_path_response(start="external", target="db"),
    )
    monkeypatch.setattr(risk_llm, "call_llm", lambda prompt: _well_formed_narration())

    strict = nl_interface.ask("reach db", min_confidence=1.0)
    lenient = nl_interface.ask("reach db", min_confidence=0.5)

    assert strict["paths_found"] == 1
    assert lenient["paths_found"] == 2  # the confirmed chain + the shortcut


def test_ask_uses_caller_supplied_nodes_for_intent_resolution(demo_store, monkeypatch):
    captured = {}

    def fake_call_llm(prompt):
        captured["prompt"] = prompt
        return _find_path_response(start="external", target="custom")

    monkeypatch.setattr(nl_interface, "call_llm", fake_call_llm)

    custom_nodes = [
        Node(id="external", type="external", label="Internet"),
        Node(id="custom", type="asset", label="A custom node not in the store"),
    ]
    result = nl_interface.ask("reach my custom thing", nodes=custom_nodes)

    assert "A custom node not in the store" in captured["prompt"]
    # 'custom' resolved against the caller-supplied node list (so the
    # existence check passes), but it isn't actually in storage's real
    # graph -- find_all_paths cleanly reports no path rather than
    # crashing on a node it doesn't recognize.
    assert result["answered"] is True
    assert result["paths_found"] == 0


# ---------------------------------------------------------------------
# ask(): the "list_findings" intent -- general vulnerability Q&A,
# no path-finding involved. Layer 7 (risk_llm) must never be called
# for this intent: it's a deterministic formatter over
# storage.list_findings(), not a second inference step.
# ---------------------------------------------------------------------


def _list_findings_response(target=None):
    return json.dumps({"intent": "list_findings", "target": target})


def test_ask_lists_findings_for_a_specific_host(demo_store, monkeypatch):
    storage.save_finding(
        {
            "host_id": "web",
            "type": "missing_security_headers",
            "severity": "medium",
            "description": "Response is missing Content-Security-Policy",
            "evidence": "HTTP GET /",
        }
    )
    storage.save_finding(
        {
            "host_id": "db",
            "type": "exposed_env_file",
            "severity": "critical",
            "description": "db exposes a .env file",
            "evidence": "HTTP GET /.env",
        }
    )
    monkeypatch.setattr(
        nl_interface, "call_llm", lambda prompt: _list_findings_response(target="web")
    )
    narrate_called = []
    monkeypatch.setattr(
        risk_llm,
        "call_llm",
        lambda prompt: narrate_called.append(1) or _well_formed_narration(),
    )

    result = nl_interface.ask("what's wrong with web01?")

    assert result["intent"] == "list_findings"
    assert result["target"] == "web"
    assert result["answered"] is True
    assert len(result["findings"]) == 1
    assert result["findings"][0]["host_id"] == "web"
    assert "Content-Security-Policy" in result["answer"]
    assert "exposed_env_file" not in result["answer"]  # scoped to web, not db
    assert narrate_called == []  # Layer 7 never called for this intent


def test_ask_lists_findings_across_environment_when_target_is_null(
    demo_store, monkeypatch
):
    storage.save_finding(
        {
            "host_id": "web",
            "type": "missing_security_headers",
            "severity": "low",
            "description": "no HSTS header",
            "evidence": "HTTP GET /",
        }
    )
    storage.save_finding(
        {
            "host_id": "db",
            "type": "exposed_env_file",
            "severity": "critical",
            "description": "db exposes a .env file",
            "evidence": "HTTP GET /.env",
        }
    )
    monkeypatch.setattr(
        nl_interface, "call_llm", lambda prompt: _list_findings_response(target=None)
    )

    result = nl_interface.ask("what are our worst vulnerabilities?")

    assert result["target"] is None
    assert result["answered"] is True
    assert len(result["findings"]) == 2
    # Sorted worst-first: critical before low.
    assert result["findings"][0]["severity"] == "critical"
    assert "exposed_env_file" in result["findings"][0]["type"]
    assert "db" in result["answer"]  # host id shown when not scoped to one host


def test_ask_list_findings_declines_unknown_target(demo_store, monkeypatch):
    monkeypatch.setattr(
        nl_interface,
        "call_llm",
        lambda prompt: _list_findings_response(target="not_a_real_node"),
    )

    result = nl_interface.ask("what's wrong with the thingamajig?")

    assert result["answered"] is False
    assert "not_a_real_node" in result["answer"]


def test_ask_list_findings_with_no_findings_yet(demo_store, monkeypatch):
    monkeypatch.setattr(
        nl_interface, "call_llm", lambda prompt: _list_findings_response(target="web")
    )

    result = nl_interface.ask("what's wrong with web01?")

    assert result["answered"] is True
    assert result["findings"] == []
    assert "No findings recorded" in result["answer"]


def test_call_llm_raises_clear_error_without_api_key(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    import sys
    import types

    fake_openai = types.ModuleType("openai")
    fake_openai.OpenAI = object  # present so the lazy import succeeds
    monkeypatch.setitem(sys.modules, "openai", fake_openai)
    with pytest.raises(RuntimeError, match="OPENROUTER_API_KEY"):
        nl_interface.call_llm("a prompt")
