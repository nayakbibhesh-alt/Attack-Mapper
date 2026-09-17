"""Tests for prompts/nl_query.py. Pure function of its inputs -- no
LLM call, no storage -- matching the style of test_prompts.py,
test_evidence_interpretation_prompt.py, and test_risk_narration_prompt.py
for the other three prompt builders.
"""

from attackmapper.models import Node
from attackmapper.prompts.nl_query import build_nl_query_prompt


def _sample_nodes():
    return [
        Node(id="external", type="external", label="Internet"),
        Node(id="web", type="host", label="web01 (10.0.1.10)"),
        Node(id="db", type="host", label="db01 (10.0.3.10)"),
    ]


def test_prompt_includes_the_question_verbatim():
    prompt = build_nl_query_prompt(
        "how could someone reach the db from the internet?", _sample_nodes()
    )
    assert "how could someone reach the db from the internet?" in prompt


def test_prompt_includes_known_node_ids_and_labels():
    prompt = build_nl_query_prompt("test question", _sample_nodes())
    assert "id=external" in prompt
    assert "id=web" in prompt
    assert "label=web01 (10.0.1.10)" in prompt
    assert "id=db" in prompt


def test_prompt_handles_empty_node_list_without_erroring():
    prompt = build_nl_query_prompt("test question", nodes=None)
    assert "no nodes known yet" in prompt


def test_prompt_demands_json_only_and_shows_schema():
    prompt = build_nl_query_prompt("test question", _sample_nodes())
    assert "ONLY JSON" in prompt
    assert '"intent"' in prompt
    assert '"start"' in prompt
    assert '"target"' in prompt


def test_prompt_shows_unknown_intent_escape_hatch():
    prompt = build_nl_query_prompt("test question", _sample_nodes())
    assert '"unknown"' in prompt
    assert '"clarification"' in prompt


def test_prompt_instructs_no_guessing_node_ids():
    prompt = build_nl_query_prompt("test question", _sample_nodes())
    assert "never invented, abbreviated, or guessed" in prompt


def test_prompt_instructs_external_literal_for_internet():
    prompt = build_nl_query_prompt("test question", _sample_nodes())
    assert '"external"' in prompt


def test_prompt_shows_list_findings_intent():
    prompt = build_nl_query_prompt("test question", _sample_nodes())
    assert '"list_findings"' in prompt


def test_prompt_explains_list_findings_target_can_be_null():
    prompt = build_nl_query_prompt("test question", _sample_nodes())
    assert "null if it doesn't" in prompt


def test_prompt_is_deterministic_given_same_inputs():
    nodes = _sample_nodes()
    first = build_nl_query_prompt("same question", nodes)
    second = build_nl_query_prompt("same question", nodes)
    assert first == second
