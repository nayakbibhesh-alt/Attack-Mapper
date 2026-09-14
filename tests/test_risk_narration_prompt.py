"""Tests for prompts/risk_narration.py. Pure function of its inputs --
no LLM call, no storage -- matching the style of test_prompts.py and
test_evidence_interpretation_prompt.py for the other two prompt
builders.
"""

from attackmapper.models import Edge, Node
from attackmapper.prompts.risk_narration import build_risk_narration_prompt


def _sample_path():
    return [
        Edge(
            source="external",
            target="web",
            relationship="CAN_REACH",
            evidence="port 443 open, no ACL",
            confirmed=True,
            confidence=1.0,
            proposed_by="discovery",
        ),
        Edge(
            source="web",
            target="app",
            relationship="RUNS_AS",
            evidence="finding #7: embedded creds",
            confirmed=False,
            confidence=0.6,
            proposed_by="llm",
        ),
    ]


def test_prompt_includes_hop_details_and_evidence():
    prompt = build_risk_narration_prompt(_sample_path())
    assert "CAN_REACH" in prompt
    assert "RUNS_AS" in prompt
    assert "port 443 open, no ACL" in prompt
    assert "finding #7: embedded creds" in prompt


def test_prompt_marks_unconfirmed_hops():
    prompt = build_risk_narration_prompt(_sample_path())
    assert "UNCONFIRMED" in prompt
    assert "proposed_by=llm" in prompt


def test_prompt_includes_node_labels_when_given():
    nodes = [
        Node(id="external", type="external", label="Internet"),
        Node(id="web", type="host", label="web01 (10.0.1.10)"),
        Node(id="app", type="host", label="app01 (10.0.2.10)"),
    ]
    prompt = build_risk_narration_prompt(_sample_path(), nodes=nodes)
    assert "web01 (10.0.1.10)" in prompt
    assert "app01 (10.0.2.10)" in prompt


def test_prompt_falls_back_to_bare_ids_without_nodes():
    prompt = build_risk_narration_prompt(_sample_path(), nodes=None)
    assert "external --CAN_REACH--> web" in prompt


def test_prompt_handles_empty_path_without_erroring():
    prompt = build_risk_narration_prompt([])
    assert "(empty path)" in prompt


def test_prompt_demands_json_only_and_shows_schema():
    prompt = build_risk_narration_prompt(_sample_path())
    assert "ONLY JSON" in prompt
    assert '"weakest_link"' in prompt
    assert '"remediations"' in prompt
    assert '"priority"' in prompt


def test_prompt_instructs_no_path_modification():
    prompt = build_risk_narration_prompt(_sample_path())
    assert "You do not change the path" in prompt
    assert "never merged back into the graph" in prompt


def test_prompt_is_deterministic_given_same_inputs():
    path = _sample_path()
    first = build_risk_narration_prompt(path)
    second = build_risk_narration_prompt(path)
    assert first == second
