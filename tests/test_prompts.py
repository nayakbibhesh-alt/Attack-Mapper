"""Tests for prompts/relationship_inference.py. Pure function of its
inputs -- no LLM call, no storage -- so these just check the prompt is
built correctly from given typed inputs, per the master spec's note
that prompts should be "testable independent of the LLM call plumbing
itself."
"""

from attackmapper.prompts.relationship_inference import (
    build_relationship_inference_prompt,
)


def test_prompt_includes_finding_details():
    findings = [
        {
            "id": "finding-1",
            "host_id": "host-1",
            "type": "leaked_credential",
            "severity": "high",
            "description": "Debug endpoint returns a service account token",
            "evidence": "GET /internal/debug returned service_account_token",
            "confidence": 0.95,
        }
    ]
    prompt = build_relationship_inference_prompt(findings, hosts=[])
    assert "leaked_credential" in prompt
    assert "finding-1" in prompt
    assert "host_id=host-1" in prompt
    assert "GET /internal/debug returned service_account_token" in prompt


def test_prompt_includes_host_inventory():
    hosts = [{"id": "host-1", "hostname": "web01", "ip": "10.0.1.10"}]
    prompt = build_relationship_inference_prompt(findings=[], hosts=hosts)
    assert "host-1" in prompt
    assert "web01" in prompt
    assert "10.0.1.10" in prompt


def test_prompt_handles_empty_inputs_without_erroring():
    prompt = build_relationship_inference_prompt(findings=[], hosts=None)
    assert "no host inventory provided" in prompt
    assert "no findings provided" in prompt


def test_prompt_demands_json_only_and_shows_schema():
    prompt = build_relationship_inference_prompt(findings=[], hosts=[])
    assert "ONLY JSON" in prompt
    assert '"relationship_type"' in prompt
    assert '"confidence"' in prompt


def test_prompt_instructs_low_confidence_should_not_be_filtered():
    prompt = build_relationship_inference_prompt(findings=[], hosts=[])
    assert "Do not filter anything out yourself" in prompt


def test_prompt_is_deterministic_given_same_inputs():
    findings = [
        {
            "id": "f1",
            "host_id": "h1",
            "type": "weak_password",
            "severity": "medium",
            "description": "desc",
            "evidence": "ev",
            "confidence": 1.0,
        }
    ]
    hosts = [{"id": "h1", "hostname": "app01", "ip": "10.0.2.10"}]
    first = build_relationship_inference_prompt(findings, hosts)
    second = build_relationship_inference_prompt(findings, hosts)
    assert first == second
