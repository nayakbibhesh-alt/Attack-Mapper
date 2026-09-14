"""Tests for prompts/evidence_interpretation.py. Pure function of its
inputs -- no LLM call, no storage -- so these just check the prompt is
built correctly from given typed inputs, matching the style of
test_prompts.py for Layer 2's prompt builder.
"""

from attackmapper.prompts.evidence_interpretation import (
    build_evidence_interpretation_prompt,
)


def test_prompt_includes_evidence_type_and_raw_evidence():
    prompt = build_evidence_interpretation_prompt(
        "service_banner", "FooServer/9.9.9 experimental-mode", host=None
    )
    assert "service_banner" in prompt
    assert "FooServer/9.9.9 experimental-mode" in prompt


def test_prompt_includes_host_context_when_given():
    host = {"id": "host-1", "hostname": "web01", "ip": "10.0.1.10", "os": "Linux"}
    prompt = build_evidence_interpretation_prompt("http_response", "body", host=host)
    assert "host-1" in prompt
    assert "web01" in prompt
    assert "10.0.1.10" in prompt


def test_prompt_handles_missing_host_without_erroring():
    prompt = build_evidence_interpretation_prompt("config_snippet", "some text")
    assert "host unknown" in prompt


def test_prompt_demands_json_only_and_shows_schema():
    prompt = build_evidence_interpretation_prompt("service_banner", "ev")
    assert "ONLY JSON" in prompt
    assert '"severity"' in prompt
    assert '"confidence"' in prompt


def test_prompt_lists_valid_severities():
    prompt = build_evidence_interpretation_prompt("service_banner", "ev")
    assert "low" in prompt and "medium" in prompt and "high" in prompt
    assert "critical" in prompt


def test_prompt_instructs_no_further_actions_or_low_confidence_filtering():
    prompt = build_evidence_interpretation_prompt("service_banner", "ev")
    assert "You do not decide what to scan next" in prompt
    assert "Do not filter anything out yourself" in prompt


def test_prompt_is_deterministic_given_same_inputs():
    host = {"id": "h1", "hostname": "app01", "ip": "10.0.2.10", "os": "Linux"}
    first = build_evidence_interpretation_prompt("service_banner", "ev", host)
    second = build_evidence_interpretation_prompt("service_banner", "ev", host)
    assert first == second
