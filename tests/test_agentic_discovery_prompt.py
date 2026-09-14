"""Tests for prompts/agentic_discovery.py. Pure function of its
inputs -- no LLM call, no storage -- so these just check the prompt is
built correctly from given typed inputs and that the scope/read-only
guardrails are actually present in the text sent to the model.
"""

from attackmapper.prompts.agentic_discovery import build_next_probe_prompt


def test_prompt_includes_scope_list():
    prompt = build_next_probe_prompt(
        hosts=[], services=[], findings=[], scope=["10.0.1.10", "10.0.2.0/24"]
    )
    assert "10.0.1.10" in prompt
    assert "10.0.2.0/24" in prompt


def test_prompt_handles_empty_scope_without_erroring():
    prompt = build_next_probe_prompt(hosts=[], services=[], findings=[], scope=[])
    assert "(empty scope)" in prompt


def test_prompt_includes_host_service_and_finding_details():
    hosts = [{"id": "host-1", "hostname": "web01", "ip": "10.0.1.10", "os": "linux"}]
    services = [
        {"host_id": "host-1", "port": 443, "protocol": "tcp", "service_name": "https"}
    ]
    findings = [
        {
            "host_id": "host-1",
            "type": "missing_security_headers",
            "severity": "low",
            "confidence": 0.8,
            "source": "scanner",
            "description": "no CSP header set",
        }
    ]
    prompt = build_next_probe_prompt(
        hosts=hosts, services=services, findings=findings, scope=["10.0.1.10"]
    )
    assert "web01" in prompt
    assert "443/tcp" in prompt
    assert "missing_security_headers" in prompt
    assert "no CSP header set" in prompt


def test_prompt_handles_empty_inventory_without_erroring():
    prompt = build_next_probe_prompt(
        hosts=[], services=[], findings=[], scope=["10.0.1.10"]
    )
    assert "no hosts known yet" in prompt
    assert "no services known yet" in prompt
    assert "no findings known yet" in prompt


def test_prompt_demands_json_only_and_shows_schema():
    prompt = build_next_probe_prompt(
        hosts=[], services=[], findings=[], scope=["10.0.1.10"]
    )
    assert "ONLY JSON" in prompt
    assert '"action_type"' in prompt
    assert '"rationale"' in prompt


def test_prompt_lists_allowed_action_types():
    prompt = build_next_probe_prompt(
        hosts=[], services=[], findings=[], scope=["10.0.1.10"]
    )
    assert "nmap_scan" in prompt
    assert "http_probe" in prompt
    assert "postgres_roles" in prompt
    assert "stop" in prompt


def test_prompt_states_read_only_guardrail():
    prompt = build_next_probe_prompt(
        hosts=[], services=[], findings=[], scope=["10.0.1.10"]
    )
    assert "read-only" in prompt
    assert "exploitation" in prompt


def test_prompt_states_scope_is_enforced_not_advisory():
    prompt = build_next_probe_prompt(
        hosts=[], services=[], findings=[], scope=["10.0.1.10"]
    )
    assert "discarded" in prompt


def test_prompt_respects_max_actions_parameter():
    prompt = build_next_probe_prompt(
        hosts=[], services=[], findings=[], scope=["10.0.1.10"], max_actions=1
    )
    assert "up to 1 specific next probes" in prompt


def test_prompt_is_deterministic_given_same_inputs():
    hosts = [{"id": "host-1", "hostname": "web01", "ip": "10.0.1.10", "os": "linux"}]
    p1 = build_next_probe_prompt(
        hosts=hosts, services=[], findings=[], scope=["10.0.1.10"]
    )
    p2 = build_next_probe_prompt(
        hosts=hosts, services=[], findings=[], scope=["10.0.1.10"]
    )
    assert p1 == p2
