"""attackmapper/prompts/attack_chain.py — the only place the exact
wording of the Attack Chain Reasoning prompt lives.

Same pattern as prompts/relationship_inference.py and
prompts/risk_narration.py: a pure function of typed inputs, no LLM
call, no storage access -- testable in isolation
(tests/test_attack_chain_prompt.py) and versionable independent of the
call plumbing in narration/attack_chain_llm.py.

What this layer is for, and how it differs from the two LLM layers
that already exist:

- inference/relationship_llm.py proposes HOST-level edges (does host A
  reach host B?) from findings/services. It needs more than one host
  in inventory to say anything interesting, and its output only shows
  up once graph.py's path finder has host-to-host hops to walk.
- narration/risk_llm.py explains ONE already-computed host-to-host
  path in plain English. It never looks at raw findings directly.

Neither of those tells the story "this scan found five separate,
individually-modest findings on the SAME host -- here's how a real
attacker would actually combine them into one breach," which is the
gap this module closes. It reasons directly over the findings list a
single scan just produced (no host-to-host graph required at all --
one target with five findings is enough), and is meant to run
automatically as part of `discovery.pipeline.scan_target_url`, not as
a separate manual step.
"""

from __future__ import annotations

import json

# Kept in sync with the "Attack Chain Reasoning — expected output
# schema" section of this module's docstring. Shown to the LLM
# verbatim as a worked example, matching every other prompt module's
# pattern of showing rather than describing the target shape.
_SCHEMA_EXAMPLE = {
    "chains": [
        {
            "title": "Leaked database credentials via exposed .env, reachable Postgres port",
            "severity": "critical",
            "finding_ids": ["finding-abc123", "finding-def456"],
            "steps": [
                {
                    "step": 1,
                    "action": (
                        "Attacker requests /.env directly and obtains the "
                        "production database connection string"
                    ),
                    "based_on": "finding-abc123",
                },
                {
                    "step": 2,
                    "action": (
                        "Attacker connects straight to the Postgres port "
                        "using the leaked credentials -- no exploit needed, "
                        "just a normal client connection"
                    ),
                    "based_on": "finding-def456",
                },
                {
                    "step": 3,
                    "action": "Attacker has full read/write access to the production database",
                    "based_on": None,
                },
            ],
            "impact": (
                "Full compromise of the production database: every "
                "customer record can be read, modified, or deleted."
            ),
            "remediation": (
                "Rotate the leaked credentials immediately, remove the "
                ".env file from the public webroot, and firewall the "
                "database port to only the application's own network."
            ),
        }
    ]
}

KNOWN_SEVERITIES = ["critical", "high", "medium", "low"]


def _format_finding(f: dict) -> str:
    fid = f.get("id", "?")
    return (
        f"- id={fid} type={f.get('type')} severity={f.get('severity')} "
        f"host_id={f.get('host_id')}\n"
        f"  description: {f.get('description', '')}\n"
        f"  evidence: {f.get('evidence', '')}"
    )


def build_attack_chain_prompt(
    findings: list[dict],
    hosts: list[dict] | None = None,
    services: list[dict] | None = None,
) -> str:
    """Build the Attack Chain Reasoning prompt.

    `findings` is the structured findings list to reason over --
    typically every finding from one just-completed scan (possibly
    spanning more than one host_id, e.g. a scan that also ran nmap
    against the resolved IP). `hosts`/`services` (optional) give the
    LLM the same host/service context relationship_inference's prompt
    gets, so it can tell whether two findings sharing a host_id are
    actually the same reachable system.

    Deliberately does NOT include the deterministic host-to-host graph
    (Nodes/Edges) at all -- this layer's whole point is to find chains
    a single-host scan already has enough material for, without
    needing relationship_llm to have run first. A caller that also
    wants host-to-host chains should still use risk_llm.narrate_path
    on top of this, not instead of it.
    """
    findings_block = "\n".join(_format_finding(f) for f in findings) or "(none)"

    hosts_block = "(not provided)"
    if hosts:
        hosts_block = "\n".join(
            f"- id={h.get('id')} hostname={h.get('hostname')} ip={h.get('ip')} os={h.get('os')}"
            for h in hosts
        )

    services_block = "(not provided)"
    if services:
        services_block = "\n".join(
            f"- host_id={s.get('host_id')} {s.get('port')}/{s.get('protocol')} {s.get('service_name')}"
            for s in services
        )

    schema_block = json.dumps(_SCHEMA_EXAMPLE, indent=2)

    return f"""You are the Attack Chain Reasoning layer of AttackMapper, a \
security scanning tool. You are given every finding (vulnerability, \
misconfiguration, or exposure) a scan just produced for one target. \
Individually, several of these findings might look low-severity or \
merely informational. Your job is to think like an attacker and \
identify which findings COMBINE into a realistic, concrete attack \
chain -- an ordered sequence of steps that starts from what's \
publicly visible and ends in a genuine compromise (credential theft, \
unauthorized data access, remote code execution, full system \
takeover, etc.).

Rules:
- Only propose a chain when the findings you cite genuinely combine \
into something worse than any one of them alone -- e.g. a leaked \
credential PLUS a reachable service that credential works against, \
or a missing security header PLUS a reflected input PLUS a cookie \
without the Secure flag. Do not pad a single finding out into a fake \
"chain" of one step restating it.
- Every step must be concrete and specific to THESE findings -- name \
the actual finding type/evidence, not a generic attacker-methodology \
description. A step should read like an incident report, not a \
textbook.
- Cite the finding(s) each step is based on via "based_on" (a finding \
id from the list below), or null for a step that's a logical \
consequence of the previous steps rather than a specific finding \
(e.g. the final "attacker now has X access" step).
- If nothing here actually chains -- the findings are independent and \
don't combine into anything worse -- return {{"chains": []}}. An \
empty list is a valid, useful answer; do not invent a chain just to \
have something to report.
- Order chains by severity, most severe first.
- "severity" must be exactly one of: {", ".join(KNOWN_SEVERITIES)}.

Findings from this scan:
{findings_block}

Hosts:
{hosts_block}

Services:
{services_block}

Respond with ONLY JSON, no preamble, no markdown code fences, matching \
exactly this shape:
{schema_block}
"""
