"""attackmapper/prompts/relationship_inference.py — the only place the
exact wording of the Relationship Inference prompt (Layer 2) lives.

Kept separate from inference/relationship_llm.py per the master spec:
"Keep every prompt template in a dedicated prompts/ module, one
function per integration point, each returning the fully-formed prompt
string given typed inputs -- this keeps prompts versionable and
testable independent of the LLM call plumbing itself." No LLM calls
happen in this file; it's a pure function of its inputs, which is what
makes it unit-testable without ever hitting a live model
(tests/test_prompts.py).
"""

from __future__ import annotations

import json

# Kept in sync with the "Relationship Inference — expected output
# schema" block in ATTACKMAPPER_MASTER.md section 7. Shown to the LLM
# verbatim as a worked example rather than described in prose, since
# models follow a concrete shape far more reliably than a description
# of one.
_SCHEMA_EXAMPLE = {
    "relationships": [
        {
            "source": "app",
            "target": "db",
            "relationship_type": "CAN_ACCESS",
            "evidence": "app's DB connection uses a superuser role per finding #12",
            "confidence": 0.9,
        }
    ]
}

# Not an exhaustive/enforced enum (the master spec's relationship_type
# column ends in "| ..."), just the known vocabulary offered to the
# LLM so it prefers consistent naming over inventing synonyms.
_KNOWN_RELATIONSHIP_TYPES = ["CONNECTS_TO", "CAN_REACH", "RUNS_AS", "CAN_ACCESS"]


def build_relationship_inference_prompt(
    findings: list[dict],
    hosts: list[dict] | None = None,
    services: list[dict] | None = None,
) -> str:
    """Build the Layer 2 prompt.

    `findings` is the structured findings list from storage.list_findings()
    (or a caller-supplied subset). `hosts` is storage.list_hosts(), passed
    along so the LLM has real host ids to anchor "source"/"target" on
    instead of inventing its own -- optional because a caller might be
    reasoning over findings for hosts not yet in the inventory.

    `services` is storage.list_services() -- the raw open-port inventory
    from discovery, independent of findings. Rigid parsers only turn a
    service into a `Finding` when something about it is actively
    noteworthy (a known-vulnerable banner, a missing header, ...), so a
    perfectly ordinary open SSH/HTTP port on a real scanned host never
    produces a finding at all. Without this block, a real (non-lab)
    target with no interesting findings would give this layer nothing
    to reason over and it would silently propose zero relationships --
    including the most basic one, "external can reach this host,"
    which only needs "there's an open port" as evidence, not a
    vulnerability. Findings remain the primary signal for anything
    beyond bare reachability (RUNS_AS, CAN_ACCESS, etc.); this is
    additive, not a replacement.

    Only structured fields are included in the prompt -- never a raw
    scanner dump -- per the master spec's general LLM-call pattern
    ("Build a prompt containing only the structured data needed").
    """
    hosts = hosts or []
    services = services or []
    host_lines = (
        "\n".join(
            f"- id={h['id']}  hostname={h.get('hostname', '?')}  ip={h.get('ip', '?')}"
            for h in hosts
        )
        or "(no host inventory provided)"
    )

    service_lines = (
        "\n".join(
            f"- host_id={s['host_id']} {s.get('protocol', '?')}/{s.get('port', '?')} "
            f"{s.get('service_name', 'unknown')}"
            for s in services
        )
        or "(no open services provided)"
    )

    finding_lines = (
        "\n".join(
            f"- id={f.get('id', '?')} host_id={f['host_id']} type={f['type']} "
            f"severity={f['severity']} confidence={f.get('confidence', 1.0)}: "
            f"{f['description']} | evidence: {f['evidence']}"
            for f in findings
        )
        or "(no findings provided)"
    )

    schema_block = json.dumps(_SCHEMA_EXAMPLE, indent=2)

    return f"""You are the Relationship Inference layer of a network attack-path \
mapping tool. You are given a fixed inventory of hosts, their open \
services, and a list of security findings already gathered about them. \
Your only job is to identify pairs of hosts/accounts that have an \
exploitable relationship implied by this evidence, and how confident \
you are in each one. You do not decide what to scan next, you do not \
take any action, and nothing you say is verified yet -- every \
relationship you propose will be stored as UNCONFIRMED and reviewed \
later against deterministic checks or a human.

Known hosts:
{host_lines}

Open services (from port scanning, independent of any finding):
{service_lines}

Findings:
{finding_lines}

Respond with ONLY JSON, no preamble, no markdown code fences, matching \
exactly this shape:
{schema_block}

Rules:
- "source" and "target" must be host ids from the inventory above, an \
account-style identifier you introduce and then reuse consistently for \
the same account, or the literal string "external" for the public \
internet.
- "relationship_type" should be one of {_KNOWN_RELATIONSHIP_TYPES} \
unless none of those fit, in which case use the closest short \
UPPER_SNAKE verb phrase.
- An open service alone is enough evidence for a low-to-medium \
confidence "external CAN_REACH host_id" proposal (a merely open port \
is not proof it's internet-facing or exploitable) -- you do not need a \
Finding to propose basic reachability. Findings raise your confidence \
or justify a different relationship_type/account/deeper hop.
- "confidence" is a float between 0.0 and 1.0 reflecting how sure you \
are the relationship actually holds -- not how severe it would be if \
true.
- Include every relationship you can support with evidence, even \
low-confidence ones. Do not filter anything out yourself; confidence \
is how the caller filters downstream.
- If the evidence doesn't support any relationship, return exactly \
{{"relationships": []}}.
"""
