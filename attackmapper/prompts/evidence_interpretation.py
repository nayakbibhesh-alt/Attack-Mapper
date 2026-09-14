"""attackmapper/prompts/evidence_interpretation.py — the only place the
exact wording of the Evidence Interpretation prompt (Layer 1's LLM
half) lives.

Kept separate from discovery/evidence_llm.py per the master spec's
rule that prompt templates live in a dedicated prompts/ module, one
function per integration point, each a pure function of typed inputs
-- versionable and unit-testable (tests/test_evidence_interpretation_prompt.py)
without ever hitting a live model.
"""

from __future__ import annotations

import json

# Kept in sync with the "Evidence Interpretation — expected output
# schema" block in ATTACKMAPPER_MASTER.md section 7. Shown to the LLM
# verbatim as a worked example rather than described in prose, since
# models follow a concrete shape far more reliably than a description
# of one.
_SCHEMA_EXAMPLE = {
    "findings": [
        {
            "type": "leaked_credential",
            "severity": "high",
            "description": "Debug endpoint returns a service account token",
            "evidence": (
                "GET /internal/debug returned service_account_token in "
                "plaintext"
            ),
            "confidence": 0.95,
        }
    ]
}

# Not an exhaustive/enforced enum (the findings.type column in the
# master spec is illustrative -- "e.g. 'ssrf', 'leaked_credential',
# 'weak_password'"), just the known vocabulary offered to the LLM so it
# prefers consistent naming over inventing synonyms for something a
# rigid parser or a future prompt version already has a name for.
_KNOWN_FINDING_TYPES = [
    "leaked_credential",
    "weak_password",
    "ssrf",
    "known_backdoored_software",
    "outdated_software",
    "missing_security_headers",
    "overprivileged_role",
    "misconfiguration",
]

_VALID_SEVERITIES = ["low", "medium", "high", "critical"]


def build_evidence_interpretation_prompt(
    evidence_type: str,
    raw_evidence: str,
    host: dict | None = None,
) -> str:
    """Build the Layer 1 (Evidence Interpretation) prompt.

    `evidence_type` is a short label for what kind of raw evidence this
    is (e.g. "service_banner", "http_response", "config_snippet") --
    purely descriptive context for the model, not validated against a
    fixed enum, since the whole point of this layer is to cover
    whatever ambiguous shape shows up that the rigid parsers in
    discovery/parsers.py don't already handle.

    `raw_evidence` is the actual ambiguous text: an unfamiliar service
    banner, an HTTP response body/headers dump, a config file snippet,
    etc. `host` is the host record (from storage.list_hosts()) this
    evidence came from, if known -- included so the model can reason
    about context (e.g. "this is the same host as web01") without
    being handed the whole inventory or any unrelated data, per the
    master spec's "only structured data needed" rule.

    This layer classifies and structures evidence it is given; it does
    not decide what to scan next and does not take any action -- the
    prompt says so explicitly so the model doesn't try to suggest
    further probes or exploitation steps.
    """
    host_block = (
        f"- id={host['id']}  hostname={host.get('hostname', '?')}  "
        f"ip={host.get('ip', '?')}  os={host.get('os', '?')}"
        if host
        else "(host unknown/not yet inventoried)"
    )

    schema_block = json.dumps(_SCHEMA_EXAMPLE, indent=2)

    return f"""You are the Evidence Interpretation layer of a network attack-path \
mapping tool. You are given one piece of raw evidence that a rigid, \
deterministic parser could not confidently classify -- an unfamiliar \
service banner, an HTTP response, or a configuration snippet. Your \
only job is to decide whether this evidence indicates a security \
finding, and if so, structure it. You do not decide what to scan \
next, you do not take any action, and nothing you say is verified yet \
-- every finding you propose will be stored with source="llm_inferred" \
and your own confidence score attached, not treated as ground truth.

Evidence type: {evidence_type}

Host this evidence came from:
{host_block}

Raw evidence:
\"\"\"
{raw_evidence}
\"\"\"

Respond with ONLY JSON, no preamble, no markdown code fences, matching \
exactly this shape:
{schema_block}

Rules:
- "type" should be one of {_KNOWN_FINDING_TYPES} unless none of those \
fit, in which case use the closest short snake_case label.
- "severity" must be exactly one of {_VALID_SEVERITIES}.
- "description" is a short, plain-English statement of what the issue \
is -- no speculation about exploitation steps or next actions.
- "evidence" should quote or closely paraphrase the specific part of \
the raw evidence that supports the finding, so a human reviewer can \
verify it against the original.
- "confidence" is a float between 0.0 and 1.0 reflecting how sure you \
are this really is a finding of the stated type -- not how severe it \
would be if true. An unfamiliar-but-probably-benign banner should get \
a low confidence, not be omitted.
- Include every finding you can support with evidence, even \
low-confidence ones. Do not filter anything out yourself; confidence \
is how the caller filters downstream.
- If the evidence doesn't support any finding, return exactly \
{{"findings": []}}.
"""
