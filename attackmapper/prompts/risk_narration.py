"""attackmapper/prompts/risk_narration.py — the only place the exact
wording of the Risk Narration prompt (Layer 7) lives.

Same pattern as prompts/relationship_inference.py and
prompts/evidence_interpretation.py: a pure function of typed inputs,
no LLM call, no storage access -- testable in isolation
(tests/test_risk_narration_prompt.py) and versionable independent of
the call plumbing in narration/risk_llm.py.
"""

from __future__ import annotations

import json

from ..models import Edge, Node

# Kept in sync with the "Risk Narration — expected output schema"
# block in ATTACKMAPPER_MASTER.md section 7.
_SCHEMA_EXAMPLE = {
    "summary": "One paragraph, plain English, no markdown.",
    "weakest_link": "app --RUNS_AS--> service_account",
    "remediations": [
        {
            "priority": 1,
            "suggestion": (
                "Scope the app's DB role to read-only access on the "
                "customers table."
            ),
        }
    ],
}


def _label_for(node_id: str, nodes_by_id: dict[str, Node]) -> str:
    node = nodes_by_id.get(node_id)
    if node is None or not node.label:
        return node_id
    return f"{node_id} ({node.label})"


def build_risk_narration_prompt(
    path: list[Edge], nodes: list[Node] | None = None
) -> str:
    """Build the Layer 7 (Risk Narration & Remediation) prompt.

    `path` is one `list[Edge]` as returned by
    AttackGraph.find_all_paths -- an ordered chain of hops from an
    entry point to a target, already computed by the deterministic
    Path Finder. This layer never re-derives or second-guesses that
    path; it only explains the one it's given. `nodes` (optional) is
    the node list from the same graph, included purely so hop labels
    (e.g. "web01 (10.0.1.10)") can be shown instead of bare ids -- the
    same "only structured data needed" rule as the other prompts, not
    a raw database dump.

    Each hop is shown with its relationship type, evidence string, and
    confirmed/confidence/proposed_by status, since the master spec's
    example output ("weakest_link": "app --RUNS_AS--> service_account")
    implies the model is meant to point at a specific hop by name --
    it needs to see which hops are unconfirmed/low-confidence to do
    that meaningfully.
    """
    nodes_by_id = {n.id: n for n in (nodes or [])}

    hop_lines = []
    for i, edge in enumerate(path, start=1):
        status = (
            "confirmed"
            if edge.confirmed
            else f"UNCONFIRMED (proposed_by={edge.proposed_by})"
        )
        hop_lines.append(
            f"{i}. {_label_for(edge.source, nodes_by_id)} "
            f"--{edge.relationship}--> {_label_for(edge.target, nodes_by_id)} "
            f"[{status}, confidence={edge.confidence:.2f}]\n"
            f"   evidence: {edge.evidence or '(none recorded)'}"
        )
    hops_block = "\n".join(hop_lines) or "(empty path)"

    schema_block = json.dumps(_SCHEMA_EXAMPLE, indent=2)

    return f"""You are the Risk Narration & Remediation layer of a network \
attack-path mapping tool. You are given one specific attack path -- an \
ordered chain of hops -- that a deterministic graph algorithm has \
already found and ranked. Your only job is to explain this path in \
plain English for a human reader, identify its weakest link, and \
suggest fixes. You do not change the path, you do not propose \
different hops or alternative routes, and you never take any action \
yourself -- everything you produce is advisory text shown alongside \
the raw path, never merged back into the graph and never \
auto-applied to any system.

Attack path ({len(path)} hop(s)):
{hops_block}

Respond with ONLY JSON, no preamble, no markdown code fences, matching \
exactly this shape:
{schema_block}

Rules:
- "summary" is one paragraph of plain English, no markdown formatting, \
explaining how an attacker could realistically walk this path and why \
it matters. Do not just restate the hop list mechanically -- explain \
the story.
- "weakest_link" identifies exactly one hop from the path above (by \
its source/relationship/target, in the same "A --REL--> B" shape used \
above) that is the single best place to break this path -- typically \
the least-confirmed, most-easily-fixed, or most-severe hop, not \
necessarily the first or last one.
- "remediations" is a ranked list (priority 1 = do this first) of \
concrete, specific suggestions for a human to act on. Each suggestion \
should be actionable (name a specific control, config change, or \
policy), not generic advice like "improve security."
- If a hop is marked UNCONFIRMED, you may note that verifying it is \
itself a useful next step, but do not treat it as more certain than \
its stated confidence.
"""
