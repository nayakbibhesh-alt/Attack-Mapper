"""attackmapper/narration/risk_llm.py — Layer 7: Risk Narration &
Remediation.

Phase E. Takes a `list[Edge]` path already produced by the Path
Finder (Layer 5, deterministic) and produces a plain-English risk
narrative plus ranked remediation suggestions. Per the master spec's
non-negotiable rules:

- This layer never changes the path, never proposes alternative hops,
  and never calls the path finder itself -- it only explains what it's
  handed. Layers 4-6 remain the only place path-finding logic lives.
- Structured LLM output only: the model is asked for JSON matching a
  fixed schema, validated before use. Malformed output is logged and
  the caller gets None back -- never a partially-filled-in guess.
- Output is always advisory text alongside the raw path -- this module
  has no write path into storage.py at all (unlike Layers 1-2, which
  write Findings/Edges). Nothing here is ever "merged into the graph
  data itself" or "auto-applied to the environment," per the spec.

Same call_llm() isolation pattern as inference/relationship_llm.py and
discovery/evidence_llm.py, so schema validation is unit-tested against
fixture responses (tests/test_risk_llm.py) with zero live model calls
in CI.
"""

from __future__ import annotations

import json
import logging

from .. import llm_client
from ..models import Edge, Node
from ..prompts.risk_narration import build_risk_narration_prompt

logger = logging.getLogger(__name__)

REQUIRED_TOP_LEVEL_FIELDS = {"summary", "weakest_link", "remediations"}
REQUIRED_REMEDIATION_FIELDS = {"priority", "suggestion"}

DEFAULT_MODEL = llm_client.DEFAULT_MODEL


def call_llm(prompt: str, *, model: str = DEFAULT_MODEL, max_tokens: int = 2000) -> str:
    """The only function in this module that talks to a real model.

    Delegates to llm_client.send_prompt (OpenRouter), the single shared
    client used by all five LLM-backed layers -- see attackmapper/
    llm_client.py for the API-key/SDK error-handling contract. Kept as a
    thin per-module wrapper (rather than importing send_prompt directly
    at call sites) so existing unit tests that monkeypatch
    `risk_llm.call_llm` keep working unchanged.
    """
    return llm_client.send_prompt(prompt, model=model, max_tokens=max_tokens)


def parse_narration_response(raw_text: str) -> dict | None:
    """Parse and validate the LLM's response against the Risk
    Narration schema from ATTACKMAPPER_MASTER.md section 7:

        {"summary": str, "weakest_link": str,
         "remediations": [{"priority": int, "suggestion": str}, ...]}

    Unlike Layers 1-2 (which validate a *list* of independent
    proposals and keep whichever ones are individually valid), Risk
    Narration produces one object describing one path -- there's no
    sensible way to keep "half" a narrative. So this returns either
    the fully-validated dict or None; never a partial result. A
    single malformed remediation item is enough to reject the whole
    response, since a caller can't trust "priority 1" ordering with an
    item missing from the middle.
    """
    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        logger.warning("risk narration: response was not valid JSON: %s", exc)
        return None

    if not isinstance(parsed, dict):
        logger.warning("risk narration: response was not a JSON object")
        return None

    missing = REQUIRED_TOP_LEVEL_FIELDS - parsed.keys()
    if missing:
        logger.warning("risk narration: response missing fields %s", missing)
        return None

    summary = parsed["summary"]
    if not isinstance(summary, str) or not summary.strip():
        logger.warning("risk narration: 'summary' is not a non-empty string")
        return None

    weakest_link = parsed["weakest_link"]
    if not isinstance(weakest_link, str) or not weakest_link.strip():
        logger.warning("risk narration: 'weakest_link' is not a non-empty string")
        return None

    remediations = parsed["remediations"]
    if not isinstance(remediations, list) or not remediations:
        logger.warning(
            "risk narration: 'remediations' is not a non-empty list"
        )
        return None

    valid_remediations: list[dict] = []
    for i, item in enumerate(remediations):
        if not isinstance(item, dict):
            logger.warning(
                "risk narration: remediation %d is not an object, rejecting "
                "whole response",
                i,
            )
            return None
        item_missing = REQUIRED_REMEDIATION_FIELDS - item.keys()
        if item_missing:
            logger.warning(
                "risk narration: remediation %d missing fields %s, rejecting "
                "whole response",
                i,
                item_missing,
            )
            return None
        priority = item["priority"]
        if isinstance(priority, bool) or not isinstance(priority, int):
            logger.warning(
                "risk narration: remediation %d has non-integer priority %r, "
                "rejecting whole response",
                i,
                priority,
            )
            return None
        suggestion = item["suggestion"]
        if not isinstance(suggestion, str) or not suggestion.strip():
            logger.warning(
                "risk narration: remediation %d has invalid 'suggestion', "
                "rejecting whole response",
                i,
            )
            return None
        valid_remediations.append({"priority": priority, "suggestion": suggestion})

    valid_remediations.sort(key=lambda r: r["priority"])

    return {
        "summary": summary,
        "weakest_link": weakest_link,
        "remediations": valid_remediations,
    }


def narrate_path(path: list[Edge], nodes: list[Node] | None = None) -> dict | None:
    """Layer 7 entry point.

    Given one path from AttackGraph.find_all_paths (typically the
    top-ranked one by AttackGraph.path_confidence), produce the
    narrative + remediation dict described above, or None if the path
    is empty, the LLM call fails to produce parseable output, or every
    item fails schema validation.

    This function has no storage.py dependency at all -- it takes a
    path and (optionally) a node list as plain arguments and returns a
    plain dict, matching the master spec's framing of this layer as
    producing "advisory text ... never merged into the graph data
    itself." The caller (typically cli.py) decides how to present it.
    """
    if not path:
        logger.info("risk narration: empty path, skipping LLM call")
        return None

    prompt = build_risk_narration_prompt(path, nodes)
    raw_response = call_llm(prompt)
    return parse_narration_response(raw_response)
