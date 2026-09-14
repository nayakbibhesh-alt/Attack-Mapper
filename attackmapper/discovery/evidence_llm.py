"""attackmapper/discovery/evidence_llm.py — Layer 1: Evidence
Interpretation (the LLM half).

Phase D. This is additive: discovery/parsers.py's rigid parsers keep
handling everything they already handle deterministically (known
vulnerable banners, missing security headers, overprivileged Postgres
roles, ...). This module only covers the gap -- evidence a rigid
parser was handed and could not confidently classify: an unfamiliar
service banner, a config snippet, an HTTP response shape parsers.py
doesn't have a rule for.

Per the master spec's non-negotiable rules:
- The LLM here classifies and structures evidence it is *given* -- it
  does not decide what to scan or take any action.
- Structured LLM output only: the model is asked for JSON matching a
  fixed schema, and that JSON is validated before anything derived
  from it is stored. Malformed items are logged and skipped -- never
  guessed at or partially used.
- Every finding this layer produces is stored with
  source="llm_inferred" and the model's own confidence score --
  never silently treated as source="scanner" ground truth. Unlike
  Layer 2's Edge.confirmed flag, findings have no confirmed/proposed
  split in the data model (see models.Finding / the master spec's
  `findings` table) -- `source` is what distinguishes "a human/rigid
  parser is certain" from "an LLM classified this," and downstream
  consumers (Layer 2's relationship inference, a human reviewer) can
  filter or weight on that basis exactly as they already do on
  `confidence`.

The actual network call lives in call_llm(), isolated on purpose --
same pattern as inference/relationship_llm.py -- so schema validation
and the store-as-llm_inferred logic can be (and are, in
tests/test_evidence_llm.py) tested by monkeypatching call_llm with
fixture responses, never against a live model in CI.
"""

from __future__ import annotations

import json
import logging

from .. import llm_client, storage
from ..models import Finding
from ..prompts.evidence_interpretation import build_evidence_interpretation_prompt

logger = logging.getLogger(__name__)

REQUIRED_FIELDS = {"type", "severity", "description", "evidence", "confidence"}
VALID_SEVERITIES = {"low", "medium", "high", "critical"}

DEFAULT_MODEL = llm_client.DEFAULT_MODEL


def call_llm(prompt: str, *, model: str = DEFAULT_MODEL, max_tokens: int = 2000) -> str:
    """The only function in this module that talks to a real model.

    Delegates to llm_client.send_prompt (OpenRouter), the single shared
    client used by all five LLM-backed layers -- see attackmapper/
    llm_client.py for the API-key/SDK error-handling contract. Kept as a
    thin per-module wrapper (rather than importing send_prompt directly
    at call sites) so existing unit tests that monkeypatch
    `evidence_llm.call_llm` keep working unchanged.
    """
    return llm_client.send_prompt(prompt, model=model, max_tokens=max_tokens)


def parse_evidence_response(raw_text: str) -> list[dict]:
    """Parse and validate the LLM's response against the Evidence
    Interpretation schema from ATTACKMAPPER_MASTER.md section 7:

        {"findings": [
            {"type", "severity", "description", "evidence",
             "confidence"}, ...
        ]}

    Per the 'structured LLM output only' principle this is strict:
    anything that fails to parse, or any single item missing a
    required field, carrying an invalid severity, or an out-of-range
    confidence, is logged and dropped. It never raises on bad model
    output and never guesses at a missing field -- the caller gets
    back exactly the subset of items that are safe to treat as data.
    """
    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        logger.warning("evidence interpretation: response was not valid JSON: %s", exc)
        return []

    if not isinstance(parsed, dict) or "findings" not in parsed:
        logger.warning(
            "evidence interpretation: response missing top-level 'findings' key"
        )
        return []

    items = parsed["findings"]
    if not isinstance(items, list):
        logger.warning("evidence interpretation: 'findings' was not a list")
        return []

    valid: list[dict] = []
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            logger.warning(
                "evidence interpretation: item %d is not an object, skipping", i
            )
            continue

        missing = REQUIRED_FIELDS - item.keys()
        if missing:
            logger.warning(
                "evidence interpretation: item %d missing fields %s, skipping",
                i,
                missing,
            )
            continue

        if not isinstance(item["type"], str) or not item["type"]:
            logger.warning(
                "evidence interpretation: item %d has invalid 'type', skipping", i
            )
            continue

        severity = item["severity"]
        if severity not in VALID_SEVERITIES:
            logger.warning(
                "evidence interpretation: item %d has invalid severity %r, "
                "skipping",
                i,
                severity,
            )
            continue

        if not isinstance(item["description"], str) or not item["description"]:
            logger.warning(
                "evidence interpretation: item %d has invalid 'description', "
                "skipping",
                i,
            )
            continue

        confidence = item["confidence"]
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            logger.warning(
                "evidence interpretation: item %d has non-numeric confidence "
                "%r, skipping",
                i,
                confidence,
            )
            continue
        confidence = float(confidence)
        if not 0.0 <= confidence <= 1.0:
            logger.warning(
                "evidence interpretation: item %d has out-of-range confidence "
                "%r, skipping",
                i,
                confidence,
            )
            continue

        valid.append(
            {
                "type": item["type"],
                "severity": severity,
                "description": item["description"],
                "evidence": str(item.get("evidence", "")),
                "confidence": confidence,
            }
        )
    return valid


def interpret_evidence(
    host_id: str,
    evidence_type: str,
    raw_evidence: str,
    *,
    host: dict | None = None,
) -> list[Finding]:
    """Layer 1 (LLM half) entry point.

    Sends one piece of ambiguous raw evidence -- already judged by the
    caller (typically discovery/pipeline.py) to be outside what
    discovery/parsers.py's rigid parsers handle -- to the LLM, and
    stores every schema-valid finding it proposes, tagged
    source="llm_inferred" with the model's own confidence.

    `host_id` is required (unlike the nmap rigid-parser path, which
    resolves ip -> host_id at the pipeline layer) because this
    function's caller always already knows which host the evidence
    came from -- there is no ambiguity to resolve here, only ambiguity
    in what the evidence *means*. `host` is an optional dict (a
    storage.list_hosts() record) passed through to the prompt purely
    as context.

    Returns the Finding objects that were stored (empty list if the
    LLM found nothing, or if every proposed item failed schema
    validation).
    """
    if not raw_evidence or not raw_evidence.strip():
        logger.info(
            "evidence interpretation: empty evidence for host %s, skipping "
            "LLM call",
            host_id,
        )
        return []

    prompt = build_evidence_interpretation_prompt(evidence_type, raw_evidence, host)
    raw_response = call_llm(prompt)
    proposals = parse_evidence_response(raw_response)

    stored: list[Finding] = []
    for p in proposals:
        finding = Finding(
            host_id=host_id,
            type=p["type"],
            severity=p["severity"],
            description=p["description"],
            evidence=p["evidence"],
            source="llm_inferred",
            confidence=p["confidence"],
        )
        storage.save_finding(
            {
                "host_id": finding.host_id,
                "type": finding.type,
                "severity": finding.severity,
                "description": finding.description,
                "evidence": finding.evidence,
                "source": finding.source,
                "confidence": finding.confidence,
            }
        )
        stored.append(finding)
    return stored
