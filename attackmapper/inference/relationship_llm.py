"""attackmapper/inference/relationship_llm.py — Layer 2: Relationship
Inference.

Turns Findings already sitting in storage into candidate Edges. Per
the master spec's non-negotiable rules:

- Every edge this layer produces is stored with confirmed=False and a
  confidence score; this layer NEVER marks its own output confirmed.
  Confirmation only happens via storage.confirm_relationship(), driven
  by deterministic verification or human review.
- Structured LLM output only: the model is asked for JSON matching a
  fixed schema, and that JSON is validated before anything derived
  from it is stored. Malformed items are logged and skipped -- never
  guessed at or partially used.
- The LLM only ever sees a summarized findings/hosts list (built by
  prompts.relationship_inference), never a raw dump of the database.

The actual network call to the model lives in call_llm(), isolated on
purpose: every other function here is a pure function of its inputs,
so schema validation and the store-as-unconfirmed logic can be (and
are, in tests/test_relationship_llm.py) tested by monkeypatching
call_llm with fixture responses -- never against a live model in CI,
per the master spec's testing strategy for Phases C-F.
"""

from __future__ import annotations

import json
import logging

from .. import llm_client, storage
from ..models import Edge
from ..prompts.relationship_inference import build_relationship_inference_prompt

logger = logging.getLogger(__name__)

REQUIRED_FIELDS = {"source", "target", "relationship_type", "evidence", "confidence"}

DEFAULT_MODEL = llm_client.DEFAULT_MODEL


def call_llm(prompt: str, *, model: str = DEFAULT_MODEL, max_tokens: int = 3000) -> str:
    """The only function in this module that talks to a real model.

    Delegates to llm_client.send_prompt (OpenRouter), the single shared
    client used by all five LLM-backed layers -- see attackmapper/
    llm_client.py for the API-key/SDK error-handling contract. Kept as a
    thin per-module wrapper (rather than importing send_prompt directly
    at call sites) so existing unit tests that monkeypatch
    `relationship_llm.call_llm` keep working unchanged.
    """
    return llm_client.send_prompt(prompt, model=model, max_tokens=max_tokens)


def parse_relationship_response(raw_text: str) -> list[dict]:
    """Parse and validate the LLM's response against the Relationship
    Inference schema from ATTACKMAPPER_MASTER.md section 7:

        {"relationships": [
            {"source", "target", "relationship_type", "evidence",
             "confidence"}, ...
        ]}

    Per the 'structured LLM output only' principle this is strict:
    anything that fails to parse, or any single item missing a
    required field or carrying an out-of-range confidence, is logged
    and dropped. It never raises on bad model output and it never
    guesses at a missing field -- the caller gets back exactly the
    subset of items that are safe to treat as data.
    """
    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        logger.warning("relationship inference: response was not valid JSON: %s", exc)
        return []

    if not isinstance(parsed, dict) or "relationships" not in parsed:
        logger.warning(
            "relationship inference: response missing top-level "
            "'relationships' key"
        )
        return []

    items = parsed["relationships"]
    if not isinstance(items, list):
        logger.warning("relationship inference: 'relationships' was not a list")
        return []

    valid: list[dict] = []
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            logger.warning(
                "relationship inference: item %d is not an object, skipping", i
            )
            continue

        missing = REQUIRED_FIELDS - item.keys()
        if missing:
            logger.warning(
                "relationship inference: item %d missing fields %s, skipping",
                i,
                missing,
            )
            continue

        if not isinstance(item["source"], str) or not item["source"]:
            logger.warning(
                "relationship inference: item %d has invalid 'source', skipping", i
            )
            continue
        if not isinstance(item["target"], str) or not item["target"]:
            logger.warning(
                "relationship inference: item %d has invalid 'target', skipping", i
            )
            continue
        if not isinstance(item["relationship_type"], str) or not item["relationship_type"]:
            logger.warning(
                "relationship inference: item %d has invalid 'relationship_type', "
                "skipping",
                i,
            )
            continue

        confidence = item["confidence"]
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            logger.warning(
                "relationship inference: item %d has non-numeric confidence %r, "
                "skipping",
                i,
                confidence,
            )
            continue
        confidence = float(confidence)
        if not 0.0 <= confidence <= 1.0:
            logger.warning(
                "relationship inference: item %d has out-of-range confidence %r, "
                "skipping",
                i,
                confidence,
            )
            continue

        valid.append(
            {
                "source": item["source"],
                "target": item["target"],
                "relationship_type": item["relationship_type"],
                "evidence": str(item.get("evidence", "")),
                "confidence": confidence,
            }
        )
    return valid


def infer_relationships(findings: list[dict] | None = None) -> list[Edge]:
    """Layer 2 entry point.

    Pulls all findings from storage (unless a specific subset is
    passed in -- useful for a targeted re-run or a test), prompts the
    LLM to propose exploitable relationships, validates the response,
    and stores every schema-valid proposal as an unconfirmed Edge.

    Per the master spec: "Store every proposed edge -- do not silently
    drop low-confidence ones; let the confidence field do the
    filtering downstream." Only items that fail schema validation are
    dropped here; a low-but-valid-shaped confidence score is still
    stored and left for load_graph(min_confidence=...) or a human to
    filter.

    Also pulls the raw open-services inventory (storage.list_services())
    so the LLM has something to reason over even when a real scanned
    host has no Findings at all -- see the "services" parameter note in
    prompts/relationship_inference.py for why that matters for anything
    that isn't the lab's deliberately-vulnerable demo topology. The
    "skip the LLM call" short-circuit below only fires when there is
    truly nothing to reason over (no findings AND no services); a
    caller-supplied `findings` subset still skips based on findings
    alone, since a targeted re-run over a specific findings slice
    shouldn't silently widen its own scope to every service in
    inventory.

    Returns the Edge objects that were stored (each already
    confirmed=False, proposed_by="llm").
    """
    explicit_findings = findings is not None
    if findings is None:
        findings = storage.list_findings()

    services = [] if explicit_findings else storage.list_services()
    if not findings and not services:
        logger.info(
            "relationship inference: no findings or services to reason "
            "over, skipping LLM call"
        )
        return []

    hosts = storage.list_hosts()
    prompt = build_relationship_inference_prompt(findings, hosts, services)
    raw_response = call_llm(prompt)
    proposals = parse_relationship_response(raw_response)

    stored_edges: list[Edge] = []
    for p in proposals:
        edge = Edge(
            source=p["source"],
            target=p["target"],
            relationship=p["relationship_type"],
            evidence=p["evidence"],
            confirmed=False,
            confidence=p["confidence"],
            proposed_by="llm",
        )
        storage.save_relationship(edge)
        stored_edges.append(edge)
    return stored_edges


def compare_proposed_to_confirmed(
    proposed: list[Edge] | None = None,
) -> dict[str, list[Edge]]:
    """A sanity-check report, not a gate.

    Per the master spec's Phase C note: "Compare LLM-proposed edges
    against the hand-verified ones from Phase B as a sanity check on
    quality before trusting the LLM on data you haven't manually
    verified." This buckets each LLM-proposed edge against the
    confirmed relationships already in storage:

    - "agrees": a confirmed edge exists for the same (source, target)
      with the same relationship type.
    - "contradicts": a confirmed edge exists for the same (source,
      target) but with a *different* relationship type -- worth a
      human's attention.
    - "novel": no confirmed edge exists for that (source, target) at
      all -- neither validated nor contradicted, just new.

    Never auto-confirms or auto-rejects anything; it only tells a
    human where to look.
    """
    if proposed is None:
        proposed = [
            Edge(
                source=r["source"],
                target=r["target"],
                relationship=r["relationship"],
                evidence=r["evidence"],
                confirmed=r["confirmed"],
                confidence=r["confidence"],
                proposed_by=r["proposed_by"],
            )
            for r in storage.list_relationships(confirmed=False)
            if r["proposed_by"] == "llm"
        ]

    confirmed_by_pair: dict[tuple[str, str], str] = {
        (r["source"], r["target"]): r["relationship"]
        for r in storage.list_relationships(confirmed=True)
    }

    agrees: list[Edge] = []
    contradicts: list[Edge] = []
    novel: list[Edge] = []
    for edge in proposed:
        confirmed_type = confirmed_by_pair.get((edge.source, edge.target))
        if confirmed_type is None:
            novel.append(edge)
        elif confirmed_type == edge.relationship:
            agrees.append(edge)
        else:
            contradicts.append(edge)

    return {"agrees": agrees, "contradicts": contradicts, "novel": novel}
