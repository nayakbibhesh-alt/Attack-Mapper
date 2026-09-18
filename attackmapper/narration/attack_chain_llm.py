"""attackmapper/narration/attack_chain_llm.py — Attack Chain Reasoning.

This is what makes "AttackMapper" actually map attacks rather than
just list vulnerabilities: it takes the findings one scan just
produced and asks the LLM which of them combine into a realistic
attack chain, the same way a human pentester would look at five
individually-modest findings and go "wait, these three together are
how I'd actually break in."

Per the same non-negotiable rules every other LLM-backed layer in this
codebase follows:

- Structured LLM output only: the model is asked for JSON matching a
  fixed schema, and every item is validated before use. A chain that
  fails validation is dropped and logged -- never guessed at or
  partially used, matching inference/relationship_llm.py's "keep the
  valid subset" pattern (each chain is an independent proposal, unlike
  risk_llm's one-object-per-path, all-or-nothing shape).
- Advisory only: this module never writes to storage.py. Chains are
  returned to the caller (discovery.pipeline.scan_target_url, or the
  /api/chain-findings endpoint) as plain data for the UI/CLI to show
  alongside the findings list -- nothing here is merged into the graph
  or auto-applied to anything.
- Same call_llm() isolation pattern as every other *_llm.py module, so
  schema validation is unit-tested against fixture responses
  (tests/test_attack_chain_llm.py) with zero live model calls in CI.

Deliberately independent of inference/relationship_llm.py and
narration/risk_llm.py (see prompts/attack_chain.py's module docstring
for exactly how): this layer needs only the findings from ONE scan of
ONE target, not a multi-host graph, which is what makes it possible to
run automatically on every scan rather than as a separate manual step.
"""

from __future__ import annotations

import json
import logging

from .. import llm_client, storage
from ..prompts.attack_chain import KNOWN_SEVERITIES, build_attack_chain_prompt

logger = logging.getLogger(__name__)

REQUIRED_CHAIN_FIELDS = {"title", "severity", "steps"}
REQUIRED_STEP_FIELDS = {"step", "action"}

DEFAULT_MODEL = llm_client.DEFAULT_MODEL


def call_llm(prompt: str, *, model: str = DEFAULT_MODEL, max_tokens: int = 3000) -> str:
    """The only function in this module that talks to a real model.

    Delegates to llm_client.send_prompt (OpenRouter), the single shared
    client used by every LLM-backed layer -- see attackmapper/
    llm_client.py for the API-key/SDK error-handling contract. Kept as a
    thin per-module wrapper (rather than importing send_prompt directly
    at call sites) so unit tests can monkeypatch
    `attack_chain_llm.call_llm` with fixture responses.
    """
    return llm_client.send_prompt(prompt, model=model, max_tokens=max_tokens)


def _validate_step(step, index: int, chain_index: int) -> dict | None:
    if not isinstance(step, dict):
        logger.warning(
            "attack chain: chain %d step %d is not an object, dropping chain",
            chain_index, index,
        )
        return None
    missing = REQUIRED_STEP_FIELDS - step.keys()
    if missing:
        logger.warning(
            "attack chain: chain %d step %d missing fields %s, dropping chain",
            chain_index, index, missing,
        )
        return None
    step_no = step["step"]
    if isinstance(step_no, bool) or not isinstance(step_no, int):
        logger.warning(
            "attack chain: chain %d step %d has non-integer 'step' %r, dropping chain",
            chain_index, index, step_no,
        )
        return None
    action = step["action"]
    if not isinstance(action, str) or not action.strip():
        logger.warning(
            "attack chain: chain %d step %d has invalid 'action', dropping chain",
            chain_index, index,
        )
        return None
    based_on = step.get("based_on")
    if based_on is not None and not isinstance(based_on, str):
        logger.warning(
            "attack chain: chain %d step %d has non-string 'based_on', dropping chain",
            chain_index, index,
        )
        return None
    return {"step": step_no, "action": action, "based_on": based_on}


def _validate_chain(item, index: int) -> dict | None:
    if not isinstance(item, dict):
        logger.warning("attack chain: chain %d is not an object, dropping", index)
        return None

    missing = REQUIRED_CHAIN_FIELDS - item.keys()
    if missing:
        logger.warning("attack chain: chain %d missing fields %s, dropping", index, missing)
        return None

    title = item["title"]
    if not isinstance(title, str) or not title.strip():
        logger.warning("attack chain: chain %d has invalid 'title', dropping", index)
        return None

    severity = item["severity"]
    if severity not in KNOWN_SEVERITIES:
        logger.warning(
            "attack chain: chain %d has unrecognized severity %r, dropping", index, severity
        )
        return None

    steps_raw = item["steps"]
    if not isinstance(steps_raw, list) or not steps_raw:
        logger.warning("attack chain: chain %d has no valid 'steps' list, dropping", index)
        return None

    steps: list[dict] = []
    for i, s in enumerate(steps_raw):
        validated = _validate_step(s, i, index)
        if validated is None:
            return None  # one bad step -> the whole chain is untrustworthy
        steps.append(validated)
    steps.sort(key=lambda s: s["step"])

    finding_ids = item.get("finding_ids", [])
    if not isinstance(finding_ids, list) or not all(isinstance(f, str) for f in finding_ids):
        finding_ids = []

    impact = item.get("impact")
    if not isinstance(impact, str):
        impact = None

    remediation = item.get("remediation")
    if not isinstance(remediation, str):
        remediation = None

    return {
        "title": title,
        "severity": severity,
        "finding_ids": finding_ids,
        "steps": steps,
        "impact": impact,
        "remediation": remediation,
    }


def parse_attack_chain_response(raw_text: str) -> list[dict]:
    """Parse and validate the LLM's response against the Attack Chain
    Reasoning schema from prompts/attack_chain.py.

    Per the 'structured LLM output only' principle: anything that
    fails to parse, or any single chain missing a required field or
    carrying an invalid severity/step, is logged and dropped. A
    top-level parse failure or an empty/absent "chains" list both
    yield [] -- there is no meaningful difference, from the caller's
    point of view, between "the model found nothing worth chaining"
    and "the model's response couldn't be trusted"; either way, no
    chains are shown."""
    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        logger.warning("attack chain: response was not valid JSON: %s", exc)
        return []

    if not isinstance(parsed, dict) or "chains" not in parsed:
        logger.warning("attack chain: response missing top-level 'chains' key")
        return []

    items = parsed["chains"]
    if not isinstance(items, list):
        logger.warning("attack chain: 'chains' was not a list")
        return []

    valid: list[dict] = []
    for i, item in enumerate(items):
        chain = _validate_chain(item, i)
        if chain is not None:
            valid.append(chain)

    severity_rank = {s: i for i, s in enumerate(KNOWN_SEVERITIES)}
    valid.sort(key=lambda c: severity_rank.get(c["severity"], len(KNOWN_SEVERITIES)))
    return valid


def find_attack_chains(
    findings: list[dict] | None = None,
    hosts: list[dict] | None = None,
    services: list[dict] | None = None,
) -> list[dict]:
    """Entry point.

    Pulls findings from storage (unless a specific subset is passed in
    -- what discovery.pipeline.scan_target_url does, scoping this to
    just the host it just scanned) plus hosts/services for context,
    prompts the LLM to identify attack chains among them, and returns
    the validated list. Returns [] immediately, with no LLM call, when
    there are fewer than two findings to reason over -- a single
    finding can never be a "chain" of findings combining into
    something worse, so there's nothing for this layer to add.

    Has no storage.py write path at all, matching risk_llm.narrate_path's
    framing of this kind of layer as producing advisory data alongside
    the raw findings, never merged into the graph or auto-applied.
    """
    explicit = findings is not None
    if findings is None:
        findings = storage.list_findings()
    if len(findings) < 2:
        logger.info(
            "attack chain: fewer than 2 findings to reason over, skipping LLM call"
        )
        return []

    if hosts is None and not explicit:
        hosts = storage.list_hosts()
    if services is None and not explicit:
        services = storage.list_services()

    prompt = build_attack_chain_prompt(findings, hosts, services)
    raw_response = call_llm(prompt)
    return parse_attack_chain_response(raw_response)
