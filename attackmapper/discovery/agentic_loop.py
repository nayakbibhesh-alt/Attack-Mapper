"""attackmapper/discovery/agentic_loop.py — Layer 1 (extended): Phase
G, Continuous/agentic discovery.

Per the master spec:

    "Discovery becomes a loop that decides what to probe next based on
    findings so far, automatically re-triggering evidence
    interpretation and relationship inference as new data arrives.
    Requires the most guardrails: strictly read-only, strictly scoped
    to authorized environments, and ideally a human-in-the-loop
    approval step before any newly inferred high-confidence
    relationship is treated as fact."

This module is deliberately *not* a new kind of actor. It is a loop
that, on every iteration:

1. Asks the LLM (prompts.agentic_discovery.build_next_probe_prompt)
   which of a small, fixed set of already-existing, already-read-only
   Layer 1 probes (discovery.pipeline.ingest_nmap_scan /
   ingest_http_probe / ingest_postgres_roles -- the exact same
   functions `attackmapper scan-nmap` and the Phase B/D demos already
   call by hand) would be most useful to run next, and why.
2. Validates every proposed action against a fixed schema *and* an
   explicit, caller-supplied authorization scope -- never a default,
   never inferred, never widened by anything the model says. A
   proposal naming a target outside scope is logged and discarded,
   not executed. This is the "strictly scoped to authorized
   environments" guardrail, enforced in code, not by asking the model
   nicely.
3. Executes only the surviving, in-scope, schema-valid actions, via
   the exact same pipeline.ingest_* functions Phases B/D already use
   -- this module has no scanning logic, network code, or SQL of its
   own. "Strictly read-only" is inherited structurally from those
   functions (discovery/scanners.py) rather than re-implemented here.
4. Re-triggers Layer 2 (inference.relationship_llm.infer_relationships)
   automatically when new findings came in this iteration, per the
   spec's "automatically re-triggering ... relationship inference as
   new data arrives."
5. Never confirms anything. Every edge Layer 2 proposes is already
   stored with confirmed=False (see models.Edge, storage.py) -- that
   invariant is untouched by this module. What this module adds is
   the human-in-the-loop guardrail the spec asks for: at the end of a
   run, it surfaces (never auto-approves) the unconfirmed relationships
   at or above `review_threshold` as a priority queue for a human to
   look at via `storage.confirm_relationship()` / `attackmapper
   confirm <id>` -- exactly the existing Phase C confirmation
   mechanism, just pointed at.

Same call_llm() isolation pattern as the other four LLM modules in
this project, so schema validation and scope enforcement are unit
tested against fixture responses (tests/test_agentic_loop.py) with
zero live model calls and zero live scans in CI, per the master
spec's testing strategy for Phases C-F extended to Phase G.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

import json

from .. import llm_client, storage
from ..inference import relationship_llm
from ..prompts.agentic_discovery import build_next_probe_prompt
from . import pipeline

logger = logging.getLogger(__name__)

ALLOWED_ACTION_TYPES = {"nmap_scan", "http_probe", "postgres_roles", "stop"}
REQUIRED_FIELDS = {"action_type", "rationale"}

DEFAULT_MODEL = llm_client.DEFAULT_MODEL
DEFAULT_MAX_ITERATIONS = 5
DEFAULT_MAX_ACTIONS_PER_ITERATION = 3
DEFAULT_REVIEW_THRESHOLD = 0.75


class ScopeError(ValueError):
    """Raised when the loop itself is misconfigured with no scope at
    all. Per-action out-of-scope targets are NOT raised as exceptions
    -- they're expected, routine model behavior (the model can't
    perfectly predict scope edge cases), so they're logged and
    skipped, same as any other invalid proposal. This exception is
    reserved for the one case that must never be allowed to proceed
    silently: a caller trying to run discovery with no authorization
    boundary declared at all.
    """


def call_llm(prompt: str, *, model: str = DEFAULT_MODEL, max_tokens: int = 2000) -> str:
    """The only function in this module that talks to a real model.

    Delegates to llm_client.send_prompt (OpenRouter), the single shared
    client used by all five LLM-backed layers -- see attackmapper/
    llm_client.py for the API-key/SDK error-handling contract. Kept as a
    thin per-module wrapper (rather than importing send_prompt directly
    at call sites) so existing unit tests that monkeypatch
    `agentic_loop.call_llm` keep working unchanged.
    """
    return llm_client.send_prompt(prompt, model=model, max_tokens=max_tokens)


def parse_next_probe_response(raw_text: str) -> list[dict]:
    """Parse and validate the LLM's response against the Phase G
    next-probe schema from prompts/agentic_discovery.py:

        {"actions": [
            {"action_type", "rationale", "target"?, "ports"?, "url"?,
             "dsn"?}, ...
        ]}

    Same "keep whichever items are individually valid" style as
    Layers 1-2's parsers (these are independent proposals, not one
    all-or-nothing decision like Layer 7/8): malformed JSON, a missing
    top-level key, or any single item missing a required field or
    naming an unrecognized action_type is logged and dropped, never
    guessed at. A "stop" item never requires "target"; every other
    action_type does.

    This function does NOT check scope or host inventory -- that
    happens in run_discovery_loop/_execute_action, which have access
    to the caller-supplied scope and current storage state that a pure
    parsing function shouldn't need to depend on.
    """
    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        logger.warning("agentic discovery: response was not valid JSON: %s", exc)
        return []

    if not isinstance(parsed, dict) or "actions" not in parsed:
        logger.warning(
            "agentic discovery: response missing top-level 'actions' key"
        )
        return []

    items = parsed["actions"]
    if not isinstance(items, list):
        logger.warning("agentic discovery: 'actions' was not a list")
        return []

    valid: list[dict] = []
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            logger.warning("agentic discovery: item %d is not an object, skipping", i)
            continue

        missing = REQUIRED_FIELDS - item.keys()
        if missing:
            logger.warning(
                "agentic discovery: item %d missing fields %s, skipping", i, missing
            )
            continue

        action_type = item["action_type"]
        if action_type not in ALLOWED_ACTION_TYPES:
            logger.warning(
                "agentic discovery: item %d has unrecognized action_type %r, "
                "skipping",
                i,
                action_type,
            )
            continue

        rationale = item["rationale"]
        if not isinstance(rationale, str) or not rationale.strip():
            logger.warning(
                "agentic discovery: item %d has invalid 'rationale', skipping", i
            )
            continue

        target = item.get("target")
        if action_type != "stop":
            if not isinstance(target, str) or not target.strip():
                logger.warning(
                    "agentic discovery: item %d (action_type=%r) missing a "
                    "valid 'target', skipping",
                    i,
                    action_type,
                )
                continue

        cleaned: dict[str, Any] = {
            "action_type": action_type,
            "rationale": rationale,
            "target": target if action_type != "stop" else None,
        }
        for optional_field in ("ports", "url", "dsn"):
            value = item.get(optional_field)
            if isinstance(value, str) and value.strip():
                cleaned[optional_field] = value
        valid.append(cleaned)

    return valid


def _target_in_scope(target: str, scope: list[str]) -> bool:
    """A target is authorized only if it exactly matches a scope entry
    (hostname or IP, string equality) or falls inside a scope entry
    that parses as a CIDR block. No wildcard, prefix, or substring
    matching -- scope is defined narrowly and explicitly, per the
    master spec's non-negotiable scope-discipline rule (section 2,
    principle 5). Anything ambiguous is treated as NOT in scope.
    """
    for entry in scope:
        if target == entry:
            return True
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        try:
            addr = ipaddress.ip_address(target)
        except ValueError:
            continue
        if addr in network:
            return True
    return False


def _resolve_host_id(target: str) -> str | None:
    """Look up an already-known host by ip or hostname. http_probe and
    postgres_roles findings must attach to a host_id, and this module
    never invents one -- if a proposed target isn't in inventory yet,
    the right next action is an nmap_scan of it, not a probe against a
    host record that doesn't exist.
    """
    for h in storage.list_hosts():
        if h.get("ip") == target or h.get("hostname") == target:
            return h["id"]
    return None


def _execute_action(action: dict) -> dict:
    """Run exactly one already-validated, already-in-scope action via
    the existing Phase B/D pipeline functions, and return the summary
    dict they already return. Raises RuntimeError (never silently
    returns a fabricated summary) if execution isn't possible --
    e.g. a host that isn't in inventory yet for http_probe/
    postgres_roles, or a scanner-level failure bubbling up from
    discovery/scanners.py.
    """
    action_type = action["action_type"]

    if action_type == "nmap_scan":
        return pipeline.ingest_nmap_scan(
            action["target"], ports=action.get("ports", "1-1024")
        )

    if action_type == "http_probe":
        host_id = _resolve_host_id(action["target"])
        if host_id is None:
            raise RuntimeError(
                f"no known host for target {action['target']!r}; an nmap_scan "
                "must discover it before it can be probed"
            )
        url = action.get("url") or f"http://{action['target']}/"
        return pipeline.ingest_http_probe(url, host_id)

    if action_type == "postgres_roles":
        host_id = _resolve_host_id(action["target"])
        if host_id is None:
            raise RuntimeError(
                f"no known host for target {action['target']!r}; an nmap_scan "
                "must discover it before it can be probed"
            )
        dsn = action.get("dsn")
        if not dsn:
            raise RuntimeError(
                "postgres_roles action is missing a 'dsn' to connect with"
            )
        return pipeline.ingest_postgres_roles(dsn, host_id)

    # Should be unreachable: parse_next_probe_response already rejects
    # anything outside ALLOWED_ACTION_TYPES, and "stop" is filtered out
    # by the caller before _execute_action is ever invoked on it.
    raise RuntimeError(f"unsupported action_type {action_type!r}")


def run_discovery_loop(
    scope: list[str],
    *,
    max_iterations: int = DEFAULT_MAX_ITERATIONS,
    max_actions_per_iteration: int = DEFAULT_MAX_ACTIONS_PER_ITERATION,
    review_threshold: float = DEFAULT_REVIEW_THRESHOLD,
    model: str = DEFAULT_MODEL,
) -> dict:
    """Phase G entry point: run the continuous discovery loop.

    `scope` is REQUIRED and must be non-empty -- a list of exact
    hostnames/IPs and/or CIDR blocks this run is authorized to touch.
    There is no default scope and no way to run "everything"; per the
    master spec's non-negotiable scope-discipline principle, this is a
    hard boundary, not a configuration option to relax later. Every
    single action this loop executes, however the model justified it,
    is re-checked against this exact list before it runs.

    On each of up to `max_iterations` iterations, this:
      1. Loads the current hosts/services/findings from storage.
      2. Asks the LLM which up-to-`max_actions_per_iteration` read-only
         probes to run next (or to "stop").
      3. Discards (logged, not executed) any proposal naming a target
         outside `scope`.
      4. Executes the rest via the existing Phase B/D pipeline
         functions.
      5. If anything new was actually ingested this iteration, re-runs
         Layer 2 (relationship inference) over the updated findings,
         per the spec's "automatically re-triggering ... relationship
         inference as new data arrives."
      6. Stops early if the model proposed "stop" (and nothing else),
         if every proposed action was out of scope or failed, or once
         `max_iterations` is reached.

    Never calls storage.confirm_relationship() -- nothing this loop
    discovers is ever auto-confirmed. Instead, once the loop ends, it
    returns every currently-unconfirmed relationship at or above
    `review_threshold` under "pending_review", as the human-in-the-loop
    queue the master spec asks Phase G to provide. A human reviews
    those (e.g. via `attackmapper edges --filter unconfirmed` and
    `attackmapper confirm <id>`) exactly as they would any other
    LLM-proposed edge from Phase C -- this loop just makes sure the
    highest-confidence ones aren't buried in whatever else is
    unconfirmed.

    Returns:
        {
          "scope": list[str],
          "iterations": [
            {
              "iteration": int,
              "proposed_actions": list[dict],   # as parsed, pre-filter
              "actions_taken": [
                {..action.., "executed": bool, "result"?: dict,
                 "reason"?: str}
              ],
              "new_relationships_proposed": int,
              "stopped": bool,
            }, ...
          ],
          "pending_review": list[dict],  # storage.list_relationships() rows
        }
    """
    if not scope:
        raise ScopeError(
            "run_discovery_loop requires an explicit, non-empty authorization "
            "scope -- refusing to run unscoped discovery (see "
            "ATTACKMAPPER_MASTER.md section 2, principle 5: scope discipline "
            "is a hard boundary, not a configuration option to relax later)"
        )

    iterations: list[dict] = []

    for i in range(max_iterations):
        hosts = storage.list_hosts()
        services = storage.list_services()
        findings = storage.list_findings()

        prompt = build_next_probe_prompt(
            hosts, services, findings, scope, max_actions=max_actions_per_iteration
        )
        raw_response = call_llm(prompt, model=model)
        proposed_actions = parse_next_probe_response(raw_response)
        proposed_actions = proposed_actions[:max_actions_per_iteration]

        if not proposed_actions or all(
            a["action_type"] == "stop" for a in proposed_actions
        ):
            iterations.append(
                {
                    "iteration": i + 1,
                    "proposed_actions": proposed_actions,
                    "actions_taken": [],
                    "new_relationships_proposed": 0,
                    "stopped": True,
                }
            )
            break

        actions_taken: list[dict] = []
        for action in proposed_actions:
            if action["action_type"] == "stop":
                continue

            target = action["target"]
            if not _target_in_scope(target, scope):
                logger.warning(
                    "agentic discovery: discarding out-of-scope proposal "
                    "(action_type=%s target=%r); scope=%s",
                    action["action_type"],
                    target,
                    scope,
                )
                actions_taken.append(
                    {**action, "executed": False, "reason": "out_of_scope"}
                )
                continue

            try:
                result = _execute_action(action)
            except RuntimeError as exc:
                logger.warning("agentic discovery: action failed: %s", exc)
                actions_taken.append(
                    {**action, "executed": False, "reason": str(exc)}
                )
                continue

            actions_taken.append({**action, "executed": True, "result": result})

        new_relationships_proposed = 0
        if any(t.get("executed") for t in actions_taken):
            proposed_edges = relationship_llm.infer_relationships()
            new_relationships_proposed = len(proposed_edges)

        iterations.append(
            {
                "iteration": i + 1,
                "proposed_actions": proposed_actions,
                "actions_taken": actions_taken,
                "new_relationships_proposed": new_relationships_proposed,
                "stopped": False,
            }
        )

        if not any(t.get("executed") for t in actions_taken):
            # Nothing in this iteration actually ran (everything was
            # out of scope or failed) -- looping again would just ask
            # the same question against the same unchanged inventory.
            break

    pending_review = [
        r
        for r in storage.list_relationships(confirmed=False)
        if r["confidence"] >= review_threshold
    ]
    pending_review.sort(key=lambda r: r["confidence"], reverse=True)

    return {
        "scope": scope,
        "iterations": iterations,
        "pending_review": pending_review,
    }
