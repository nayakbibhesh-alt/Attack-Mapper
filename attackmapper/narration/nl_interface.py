"""attackmapper/narration/nl_interface.py — Layer 8: Natural Language
Interface.

Phase F, the last layer in the build plan and "the primary user-facing
surface of the finished product." Per the master spec, this is a thin
translation layer:

    "translate a user's English question into a call against Layers
    5/6 (e.g. find_all_paths(start=?, target=?)), then hand the raw
    result to Layer 7's narration logic (or a similar prompt) to
    phrase the answer back in English. This is a thin translation
    layer -- it should not itself contain graph logic; it calls the
    existing deterministic functions and formats their output."

Concretely, `ask()` below does exactly that and nothing else:

1. Intent parsing (one LLM call, via prompts/nl_query.py): the user's
   English question -> {"intent": "find_path", "start": ..., "target":
   ...}, {"intent": "list_findings", "target": ...}, or {"intent":
   "unknown", ...}. Structured LLM output only, validated before use,
   same as every other LLM integration point in this system.
2. If the intent isn't a resolvable request, `ask()` returns a
   clarifying answer immediately -- no graph/storage call beyond the
   one existence check, no second LLM call. This is not graph logic;
   it's just declining to call `find_all_paths` (or filter findings)
   with nodes the model wasn't sure about.
3. For "find_path", `ask()` calls the *actual* Layers 4/5/6 functions
   (`storage.load_graph`, `AttackGraph.find_all_paths`,
   `AttackGraph.path_confidence`) exactly as `cli.cmd_analyze` does --
   no reimplementation of path-finding, ranking, or graph traversal
   here. This module has no adjacency logic of its own. The top-ranked
   path is then handed to Layer 7's existing `risk_llm.narrate_path()`
   (the "or a similar prompt" the spec allows for, but reusing Layer 7
   directly is simpler and keeps the English-phrasing logic in exactly
   one place) to produce the final plain-English answer. If Layer 7
   fails to produce a usable narrative, `ask()` falls back to the
   graph's own deterministic `describe_path()` rather than inventing
   prose of its own.
4. For "list_findings" -- the general-Q&A extension described in
   prompts/nl_query.py -- `ask()` calls `storage.list_findings()`
   (optionally filtered to one host) exactly as the webapp's
   `/api/findings` route does, sorts by severity, and formats a plain-
   English summary with `remediation.remedy_for()` attached to each
   line. No LLM call here: the intent-parsing call already used the
   model to figure out *what* the question wants; turning a list of
   findings into readable English is plain string formatting, not a
   second inference the way narrating a graph path is, so there's
   nothing for a second call to buy beyond latency and another failure
   mode. This mirrors risk_llm/describe_path's own fallback: prefer a
   deterministic formatter over an LLM call when one will do.

Same call_llm() isolation pattern as the other three LLM modules, so
intent-parsing schema validation is unit-tested against fixture
responses (tests/test_nl_interface.py) with zero live model calls in
CI, and the "calls existing deterministic functions" claim above is
checked by monkeypatching call_llm and risk_llm.narrate_path rather
than mocking out find_all_paths itself.
"""

from __future__ import annotations

import json
import logging

from .. import llm_client, remediation, storage
from ..graph import AttackGraph
from ..models import Node
from ..prompts.nl_query import build_nl_query_prompt
from . import risk_llm

logger = logging.getLogger(__name__)

VALID_INTENTS = {"find_path", "list_findings", "unknown"}

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}

DEFAULT_MODEL = llm_client.DEFAULT_MODEL


def call_llm(prompt: str, *, model: str = DEFAULT_MODEL, max_tokens: int = 800) -> str:
    """The only function in this module that talks to a real model for
    intent parsing. (Answer phrasing delegates to
    narration.risk_llm.narrate_path, which has its own call_llm.)

    Delegates to llm_client.send_prompt (OpenRouter), the single shared
    client used by all five LLM-backed layers -- see attackmapper/
    llm_client.py for the API-key/SDK error-handling contract. Kept as a
    thin per-module wrapper (rather than importing send_prompt directly
    at call sites) so existing unit tests that monkeypatch
    `nl_interface.call_llm` keep working unchanged.
    """
    return llm_client.send_prompt(prompt, model=model, max_tokens=max_tokens)


def parse_intent_response(raw_text: str) -> dict | None:
    """Parse and validate the LLM's response against the Layer 8
    intent-parsing schema from ATTACKMAPPER_MASTER.md section 7, plus
    the "unknown" extension documented in prompts/nl_query.py:

        {"intent": "find_path", "start": str, "target": str}
        {"intent": "unknown", "start": None, "target": None,
         "clarification": str}

    Like Layer 7's parse_narration_response (and unlike Layers 1-2),
    this describes one decision about one question, not a list of
    independent proposals -- so any structural problem rejects the
    whole response as None rather than guessing at a partial intent.
    """
    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        logger.warning("nl interface: response was not valid JSON: %s", exc)
        return None

    if not isinstance(parsed, dict):
        logger.warning("nl interface: response was not a JSON object")
        return None

    intent = parsed.get("intent")
    if intent not in VALID_INTENTS:
        logger.warning("nl interface: unrecognized intent %r", intent)
        return None

    if intent == "find_path":
        start = parsed.get("start")
        target = parsed.get("target")
        if not isinstance(start, str) or not start.strip():
            logger.warning("nl interface: find_path response has invalid 'start'")
            return None
        if not isinstance(target, str) or not target.strip():
            logger.warning("nl interface: find_path response has invalid 'target'")
            return None
        return {"intent": "find_path", "start": start, "target": target}

    if intent == "list_findings":
        target = parsed.get("target")
        if target is not None and (not isinstance(target, str) or not target.strip()):
            logger.warning(
                "nl interface: list_findings response has invalid 'target'"
            )
            return None
        return {"intent": "list_findings", "start": None, "target": target}

    # intent == "unknown"
    clarification = parsed.get("clarification", "")
    if not isinstance(clarification, str):
        logger.warning("nl interface: 'clarification' is not a string")
        return None
    return {
        "intent": "unknown",
        "start": None,
        "target": None,
        "clarification": clarification.strip(),
    }


def _answer_for_unresolved(question: str, clarification: str) -> dict:
    message = clarification or (
        "I couldn't map that question onto a specific start and target "
        "in the current environment."
    )
    return {
        "question": question,
        "intent": "unknown",
        "start": None,
        "target": None,
        "answered": False,
        "answer": message,
        "paths_found": 0,
        "top_path": None,
        "narration": None,
    }


def _answer_list_findings(question: str, target: str | None) -> dict:
    """Handle a "list_findings" intent: format the current finding
    inventory (optionally scoped to one host) as plain English. See
    the module docstring for why this is a deterministic formatter
    rather than a second LLM call."""
    findings = storage.list_findings()
    if target is not None:
        findings = [f for f in findings if f.get("host_id") == target]
    ranked = sorted(findings, key=lambda f: _SEVERITY_RANK.get(f.get("severity"), 4))

    scope = f"on {target}" if target else "across the current environment"

    if not ranked:
        answer = f"No findings recorded {scope} yet -- run a scan first."
    else:
        shown = ranked[:10]
        lines = [f"{len(ranked)} finding(s) {scope}, worst first:"]
        for f in shown:
            sev = (f.get("severity") or "unknown").upper()
            desc = f.get("description") or f.get("type", "finding")
            line = f"- [{sev}] {desc}"
            if target is None and f.get("host_id"):
                line += f" (host: {f['host_id']})"
            remedy = remediation.remedy_for(f.get("type", ""))
            if remedy:
                line += f" -- fix: {remedy}"
            lines.append(line)
        if len(ranked) > len(shown):
            lines.append(f"...and {len(ranked) - len(shown)} more not shown.")
        answer = "\n".join(lines)

    return {
        "question": question,
        "intent": "list_findings",
        "start": None,
        "target": target,
        "answered": True,
        "answer": answer,
        "paths_found": 0,
        "top_path": None,
        "narration": None,
        "findings": ranked,
    }


def ask(
    question: str,
    *,
    min_confidence: float = 1.0,
    nodes: list[Node] | None = None,
) -> dict:
    """Layer 8 entry point: an English question in, a dict describing
    an English answer out.

    `min_confidence` is passed straight through to `storage.load_graph`,
    same default (1.0 = confirmed edges only) and same meaning as
    `cli.py`'s `--min-confidence` flag -- this layer doesn't change
    what "the graph" means, it just calls it. `nodes` lets a caller
    supply a specific node list for intent resolution (e.g. a caller
    that already has one loaded); by default this loads the full node
    inventory from storage so the intent parser can resolve names
    against everything known, not just the min_confidence-filtered
    subgraph a particular query will end up using.

    Returns a plain dict (never writes to storage, never mutates the
    graph):
        {
          "question": str,
          "intent": "find_path" | "list_findings" | "unknown",
          "start": str | None,
          "target": str | None,
          "answered": bool,
          "answer": str,            # the plain-English answer
          "paths_found": int,
          "top_path": list[Edge] | None,
          "narration": dict | None, # Layer 7's output, if find_path ran
          "findings": list[dict] | None,  # present for list_findings
        }
    """
    if nodes is None:
        nodes, _ = storage.load_graph(min_confidence=0.0)

    prompt = build_nl_query_prompt(question, nodes)
    raw_response = call_llm(prompt)
    intent_result = parse_intent_response(raw_response)

    if intent_result is None:
        return _answer_for_unresolved(
            question,
            "I couldn't understand that question well enough to answer it.",
        )
    if intent_result["intent"] == "unknown":
        return _answer_for_unresolved(question, intent_result["clarification"])

    node_ids = {n.id for n in nodes}

    if intent_result["intent"] == "list_findings":
        target = intent_result["target"]
        if target is not None and target not in node_ids:
            result = _answer_for_unresolved(
                question,
                f"The model resolved this to node id {target!r} which "
                f"isn't in the current environment.",
            )
            result["intent"] = "list_findings"
            result["target"] = target
            return result
        return _answer_list_findings(question, target)

    start = intent_result["start"]
    target = intent_result["target"]

    # This is not graph logic -- it's the same node-existence check
    # cli.cmd_analyze does before ever touching AttackGraph. A model
    # that ignored the "copy ids exactly from Known nodes" instruction
    # is a bad intent parse, not a reason to guess.
    if start not in node_ids or target not in node_ids:
        unknown = [n for n in (start, target) if n not in node_ids]
        result = _answer_for_unresolved(
            question,
            f"The model resolved this to node id(s) {unknown} which "
            f"aren't in the current environment.",
        )
        result["intent"] = "find_path"
        result["start"] = start
        result["target"] = target
        return result

    if start == target:
        result = _answer_for_unresolved(
            question,
            f"'{start}' and '{target}' are the same node -- there's no "
            f"path to trace.",
        )
        result["intent"] = "find_path"
        result["start"] = start
        result["target"] = target
        return result

    # Layers 4-5, unchanged: the exact same call cli.cmd_analyze makes.
    graph_nodes, edges = storage.load_graph(min_confidence=min_confidence)
    graph = AttackGraph(graph_nodes, edges)
    paths = graph.find_all_paths(start, target)

    if not paths:
        suffix = (
            " (try asking again once more evidence is confirmed, or lower "
            "the confidence threshold)"
            if min_confidence >= 1.0
            else ""
        )
        answer = (
            f"I don't see a way to get from {start} to {target} in the "
            f"current environment at confidence >= {min_confidence:.2f}.{suffix}"
        )
        return {
            "question": question,
            "intent": "find_path",
            "start": start,
            "target": target,
            "answered": True,
            "answer": answer,
            "paths_found": 0,
            "top_path": None,
            "narration": None,
        }

    ranked = sorted(paths, key=AttackGraph.path_confidence, reverse=True)
    top_path = ranked[0]

    # Layer 7, reused rather than reimplemented: "hand the raw result
    # to Layer 7's narration logic ... to phrase the answer back in
    # English."
    narration = risk_llm.narrate_path(top_path, graph_nodes)

    if narration is not None:
        answer = narration["summary"]
        if len(ranked) > 1:
            answer += (
                f" ({len(ranked)} possible paths were found in total; this "
                f"is the highest-confidence one.)"
            )
    else:
        # Layer 7 failed to produce a usable narrative (e.g. malformed
        # LLM output) -- fall back to the deterministic description
        # rather than inventing prose that didn't come from either
        # layer.
        answer = (
            f"I found a path from {start} to {target}, but couldn't "
            f"generate a narrative for it. The raw path is: "
            f"{graph.describe_path(top_path)}"
        )

    return {
        "question": question,
        "intent": "find_path",
        "start": start,
        "target": target,
        "answered": True,
        "answer": answer,
        "paths_found": len(ranked),
        "top_path": top_path,
        "narration": narration,
    }
