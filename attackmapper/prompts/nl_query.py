"""attackmapper/prompts/nl_query.py — the only place the exact wording
of the Natural Language Interface's intent-parsing prompt (Layer 8)
lives.

Same pattern as the other three prompt modules (relationship_inference,
evidence_interpretation, risk_narration): a pure function of typed
inputs, no LLM call, no storage access -- testable in isolation
(tests/test_nl_query_prompt.py) and versionable independent of the
call plumbing in narration/nl_interface.py.

Layer 8's job per the master spec is to "translate a user's English
question into a call against Layers 5/6" -- concretely, this means
mapping loose English ("how could someone get to our customer
database from the internet?") onto the two node ids `find_all_paths`
actually needs. This module only builds that one prompt; it has no
opinion about what happens with the parsed intent afterwards.

A second intent, "list_findings", is an additive extension past the
original spec's path-tracing-only scope: "what's wrong with
rubyzensemble.in" or "what are the worst vulnerabilities we have"
aren't find_path questions at all -- there's no start/target pair to
resolve -- but they're exactly the kind of general question a Q&A box
called "Ask" should be able to answer without a human being expected
to know it secretly only understands path-tracing. Same "thin
translation layer" rule applies: this module still doesn't decide
what happens with a list_findings intent, it just recognizes the
question shape and (optionally) which single host it's scoped to.
"""

from __future__ import annotations

import json

from ..models import Node

# Kept in sync with the "Natural Language Interface — expected output
# schema (intent parsing step)" block in ATTACKMAPPER_MASTER.md
# section 7. The spec only shows the happy-path shape; the "unknown"
# intent and "clarification" field below are an additive extension
# (same escape-hatch pattern as Relationship Inference's
# `{"relationships": []}` for "no evidence supports anything") so a
# question that doesn't map onto a graph call still gets a
# schema-valid, parseable response instead of the model being forced
# to guess at node ids it isn't sure about.
_SCHEMA_EXAMPLE = {
    "intent": "find_path",
    "start": "external",
    "target": "db",
}

_UNKNOWN_EXAMPLE = {
    "intent": "unknown",
    "start": None,
    "target": None,
    "clarification": "I can't tell which host you mean by 'the app server' "
    "-- there are two: app01 and app02.",
}

# "target" is the one host the question is scoped to ("what's wrong
# with web01"), or null when the question isn't scoped to a single
# host ("what are our worst vulnerabilities overall").
_LIST_FINDINGS_EXAMPLE = {
    "intent": "list_findings",
    "target": "web",
}

_LIST_FINDINGS_ALL_EXAMPLE = {
    "intent": "list_findings",
    "target": None,
}


def _node_line(node: Node) -> str:
    label = f"  label={node.label}" if node.label else ""
    return f"- id={node.id}  type={node.type}{label}"


def build_nl_query_prompt(question: str, nodes: list[Node] | None = None) -> str:
    """Build the Layer 8 (Natural Language Interface) intent-parsing
    prompt.

    `question` is the user's raw English question. `nodes` is the
    current node inventory (typically `storage.load_graph()[0]`),
    included so the model can resolve loose descriptions ("our
    customer database", "the internet") onto real node ids instead of
    inventing its own -- the same "only structured data needed" rule
    as the other prompts, not a raw database dump. An empty/omitted
    node list is valid (e.g. a fresh environment with nothing
    discovered yet); the model is expected to return intent="unknown"
    in that case since it has nothing to map onto.
    """
    nodes = nodes or []
    node_lines = "\n".join(_node_line(n) for n in nodes) or "(no nodes known yet)"

    schema_block = json.dumps(_SCHEMA_EXAMPLE, indent=2)
    findings_block = json.dumps(_LIST_FINDINGS_EXAMPLE, indent=2)
    findings_all_block = json.dumps(_LIST_FINDINGS_ALL_EXAMPLE, indent=2)
    unknown_block = json.dumps(_UNKNOWN_EXAMPLE, indent=2)

    return f"""You are the Natural Language Interface layer of a network \
attack-path mapping tool. A human has asked a question in plain \
English. Your only job is to translate that question into a call \
against the tool's deterministic backend -- you do not answer the \
question yourself, you do not reason about attack paths or \
vulnerabilities, and you do not know anything about the environment \
beyond the node inventory below. All you do is identify which of three \
intents the question is, and the node id(s) it needs.

Known nodes:
{node_lines}

User's question:
{question}

Respond with ONLY JSON, no preamble, no markdown code fences, matching \
exactly one of these three shapes:

1. A path-finding question -- how one thing could be used to reach, \
compromise, or access another thing (directly or via a chain of \
steps):
{schema_block}

2. A findings/vulnerability question -- what's wrong with something, \
what vulnerabilities or weaknesses exist, either on one named host or \
across the whole environment:
{findings_block}
or, if no single host is named:
{findings_all_block}

3. Anything else -- greetings, questions about a single node in \
isolation that aren't asking what's wrong with it, or questions you \
cannot map onto the "Known nodes" list above with confidence:
{unknown_block}

Rules:
- "intent" is "find_path" for reach/compromise/access questions \
between two things, "list_findings" for what's-wrong-with/vulnerable/ \
weakness/issue questions about one host or the environment in general, \
and "unknown" for everything else.
- For "find_path": "start" and "target" must be exact node ids copied \
from the "Known nodes" list above -- never invented, abbreviated, or \
guessed. Use the literal id "external" for questions about "the \
internet", "outside", or "an attacker" with no more specific starting \
point given.
- For "list_findings": "target" must be an exact node id copied from \
the "Known nodes" list above if the question names one specific host \
(e.g. "what's wrong with web01"), or null if it doesn't (e.g. "what \
are our worst vulnerabilities", "what should we fix first"). Never \
include a "start" field for this intent.
- If a "find_path" or "list_findings" question mentions something not \
in the "Known nodes" list, or mentions more than one plausible match \
for a name (e.g. two hosts that could both be "the app server"), do \
not guess -- return intent="unknown" with "start" and "target" set to \
null and a one-sentence "clarification" explaining what's ambiguous or \
missing, for example:
{unknown_block}
- Never include a "clarification" field except for "unknown".
"""
