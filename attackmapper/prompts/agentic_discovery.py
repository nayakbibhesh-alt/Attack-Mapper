"""attackmapper/prompts/agentic_discovery.py — the only place the exact
wording of the Continuous/Agentic Discovery prompt (Phase G, the LLM
half of Layer 1's probe-selection step) lives.

Same pattern as the other four prompt modules: a pure function of
typed inputs, no LLM call, no storage access, no network access --
testable in isolation (tests/test_agentic_discovery_prompt.py) and
versionable independent of the call plumbing in
discovery/agentic_loop.py.

Per the master spec's Phase G description, this layer "decides what to
probe next based on findings so far." Critically, deciding is all it
does -- the model proposes a short list of candidate probes and a
rationale for each; discovery/agentic_loop.py is the only place any of
them are actually validated against the authorization scope and
executed (or, just as often, rejected and logged). The prompt is
written to make that division explicit to the model too, mostly so it
doesn't try to talk itself into skipping the "this is only a proposal"
framing -- but the real enforcement lives in code, not in what the
prompt asks for.
"""

from __future__ import annotations

import json

# Kept in sync with discovery/agentic_loop.py's ALLOWED_ACTION_TYPES
# and _execute_action dispatch. Listed here (rather than only in code)
# so the model is told exactly what it's allowed to propose instead of
# being left to guess from the read-only scanners it might know about
# from general training.
_ALLOWED_ACTION_TYPES = ["nmap_scan", "http_probe", "postgres_roles", "stop"]

# Kept in sync with the schema discovery/agentic_loop.py's
# parse_next_probe_response validates. Shown to the LLM verbatim as a
# worked example, same convention as every other prompt module in this
# project.
_SCHEMA_EXAMPLE = {
    "actions": [
        {
            "action_type": "nmap_scan",
            "target": "10.0.2.10",
            "ports": "1-1024",
            "rationale": (
                "app01 was just discovered via web01's CAN_REACH edge and "
                "has no service inventory yet."
            ),
        },
        {
            "action_type": "http_probe",
            "target": "10.0.1.10",
            "url": "http://10.0.1.10/debug",
            "rationale": (
                "web01's nmap banner mentioned a debug build; a single GET "
                "will confirm whether the endpoint is actually reachable."
            ),
        },
        {
            "action_type": "stop",
            "rationale": (
                "every host in the current inventory has already been "
                "scanned and probed at least once; no new leads."
            ),
        },
    ]
}


def _host_line(h: dict) -> str:
    return (
        f"- id={h.get('id', '?')}  hostname={h.get('hostname', '?')}  "
        f"ip={h.get('ip', '?')}  os={h.get('os', '?')}"
    )


def _service_line(s: dict) -> str:
    return (
        f"- host_id={s.get('host_id', '?')}  {s.get('port', '?')}/"
        f"{s.get('protocol', '?')}  {s.get('service_name', '?')}"
    )


def _finding_line(f: dict) -> str:
    return (
        f"- host_id={f.get('host_id', '?')} type={f.get('type', '?')} "
        f"severity={f.get('severity', '?')} "
        f"confidence={f.get('confidence', 1.0)} "
        f"source={f.get('source', '?')}: {f.get('description', '')}"
    )


def build_next_probe_prompt(
    hosts: list[dict],
    services: list[dict],
    findings: list[dict],
    scope: list[str],
    *,
    max_actions: int = 3,
) -> str:
    """Build the Phase G next-probe-selection prompt.

    `hosts`/`services`/`findings` are the current inventory from
    storage.list_hosts()/list_services()/list_findings() -- the same
    kind of structured-only, no-raw-dump inputs every other prompt
    module in this project takes. `scope` is the caller's explicit,
    human-set list of authorized targets (exact hostnames/IPs or CIDR
    blocks) for this run; it is shown to the model so it doesn't waste
    a proposal on something obviously out of bounds, but the model's
    adherence to it is advisory only -- discovery/agentic_loop.py
    re-checks every single proposed target against this same list
    before anything is executed, and silently discards (with a logged
    warning) anything that doesn't pass, regardless of what this
    prompt asked for.

    `max_actions` caps how many actions the model is asked to propose
    in one go; the caller enforces the same cap on the parsed result
    independently, so this is a courtesy to the model's own reasoning,
    not the actual limit.
    """
    host_lines = "\n".join(_host_line(h) for h in hosts) or "(no hosts known yet)"
    service_lines = (
        "\n".join(_service_line(s) for s in services) or "(no services known yet)"
    )
    finding_lines = (
        "\n".join(_finding_line(f) for f in findings) or "(no findings known yet)"
    )
    scope_lines = "\n".join(f"- {entry}" for entry in scope) or "(empty scope)"

    schema_block = json.dumps(_SCHEMA_EXAMPLE, indent=2)

    return f"""You are the probe-selection step of a continuous, agentic \
discovery loop for a network attack-path mapping tool. You are shown \
everything discovered about an environment so far, and your only job \
is to propose up to {max_actions} specific next probes that would most \
usefully extend that picture, plus a one-sentence rationale for each. \
You do not run anything yourself, you do not decide what happens with \
your proposals, and nothing you propose is trusted at face value -- \
every proposed target is checked against the authorization scope \
below before anything runs, and anything outside it is discarded \
without being executed, no matter how you justify it.

Every probe you can propose is strictly read-only: a TCP connect \
scan (which service is listening where), a single HTTP GET (what does \
this page/endpoint actually return), or a single read-only SELECT \
against a Postgres system catalog (what roles/privileges exist). None \
of them create, modify, delete, authenticate destructively, or attempt \
exploitation of anything -- you are only ever gathering more \
information about what is already there.

Authorized scope for this run (the ONLY targets a proposal may name --
anything outside this list will be discarded, not executed):
{scope_lines}

Known hosts:
{host_lines}

Known services:
{service_lines}

Known findings:
{finding_lines}

Respond with ONLY JSON, no preamble, no markdown code fences, matching \
exactly this shape:
{schema_block}

Rules:
- "action_type" must be exactly one of {_ALLOWED_ACTION_TYPES}. Do not \
invent a new action type, and do not propose anything resembling \
active exploitation, credential guessing, denial of service, or any \
state-changing request -- those are not probes this system runs, ever.
- "target" is required for every action_type except "stop", and must \
be an exact hostname or IP copied from the "Known hosts" list above or \
from the "Authorized scope" list above -- never invented. Prefer \
targets already in scope and not yet fully probed over re-probing \
something already well understood.
- "http_probe" and "postgres_roles" only make sense for a target \
already in "Known hosts" (you need somewhere to attach the resulting \
finding to) -- prefer "nmap_scan" for anything not yet in the host \
inventory.
- For "http_probe", include a "url" field with the specific URL to GET \
if the findings above suggest one worth checking (e.g. an endpoint \
mentioned in a finding's evidence); otherwise omit it and the caller \
will probe a sensible default.
- For "postgres_roles", only propose this if a finding or service \
already indicates the target is actually running Postgres -- do not \
guess.
- Propose fewer than {max_actions} actions, or a single "stop" action, \
if you don't see that many genuinely useful next probes. Padding the \
list with speculative or already-covered probes is worse than \
proposing fewer.
- Use action_type "stop" (with no "target") when every host currently \
in scope already has a reasonably complete picture (services scanned, \
any notable findings followed up on) and further probing wouldn't \
plausibly reveal anything new. When you propose "stop" it should be \
the only action in the list.
"""
