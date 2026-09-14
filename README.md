# AttackMapper

Continuously watches a network, figures out what's on it, works out how
those things can be abused to reach each other, and produces a ranked
list of realistic attack paths from an entry point to a high-value
target — in plain English, with evidence. See `ATTACKMAPPER_MASTER.md`
for the full spec this was built against.

> **Post-Phase-G update:** two things below have since changed and are
> now documented in ["Running it"](#running-it) rather than rewritten
> throughout this phase-by-phase history: (1) storage is persistent by
> default (`SQLiteStore`, not the process-local `InMemoryStore` the
> phase log below describes) and (2) a fresh store no longer
> auto-loads the demo topology — it's opt-in via `attackmapper
> seed-demo`. The "Known limitation" note right below this, about
> in-memory state not surviving a new process, describes the
> *original* Phase A behavior and is no longer accurate as of the
> SQLite backend.

## Status: Phase A complete (deterministic core)

Per the phased build plan, this is the ground-truth layer everything
else gets judged against — **zero LLM calls anywhere in this code.**

Implemented:
- `attackmapper/models.py` — `Node`, `Edge`, `Finding`. Enforces two
  invariants beyond the literal spec text: `confirmed=True` requires
  `confidence=1.0` (a confirmed edge can't also be hedged), and
  `proposed_by`/`confidence` are validated at construction time.
- `attackmapper/storage.py` — the `load_graph`/`save_finding`/
  `save_relationship`/`confirm_relationship` interface, backed by an
  `InMemoryStore` seeded with a small hand-verified lab topology
  (`external → web → app → svc_account → db → customer_db`, plus one
  unconfirmed LLM-proposed shortcut edge to demonstrate confidence
  filtering).
- `attackmapper/graph.py` — `AttackGraph`: DFS enumeration of all
  simple paths (cycle-safe), `describe_path`, and `path_confidence`
  (product of edge confidences — pure arithmetic, per Layer 5's spec).
- `attackmapper/cli.py` — `attackmapper analyze --start X --target Y
  [--min-confidence F]`, plus `nodes`, `edges`, `confirm` for
  inspecting/managing the graph.
- `tests/` — 22 unit tests, no infra required: disconnected graphs,
  cyclic graphs, multi-path graphs, zero-path cases, storage
  save/confirm round-trips, and the Edge invariants.

### Known limitation (by design, not a bug)

`InMemoryStore` is process-local and unseeded state does not persist
across separate CLI invocations — each `python3 -m attackmapper.cli
...` call starts a fresh process with a freshly-seeded store. Calling
`confirm <id>` and then `edges` in a *new* process won't show the
promotion; it will within the same process/session (see
`tests/test_storage.py::test_save_relationship_then_confirm_promotes_it`).
This is exactly why Phase B swaps in a real (Postgres) backend behind
the same `Backend` protocol in `storage.py` — nothing above that file
needs to change.

## Status: Phase B complete (discovery, real evidence)

Still **zero LLM calls.** Everything below is exercised against a real
target (a throwaway local HTTP server, `lab_http_server.py`) rather
than only unit-tested in the abstract — nmap actually ran, the HTTP
probe actually fired, the parsed output actually got stored.

Implemented:
- `attackmapper/discovery/scanners.py` — real scanners: `run_nmap_scan`
  (subprocess, `-sT -sV`), `http_probe` (`requests`, GET-only),
  `introspect_postgres_roles` (`psycopg2`, a single read-only SELECT
  against `pg_roles`). Read-only by construction; raises clear
  `RuntimeError`s on missing tools/timeouts/connection failures rather
  than failing silently.
- `attackmapper/discovery/parsers.py` — rigid, pure-function parsers:
  nmap XML → hosts/services/findings (including a small known-
  vulnerable-banner table — e.g. vsftpd 2.3.4 — as an example of
  evidence a rigid parser CAN classify deterministically, versus
  ambiguous evidence which is explicitly left alone for Phase D's
  LLM-backed parser); HTTP responses → leaked-credential and missing-
  security-header findings; Postgres role rows → overprivileged-role
  findings.
- `attackmapper/discovery/pipeline.py` — thin glue tying scanners +
  parsers + storage together (`ingest_nmap_scan`, `ingest_http_probe`,
  `ingest_postgres_roles`).
- `storage.py` extended (additively — the original four functions are
  unchanged) with `save_host`/`save_service`/`list_hosts`/
  `list_services`/`list_findings`, so discovery output actually lands
  in the graph as `Node`s.
- `cli.py` extended with `hosts`, `services`, and `scan-nmap`.
- `examples/phase_b_demo.py` — the full pipeline in one process:
  real scan → real HTTP probe → a **hand-verified** relationship added
  the way an analyst would (Phase C's job is to automate that
  step) → the existing deterministic graph/path finder. Run it:
  `python3 examples/phase_b_demo.py`.
- `tests/test_scanners.py`, `test_parsers.py`, `test_pipeline.py` — 28
  new tests (50 total). Per the master spec's testing strategy,
  scanner *wiring* is tested with mocks (no live network in CI), while
  parsers are tested against fixtures — one of which
  (`nmap_localhost_scan.xml`) is a **real captured scan**, and one
  (`nmap_vsftpd_backdoor_synthetic.xml`) is hand-crafted and clearly
  labeled as such, since actually standing up a backdoored vsftpd
  build isn't something to do even in a throwaway sandbox.

### Design notes worth flagging

- `save_host` upserts by IP rather than inserting duplicates on every
  re-scan — not stated in the spec, but re-scanning is the normal case
  for a "continuously watches a network" tool, and duplicate Nodes per
  scan would silently break path-finding correctness over time.
- Regex-based finding types (`leaked_credential`) get `confidence <
  1.0` even though they come from deterministic code, not an LLM —
  read as "how sure are we this is real" rather than "was this
  produced by an algorithm." A pattern match on a response body can
  false-positive; that uncertainty should show up in the number.

## Running it

```bash
# from the repo root
python3 -m pytest tests/ -v
```

### Storage: persistent by default

`attackmapper` and `attackmapper serve` both read/write the same
SQLite file (`./attackmapper.db` by default), so results from one CLI
invocation, or from a previous `serve` session, are still there the
next time you run either one — nothing is lost when the process exits.
A fresh store starts **empty** except for one structural `external`
node (the internet / an unauthenticated attacker); the old hardcoded
demo topology is opt-in only now (see below), not loaded automatically.

```bash
# override where the .db file lives (default: ./attackmapper.db)
export ATTACKMAPPER_DB_PATH=/path/to/mylab.db

# opt out of persistence entirely — a throwaway, process-local store
export ATTACKMAPPER_STORAGE=memory

# auto-load the demo topology at startup instead of doing it manually
export ATTACKMAPPER_SEED_DEMO=1
```

### Point it at a real target

```bash
# scan something you're authorized to test (real nmap, real network)
python3 -m attackmapper.cli scan-nmap --target 10.0.1.10 --ports 1-1024

# propose relationships from whatever that scan found -- works even if
# nothing on the target tripped a known-vulnerable-banner rule, since
# this also reasons over the raw open-services inventory, not just
# findings
export OPENROUTER_API_KEY=sk-or-...
python3 -m attackmapper.cli infer --compare

# see what got discovered
python3 -m attackmapper.cli nodes
python3 -m attackmapper.cli hosts
python3 -m attackmapper.cli edges --filter unconfirmed

# find paths from the internet to whatever host id scan-nmap assigned
# (attackmapper nodes / hosts will show you the real id, e.g. host-1)
python3 -m attackmapper.cli analyze --start external --target host-1

# start over on the same store, e.g. to point it at a different lab
python3 -m attackmapper.cli reset --yes
```

### Or load the worked example instead

```bash
# additive: loads external -> web -> app -> svc_account -> db ->
# customer_db on top of whatever the store already has
python3 -m attackmapper.cli seed-demo

# confirmed-only view (default, min_confidence=1.0)
python3 -m attackmapper.cli analyze --start external --target db

# include unconfirmed/LLM-proposed edges above a threshold
python3 -m attackmapper.cli analyze --start external --target db --min-confidence 0.5

# inspect the graph
python3 -m attackmapper.cli nodes
python3 -m attackmapper.cli edges --filter unconfirmed
python3 -m attackmapper.cli confirm <edge-id>

# Phase C: ask the LLM to propose relationships from stored findings
export OPENROUTER_API_KEY=sk-or-...
python3 -m attackmapper.cli infer --compare

# Phase D: hand one ambiguous piece of evidence to the LLM directly
python3 -m attackmapper.cli interpret-evidence \
    --host-id host-1 --type service_banner \
    --text "GlacierFS-Admin/0.9.1-rc (debug-mode; auth=disabled-by-default)"

# Phase E: narrate the top-ranked path in plain English + remediations
python3 -m attackmapper.cli analyze --start external --target db --narrate

# Phase F: ask a plain-English question instead of naming node ids
python3 -m attackmapper.cli ask "how could someone reach the db from the internet?"
```

The browser UI (`python3 -m attackmapper.cli serve`) exposes all of
the above too: a "Go scan a target" / "Load demo network instead"
panel shows up on the Overview page whenever the store is empty, and a
"reset store…" button lives on the Hosts page.

Standard library only for Phase A. `requests`/`psycopg2-binary` for
Phase B. `openai` (used only as an OpenAI-compatible client for
OpenRouter — see `attackmapper/llm_client.py`) for Phase C (only
imported when `infer` actually
runs — Phases A/B and all of Phase C's own unit tests work without it
installed). `pytest` is only needed to run the test suite.

## Status: Phase C complete (relationship inference — first LLM layer)

The first layer in the whole system that calls a model. Layers 4–6
(graph, path finder, CLI orchestration) remain completely unchanged
and still never call an LLM, per the architecture's non-negotiable
separation.

Implemented:
- `attackmapper/prompts/relationship_inference.py` — the one place the
  exact wording of the Layer 2 prompt lives, per the spec's "keep
  every prompt template in a dedicated `prompts/` module" rule. A pure
  function of `(findings, hosts)` in, prompt string out — no LLM call,
  no storage access, so it's tested (`tests/test_prompts.py`) without
  ever touching a model.
- `attackmapper/inference/relationship_llm.py` — `call_llm()` (a thin
  wrapper delegating to the shared `attackmapper/llm_client.py`, which
  lazily imports `openai` and raises a clear `RuntimeError` if the
  package or `OPENROUTER_API_KEY` is missing, matching
  `discovery/scanners.py`'s error style), `parse_relationship_response()` (strict schema
  validation — malformed JSON, a missing top-level key, or any single
  item missing a field or carrying an out-of-range confidence is
  logged and dropped, never guessed at), `infer_relationships()` (the
  Layer 2 entry point: findings from storage → prompt → LLM →
  validate → store every valid proposal as `confirmed=False,
  proposed_by="llm"` — low-confidence proposals are stored too, not
  filtered here, per the spec), and `compare_proposed_to_confirmed()`
  (the Phase C sanity-check the build plan calls for: buckets each
  proposal against the hand-verified confirmed edges from Phase B into
  agrees / contradicts / novel, for a human to review — never an
  auto-confirm or auto-reject).
- `cli.py` extended with `infer [--compare]`.
- `examples/phase_c_demo.py` — real findings from the Phase B pipeline
  fed to a real LLM call, then compared against a hand-verified
  baseline for the identical scenario. Needs `OPENROUTER_API_KEY`; the
  demo says so and exits cleanly rather than faking a call if it's
  unset. Run it: `python3 examples/phase_c_demo.py`.
- `tests/test_prompts.py`, `tests/test_relationship_llm.py` — 23 new
  tests (73 total), zero live model calls. Per the master spec's
  testing strategy for Phases C–F: prompt-building is tested directly,
  and the inference pipeline is tested entirely against fixture LLM
  *responses* (well-formed, non-JSON, missing top-level key, wrong
  type, missing fields, out-of-range confidence, non-numeric
  confidence) by monkeypatching `call_llm`.

### Design notes worth flagging

- `relationship_type` is deliberately *not* restricted to a hard enum
  during validation — the master spec's schema lists it as
  `'CONNECTS_TO' | 'CAN_REACH' | 'RUNS_AS' | 'CAN_ACCESS' | ...`, i.e.
  explicitly extensible. The prompt nudges the model toward the known
  vocabulary; validation only requires a non-empty string, so a
  genuinely novel-but-real relationship type isn't silently dropped.
- `infer_relationships()` skips the LLM call entirely (and returns
  `[]`) when there are no findings to reason over, rather than sending
  an empty-context prompt and burning a call for nothing.
- `compare_proposed_to_confirmed()` keys strictly on the `(source,
  target)` pair, not on evidence text or confidence — "agrees" means
  same pair *and* same relationship type; a same-pair edge with a
  *different* type is flagged as `contradicts` rather than silently
  bucketed as agreement, since that's exactly the case a human most
  needs to see before trusting the LLM further.

## Status: Phase D complete (evidence interpretation upgrade)

The second LLM layer, and the last one inside Layer 1. Purely
additive: `discovery/parsers.py` is completely unchanged and keeps
handling everything it already handled deterministically — the LLM
only covers evidence a rigid parser was handed and couldn't
confidently classify (an unfamiliar banner, an HTTP response, a config
snippet).

Implemented:
- `attackmapper/prompts/evidence_interpretation.py` — the one place
  the exact wording of the Layer 1 LLM prompt lives, mirroring
  `prompts/relationship_inference.py`'s shape: a pure function of
  `(evidence_type, raw_evidence, host)` in, prompt string out. Tells
  the model explicitly that it classifies evidence it's given and does
  not decide what to scan next or take any action, and shows the
  `{"findings": [...]}` schema from the master spec as a worked
  example rather than a prose description.
- `attackmapper/discovery/evidence_llm.py` — `call_llm()` (same
  lazy-import-`openai`, clear-`RuntimeError` style as
  `inference/relationship_llm.py`), `parse_evidence_response()` (strict
  schema validation: malformed JSON, a missing top-level key, a
  missing field, or an invalid `severity`/out-of-range `confidence` on
  any single item is logged and dropped, never guessed at), and
  `interpret_evidence()` (the Layer 1 LLM entry point: one piece of
  raw evidence → prompt → LLM → validate → store every valid finding
  with `source="llm_inferred"` and the model's own confidence — never
  silently upgraded to `source="scanner"`).
- `attackmapper/discovery/pipeline.py` extended with
  `ingest_ambiguous_evidence(host_id, evidence_type, raw_evidence)` —
  a thin, explicit entry point (not an automatic fallback inside
  `ingest_nmap_xml`/`ingest_http_probe`) since deciding *that* a piece
  of evidence is ambiguous is a judgment call for the caller, not
  something this function tries to detect on its own.
- `cli.py` extended with `interpret-evidence --host-id ID --type LABEL
  (--text TEXT | --file PATH)`.
- `examples/phase_d_demo.py` — an invented, unfamiliar service banner
  and a config snippet (the two evidence shapes the master spec names
  explicitly) go through the real LLM call and come back as stored
  findings, after first confirming against
  `parsers.KNOWN_VULNERABLE_BANNERS` that the rigid parser really has
  no rule for that banner. Needs `OPENROUTER_API_KEY`; exits cleanly
  with an explanation if it's unset. Run it:
  `python3 examples/phase_d_demo.py`.
- `tests/test_evidence_interpretation_prompt.py`,
  `tests/test_evidence_llm.py`, plus two new cases in
  `tests/test_pipeline.py` — 26 new tests (99 total), zero live model
  calls, same fixture-response-based approach as Phase C.

### Design notes worth flagging

- Findings have no `confirmed`/`proposed_by` split the way `Edge`
  does — the master spec's `findings` table only has `source` and
  `confidence`. `source="llm_inferred"` is what plays the same role
  `confirmed=False` plays for edges: it's the flag every downstream
  consumer (a human reviewer, or Layer 2's relationship inference,
  which reads all findings regardless of source) can filter or weight
  on, so an LLM-classified finding is never indistinguishable from
  something a scanner actually confirmed.
- `ingest_ambiguous_evidence` looks up host context from storage and
  passes it through, but works fine with a `host_id` that isn't in the
  inventory yet (`host=None`) — evidence can arrive before the host
  record does.
- `interpret_evidence` skips the LLM call entirely on empty/whitespace
  evidence, matching `infer_relationships`' no-op-on-nothing-to-reason-
  over behavior from Phase C.

## Status: Phase E complete (risk narration and remediation)

Layer 7 — the last LLM layer that reads *output* of the deterministic
core rather than feeding *into* it. Layers 4–6 are completely
unchanged: this layer takes a `list[Edge]` path already computed by
the Path Finder and only explains it — it never re-derives, re-ranks,
or second-guesses the path itself, and it has no write path into
`storage.py` at all (unlike Layers 1–2, which persist Findings/Edges).

Implemented:
- `attackmapper/prompts/risk_narration.py` — the one place the exact
  wording of the Layer 7 prompt lives, same pattern as the other two
  prompt modules: a pure function of `(path, nodes)` in, prompt string
  out. Renders each hop with its relationship, evidence, and
  confirmed/confidence/proposed_by status (so the model can point at a
  specific hop as `weakest_link` and correctly flag unconfirmed ones
  rather than treating everything as equally certain), and shows the
  `{"summary", "weakest_link", "remediations"}` schema from the master
  spec as a worked example.
- `attackmapper/narration/risk_llm.py` — `call_llm()` (same
  lazy-import-`openai`, clear-`RuntimeError` style as the other two
  LLM modules), `parse_narration_response()` (schema validation with
  one deliberate difference from Layers 1–2: this layer produces a
  *single* narrative object describing one path, not a list of
  independent proposals, so any single malformed field — including one
  bad remediation item in the middle of the list — rejects the whole
  response as `None` rather than silently keeping a partial result a
  caller could mistake for complete), and `narrate_path()` (the Layer
  7 entry point: skips the LLM call on an empty path, otherwise
  prompt → LLM → validate → return the dict, remediations sorted by
  priority).
- `cli.py`'s `analyze` command extended with `--narrate`, which runs
  Layer 7 on the top-ranked (highest-confidence) path after printing
  the raw path as before, and surfaces a clean error rather than a
  traceback if `OPENROUTER_API_KEY` is missing.
- `examples/phase_e_demo.py` — reuses the seeded Phase A demo topology
  (which already matches the master spec's own worked example almost
  exactly) to find and rank real paths, then narrates the top one via
  a real LLM call, and — when more than one path exists — narrates the
  lowest-confidence one too for contrast. Needs `OPENROUTER_API_KEY`;
  exits cleanly with an explanation if it's unset. Run it:
  `python3 examples/phase_e_demo.py`.
- `tests/test_risk_narration_prompt.py`, `tests/test_risk_llm.py` — 25
  new tests (124 total), zero live model calls, same fixture-response
  approach as Phases C–D.

### Design notes worth flagging

- `parse_narration_response` rejects the *entire* response on any
  single malformed remediation item, unlike `parse_relationship_response`/
  `parse_evidence_response`, which keep whichever list items are
  individually valid. That asymmetry is intentional: those two layers
  produce independent proposals where "3 out of 4 were valid" is still
  useful, whereas a narrative with "priority 1" and "priority 3" but a
  broken "priority 2" is a result a caller can't safely trust the
  ordering or completeness of.
- `narrate_path()` takes plain `list[Edge]`/`list[Node]` arguments and
  returns a plain `dict` — no `storage` import anywhere in
  `risk_llm.py`. That's a direct reflection of the spec's "advisory
  text ... never merged into the graph data itself": there is
  structurally no way for this layer to accidentally write back into
  the graph, because it has no handle to do so.
- The CLI's `--narrate` only narrates the single top-ranked path, not
  every path found, to avoid burning an LLM call per path on every
  `analyze` invocation — a caller who wants more can call
  `risk_llm.narrate_path()` directly on any path from the returned
  list.

## Status: Phase F complete (natural language interface)

Layer 8 — "the primary user-facing surface of the finished product,"
per the build plan. This is the layer the Vision section's worked
example ("how could someone get to our customer database from the
internet?") is actually answered by. Per the spec, it's a thin
translation layer: it doesn't contain graph logic of its own, it calls
the same `AttackGraph.find_all_paths` Layers 4–5 already provide and
reuses Layer 7's narration to phrase the answer back in English.

Implemented:
- `attackmapper/prompts/nl_query.py` — the one place the exact wording
  of the Layer 8 intent-parsing prompt lives, same pattern as the
  other three prompt modules: a pure function of `(question, nodes)`
  in, prompt string out. Shows the model the current node inventory
  (ids + types + labels) so it can resolve loose English ("our
  customer database") onto a real node id instead of inventing one,
  and asks for the `{"intent", "start", "target"}` schema from the
  master spec verbatim. Adds one additive extension beyond the
  spec's literal example: an `intent="unknown"` escape hatch (with a
  one-sentence `"clarification"`) for questions that don't resolve to
  exactly two known nodes with confidence — same pattern as
  Relationship Inference's `{"relationships": []}` for "no evidence
  supports anything," just for "I'm not sure which nodes you mean"
  instead of "there's nothing here."
- `attackmapper/narration/nl_interface.py` — `call_llm()` (same
  lazy-import-`openai`, clear-`RuntimeError` style as the other
  three LLM modules), `parse_intent_response()` (schema validation;
  like Layer 7, a single decision about one question, so any
  structural problem rejects the whole response as `None` rather than
  guessing at a partial intent), and `ask()` — the Layer 8 entry
  point. `ask()` does intent parsing (one LLM call), checks the
  resolved `start`/`target` actually exist and aren't the same node
  (plain node-id lookups, not graph logic — the identical check
  `cli.cmd_analyze` already does), calls the real
  `storage.load_graph()` → `AttackGraph.find_all_paths()` →
  `AttackGraph.path_confidence()` exactly as `cli.py` does, and hands
  the top-ranked path to `narration.risk_llm.narrate_path()` (Layer 7,
  reused unmodified) to produce the final English answer. If Layer 7's
  narration fails, `ask()` falls back to `AttackGraph.describe_path()`
  rather than inventing prose that came from neither layer.
- `cli.py`'s new `ask` subcommand: `attackmapper ask "<question>"
  [--min-confidence F]`, printing the English answer and, when a path
  was narrated, the weakest link and remediations underneath it — same
  shape as `analyze --narrate`'s output.
- `examples/phase_f_demo.py` — runs the master spec's own Vision-section
  question against the seeded Phase A demo topology, plus two
  questions chosen to show the no-LLM-call-for-Layer-7 short-circuits:
  one with no path in the seeded data (reports "no path" instead of
  hallucinating one) and one that doesn't resolve to any known node
  (`intent="unknown"`, declines rather than guesses). Needs
  `OPENROUTER_API_KEY`; exits cleanly with an explanation if it's unset.
  Run it: `python3 examples/phase_f_demo.py`.
- `tests/test_nl_query_prompt.py`, `tests/test_nl_interface.py` — 29
  new tests (153 total; two pre-existing `test_scanners.py` failures
  are an environment gap — `psycopg2` isn't installed — unrelated to
  this phase), zero live model calls. `test_nl_interface.py` runs
  `ask()` against a real `InMemoryStore` and real `AttackGraph` with
  only the two LLM calls (intent parsing, Layer 7's narration) mocked,
  specifically to check that Layer 8 delegates to the real
  deterministic layers rather than reimplementing any path-finding
  logic of its own.

### Design notes worth flagging

- `ask()` takes a `min_confidence` parameter with the same default and
  meaning as `cli.py`'s `--min-confidence` flag, threaded straight
  through to `storage.load_graph()`. Layer 8 doesn't get to redefine
  what "the graph" means for a plain-English question versus an
  id-based one.
- Node-existence and start-equals-target checks happen *before* any
  call into `AttackGraph`, using plain set membership against the node
  inventory — not because a "smarter" check belongs in this layer, but
  because a model that ignored the prompt's "copy ids exactly from
  Known nodes" instruction produced a bad intent parse, and that's
  cheaper and clearer to catch here than to let `find_all_paths`
  silently return `[]` for a typo'd node id and report it as "no path
  exists" when the real problem was "that node doesn't exist."
- No path found and intent="unknown" both short-circuit before Layer 7
  is ever called — an English answer for "there's no path" or "I don't
  know what you mean" doesn't need a second LLM call to phrase; only an
  actual found path is worth spending one narrating.
- Same as Layer 7: `ask()` never writes to `storage.py`. It takes a
  question, reads the graph, and returns a plain dict — nothing here
  can accidentally feed back into the data Layers 1–3 are responsible
  for.

## Status: Phase G complete (continuous/agentic discovery)

The last phase, and the one the build plan flags as needing the most
guardrails. This does **not** introduce a new kind of actor or any new
scanning/network code — it's a loop around the exact same Layer 1/2
functions every earlier phase already uses by hand (`discovery.
pipeline.ingest_nmap_scan` / `ingest_http_probe` / `ingest_postgres_roles`,
`inference.relationship_llm.infer_relationships`). The read-only and
"never auto-confirmed" guarantees are inherited structurally from
those functions, not re-implemented here.

Implemented:
- `attackmapper/prompts/agentic_discovery.py` — the one place the
  exact wording of the Phase G probe-selection prompt lives, same
  pattern as the other four prompt modules: a pure function of
  `(hosts, services, findings, scope, max_actions)` in, prompt string
  out. Tells the model explicitly it may only *propose* one of four
  fixed action types (`nmap_scan`, `http_probe`, `postgres_roles`,
  `stop`), that every probe is strictly read-only, and — honestly,
  since this is enforced in code either way — that any proposal
  naming a target outside the authorized scope shown to it will be
  discarded rather than executed no matter how it's justified.
- `attackmapper/discovery/agentic_loop.py` — `call_llm()` (same
  lazy-import-`openai`, clear-`RuntimeError` style as the other
  four LLM modules), `parse_next_probe_response()` (schema validation,
  same "keep whichever independent proposals are individually valid"
  style as Layers 1–2, since a "stop" mixed with a malformed item
  should still let the valid item through), `_target_in_scope()` (the
  actual guardrail: exact string match or CIDR containment against a
  caller-supplied scope list, no wildcards — an IP that fails to parse
  against a CIDR entry is never treated as a match), and
  `run_discovery_loop()` (the Phase G entry point): loads the current
  inventory, asks the LLM what to probe next, discards (logged, not
  executed) anything out of scope, executes the rest via the existing
  pipeline functions, re-runs relationship inference automatically
  whenever something new was actually ingested that iteration, and
  stops on a `stop` proposal, on nothing-executed, or after
  `max_iterations`. **Requires an explicit, non-empty `scope`
  argument — there is no default scope, and passing an empty one
  raises `ScopeError` immediately** rather than silently running
  unscoped, per the master spec's non-negotiable scope-discipline
  principle. Never calls `storage.confirm_relationship()` anywhere;
  instead, at the end of a run it returns every currently-unconfirmed
  relationship at or above `review_threshold` as a `pending_review`
  list — the human-in-the-loop queue the spec asks for, sitting on
  top of the exact same `confirmed=False` / `attackmapper confirm
  <id>` mechanism Phase C already established, not a new one.
- `cli.py` extended with `discover --scope TARGET [TARGET ...]
  [--max-iterations N] [--max-actions N] [--review-threshold F]`,
  printing each iteration's proposed/executed/skipped actions and the
  final pending-review queue.
- `examples/phase_g_demo.py` — runs the real loop against the same
  throwaway local HTTP target `phase_b_demo.py` uses, scoped to
  exactly `["127.0.0.1"]`, so the demo doubles as a live scope-
  enforcement check: the model is never told what else might be out
  there, and the loop structurally cannot touch anything beyond that
  one address regardless of what it proposes. Needs
  `OPENROUTER_API_KEY`; exits cleanly with an explanation if it's
  unset. Run it: `python3 examples/phase_g_demo.py`.
- `tests/test_agentic_discovery_prompt.py`,
  `tests/test_agentic_loop.py` — 35 new tests (188 total; the same two
  pre-existing `test_scanners.py` failures from missing `psycopg2` in
  this environment remain, unrelated to this phase), zero live model
  calls and zero live scans/probes — `run_discovery_loop()` is
  exercised against a fresh `InMemoryStore` with `call_llm` and the
  pipeline's `ingest_*` functions both monkeypatched, and scope
  enforcement (`_target_in_scope`) is tested directly with exact
  matches, CIDR containment, CIDR misses, and non-IP targets against
  CIDR scopes.

### Design notes worth flagging

- `run_discovery_loop` raising `ScopeError` on an empty/missing scope
  is deliberate friction, not an oversight: every other guardrail in
  this module (schema validation, the scope check itself) degrades
  gracefully by logging and skipping, because a single bad LLM
  proposal shouldn't kill a whole run. An unscoped *invocation* is
  different in kind — there's no reasonable default to fall back to,
  so it fails loudly and immediately instead of, say, silently
  scoping to nothing and just always skipping everything.
- The model is shown the authorized scope in the prompt and asked to
  respect it, but `prompts/agentic_discovery.py`'s docstring and the
  prompt text itself are explicit that this is a courtesy, not the
  enforcement mechanism — `_target_in_scope()` in `agentic_loop.py` is
  the actual guardrail, re-checked in code against every single
  proposed target regardless of what the prompt asked for or how the
  model justified it.
- `http_probe`/`postgres_roles` actions require the target to already
  be a known host (resolved via `_resolve_host_id`, an exact ip/
  hostname lookup against `storage.list_hosts()`) — the loop never
  invents a host record just to attach a probe result to one. A
  proposal against an unknown target fails with a clear reason
  (`"no known host for target ..."`) rather than silently skipping or
  guessing; the natural next step (an `nmap_scan` of that target
  first) is left for the model to propose on a later iteration once
  it sees the failure reflected in the next prompt's inventory.
- The loop re-runs Layer 2 (`infer_relationships()`) once per
  iteration, over *all* findings currently in storage, rather than
  only the findings from that iteration — mirroring `infer_relationships`'s
  own existing behavior of reasoning over everything in storage each
  time it's called (Phase C), not a new incremental-inference mode.
- `pending_review` is a read-only snapshot, not a persistent queue —
  it's recomputed fresh via `storage.list_relationships(confirmed=False)`
  at the end of every `run_discovery_loop()` call, filtered by
  `review_threshold` and sorted by confidence descending. There is no
  separate "reviewed/dismissed" state; the queue is exactly "what's
  still unconfirmed and confident enough to prioritize," recomputed on
  demand, which means confirming an edge (via the existing `attackmapper
  confirm <id>`) is the only way it stops showing up.
