# AttackMapper — Master Reference & Build Guide

This is the single source of truth for the project: what it is, how
it's structured, the exact data contracts between layers, where LLMs
plug in and how, and the order to build it in. Use this file as the
spec to generate code against — every interface named here should be
implemented exactly as described so the layers stay swappable.

---

## 1. Vision

AttackMapper continuously watches a network, automatically figures out
what's on it, works out how those things can be abused to reach each
other, and produces a ranked list of realistic attack paths from an
entry point to a high-value target — in plain English, with evidence,
not just a graph diagram. A user asks "how could someone get to our
customer database from the internet?" and gets back an actual answer:
the specific hosts, the specific misconfigurations, the specific order
of steps, ranked by plausibility, with a suggested fix for the weakest
link. A deterministic graph engine does the traversal math; an LLM
does the reasoning-under-ambiguity work of turning messy evidence into
graph relationships and turning graph output back into plain English.

---

## 2. Core design principles (non-negotiable)

1. **Contracts, not implementations.** Every layer promises a fixed
   *shape* of data to the layer above it (a list of `Node`, a list of
   `Edge`) and nothing else. Internals of any layer can be completely
   rewritten as long as the shape at its boundary doesn't change.
2. **LLMs propose, the graph engine disposes.** The path-finding
   algorithm is always plain deterministic graph traversal — never an
   LLM call. LLMs may propose candidate `Edge`s or `Finding`s, but
   every such proposal is stored with `confirmed=False` and a
   `confidence` score. The path finder can be told to use confirmed
   edges only, or to include proposed ones above a threshold — that's
   a parameter, not a hardcoded behavior.
3. **Discovery is read-only.** Nothing in this system modifies the
   environment it's scanning. Remediation output is advisory text for
   a human to act on — never an auto-applied change.
4. **Structured LLM output only.** Every LLM call in this system
   returns JSON matching a predefined schema (validated before use),
   never freeform prose consumed directly by other code. Freeform
   prose is only a final output, shown to a human, never fed back into
   the graph.
5. **Scope discipline.** Discovery and any future agentic/autonomous
   behavior is scoped strictly to environments you own or are
   explicitly authorized to test (the lab, and later, only networks
   with clear authorization). This is a hard boundary, not a
   configuration option to relax later.

---

## 3. Architecture

```
┌────────────────────────────────────────────────────────────┐
│ 8. Natural Language Interface   (LLM: English <-> graph)    │
├────────────────────────────────────────────────────────────┤
│ 7. Risk Narration & Remediation (LLM: explain + suggest)    │
├────────────────────────────────────────────────────────────┤
│ 6. CLI / API                    (orchestration, output)     │
├────────────────────────────────────────────────────────────┤
│ 5. Path Finder                  (deterministic)             │
├────────────────────────────────────────────────────────────┤
│ 4. Graph Engine                 (deterministic)             │
├────────────────────────────────────────────────────────────┤
│ 3. Storage (Postgres)           (Nodes/Edges + confidence)  │
├────────────────────────────────────────────────────────────┤
│ 2. Relationship Inference       (LLM: findings -> edges)    │
├────────────────────────────────────────────────────────────┤
│ 1. Discovery + Evidence Interp. (scanners + LLM parsing)    │
└────────────────────────────────────────────────────────────┘
```

Data flows strictly upward. Layers 4–6 never call an LLM. Layers 1–2
and 7–8 are where all LLM calls live. This separation is what keeps
the core trustworthy even while the LLM-facing edges evolve quickly.

---

## 4. Data model

```sql
hosts (
    id          UUID PRIMARY KEY,
    hostname    TEXT,
    ip          TEXT,
    os          TEXT,
    first_seen  TIMESTAMP,
    last_seen   TIMESTAMP
);

services (
    id            UUID PRIMARY KEY,
    host_id       UUID REFERENCES hosts(id),
    port          INT,
    protocol      TEXT,
    service_name  TEXT
);

findings (
    id           UUID PRIMARY KEY,
    host_id      UUID REFERENCES hosts(id),
    type         TEXT,          -- e.g. 'ssrf', 'leaked_credential', 'weak_password'
    severity     TEXT,          -- 'low' | 'medium' | 'high' | 'critical'
    description  TEXT,
    evidence     TEXT,
    source       TEXT,          -- 'scanner' | 'llm_inferred' | 'manual'
    confidence   FLOAT          -- 1.0 for scanner-confirmed, LLM self-reported otherwise
);

assets (
    id           UUID PRIMARY KEY,
    host_id      UUID REFERENCES hosts(id),
    name         TEXT,
    criticality  TEXT           -- 'low' | 'medium' | 'high' | 'crown_jewel'
);

relationships (
    id                 UUID PRIMARY KEY,
    source_id          UUID,    -- references hosts.id or a virtual node (e.g. 'external')
    target_id          UUID,
    relationship_type  TEXT,    -- 'CONNECTS_TO' | 'CAN_REACH' | 'RUNS_AS' | 'CAN_ACCESS' | ...
    evidence           TEXT,
    confirmed          BOOLEAN, -- true if deterministically verified or human-approved
    confidence         FLOAT,   -- 0.0-1.0
    proposed_by        TEXT     -- 'discovery' | 'llm' | 'manual'
);
```

`confirmed`/`confidence`/`proposed_by` on `relationships` are what
keep LLM output honest — nothing an LLM proposes silently becomes "the
truth"; it's visibly a hypothesis until confirmed, and every consumer
(path finder, CLI, reports) can filter or visually distinguish on that
basis.

---

## 5. Core types (implement exactly this shape)

```python
# models.py
from dataclasses import dataclass

@dataclass
class Node:
    id: str
    type: str          # 'external' | 'host' | 'account' | 'asset'
    label: str = ""

@dataclass
class Edge:
    source: str
    target: str
    relationship: str
    evidence: str = ""
    confirmed: bool = True     # False for LLM-proposed, unverified edges
    confidence: float = 1.0    # 1.0 for deterministic/confirmed evidence
    proposed_by: str = "discovery"   # 'discovery' | 'llm' | 'manual'
```

```python
# storage.py — the ONLY interface layers above storage may depend on
def load_graph(min_confidence: float = 1.0) -> tuple[list[Node], list[Edge]]:
    """Return all nodes, and edges with confidence >= min_confidence.
    Passing min_confidence=1.0 (default) returns only confirmed,
    deterministic edges — i.e. the safe/conservative view."""
    ...

def save_finding(finding: dict) -> None: ...
def save_relationship(edge: Edge) -> None: ...
def confirm_relationship(edge_id: str) -> None:
    """Promote an LLM-proposed edge to confirmed=True, e.g. after a
    human review or a deterministic verification step."""
    ...
```

```python
# graph.py — unchanged from the deterministic core, LLM-agnostic
class AttackGraph:
    def __init__(self, nodes: list[Node], edges: list[Edge]): ...
    def find_all_paths(self, start: str, target: str) -> list[list[Edge]]: ...
    def describe_path(self, path: list[Edge]) -> str: ...
```

---

## 6. Layer specifications

### Layer 1 — Discovery + Evidence Interpretation
**Responsibility:** turn a live environment into `Finding` records.
**Non-LLM part:** run scanners (`nmap`, `requests`, `psycopg2`
introspection), get raw output.
**LLM part:** for evidence that doesn't fit a rigid parser (unfamiliar
banners, HTTP responses, config snippets), send it to an LLM with a
prompt that forces structured JSON output matching the `findings`
schema. Validate the JSON against the schema before storing; reject
and log anything that doesn't parse.
**Key rule:** the LLM here classifies and structures evidence it is
given — it does not decide what to scan or take any action.

### Layer 2 — Relationship Inference
**Responsibility:** turn a set of `Finding`s into candidate `Edge`s.
**Input:** all findings for the environment (from storage).
**Output:** `Edge` objects with `confirmed=False`, a `confidence`
score, and `proposed_by="llm"`.
**Mechanism:** prompt the LLM with the full list of findings and ask
it to identify which pairs of hosts/accounts have an exploitable
relationship, why, and how confident it is. Force JSON output as a
list of `{source, target, relationship_type, evidence, confidence}`
objects. Store every proposed edge — do not silently drop low-
confidence ones; let the confidence field do the filtering downstream.
**Key rule:** this layer never marks its own output as confirmed.
Confirmation happens via deterministic verification (e.g., you
actually test the SSRF and it works) or explicit human review.

### Layer 3 — Storage
**Responsibility:** durable persistence and the `load_graph()` /
`save_*()` / `confirm_relationship()` interface above. No LLM calls
happen here. Every other layer touches the environment through this
interface only — no layer above Storage is allowed to write raw SQL.

### Layer 4 — Graph Engine
**Responsibility:** build an adjacency structure from `Node`/`Edge`
lists. Purely deterministic, no knowledge of scanners, Postgres, or
LLMs. Identical to the original design — this layer should not change
at all as the rest of the system grows.

### Layer 5 — Path Finder
**Responsibility:** deterministic traversal (DFS today; a weighted
shortest-path algorithm once edges carry meaningful cost/likelihood
values later) returning `list[list[Edge]]`. Never calls an LLM.
Confidence-weighted ranking of paths (e.g., a path's overall
confidence = product of its edges' confidence) can live here as a
pure-math addition — still not an LLM call, just arithmetic over
already-produced numbers.

### Layer 6 — CLI / API
**Responsibility:** orchestrate Layers 3–5, expose both a CLI
(`attackmapper analyze --start external --target db`) and eventually
an HTTP API returning JSON, so Layers 7–8 (and any future UI) can
consume results without re-implementing orchestration logic.

### Layer 7 — Risk Narration & Remediation
**Responsibility:** given a `list[Edge]` path from the Path Finder,
produce a plain-English risk explanation and a suggested fix for the
weakest link. Prompt the LLM with the path's edges (relationship
types + evidence strings) and ask for: a one-paragraph narrative, and
a ranked list of remediation suggestions. Output is always presented
as advisory text alongside the raw path — never merged into the graph
data itself, and never auto-applied to the environment.

### Layer 8 — Natural Language Interface
**Responsibility:** translate a user's English question into a call
against Layers 5/6 (e.g. `find_all_paths(start=?, target=?)`), then
hand the raw result to Layer 7's narration logic (or a similar prompt)
to phrase the answer back in English. This is a thin translation
layer — it should not itself contain graph logic; it calls the
existing deterministic functions and formats their output.

---

## 7. LLM integration details

**General pattern for every LLM call in this system:**
1. Build a prompt containing only the structured data needed (never
   raw, un-summarized dumps of everything in the database).
2. Instruct the model to return ONLY JSON matching a specific schema
   — no preamble, no markdown fences.
3. Parse and validate the JSON against that schema in code before
   using it. On failure, log and skip — never guess or partially use
   malformed output.
4. Attach `confidence`/`proposed_by`/`confirmed` fields as specified
   above wherever the call produces graph data.

**Evidence Interpretation — expected output schema:**
```json
{
  "findings": [
    {
      "type": "leaked_credential",
      "severity": "high",
      "description": "Debug endpoint returns a service account token",
      "evidence": "GET /internal/debug returned service_account_token in plaintext",
      "confidence": 0.95
    }
  ]
}
```

**Relationship Inference — expected output schema:**
```json
{
  "relationships": [
    {
      "source": "app",
      "target": "db",
      "relationship_type": "CAN_ACCESS",
      "evidence": "app's DB connection uses a superuser role per finding #12",
      "confidence": 0.9
    }
  ]
}
```

**Natural Language Interface — expected output schema (intent parsing step):**
```json
{
  "intent": "find_path",
  "start": "external",
  "target": "db"
}
```

**Risk Narration — expected output schema:**
```json
{
  "summary": "One paragraph, plain English, no markdown.",
  "weakest_link": "app --RUNS_AS--> service_account",
  "remediations": [
    {"priority": 1, "suggestion": "Scope the app's DB role to read-only access on the customers table."}
  ]
}
```

Keep every prompt template in a dedicated `prompts/` module, one
function per integration point, each returning the fully-formed
prompt string given typed inputs — this keeps prompts versionable and
testable independent of the LLM call plumbing itself.

---

## 8. Suggested repository structure

```
attackmapper/
    models.py            # Node, Edge dataclasses
    storage.py            # load_graph, save_*, confirm_relationship
    graph.py              # AttackGraph, find_all_paths, describe_path
    cli.py                # orchestration + argparse entry point
    discovery/
        scanners.py        # shells out to nmap/requests/psycopg2
        parsers.py          # rigid parsers for well-known formats
        evidence_llm.py     # LLM-backed parsing for ambiguous evidence
    inference/
        relationship_llm.py # findings -> proposed edges
    narration/
        risk_llm.py          # path -> summary + remediation
        nl_interface.py      # English question -> graph call -> English answer
    prompts/
        evidence_interpretation.py
        relationship_inference.py
        risk_narration.py
        nl_query.py
    tests/
        test_graph.py
        test_storage.py
        test_prompts.py      # schema-validation tests using fixture LLM outputs
```

---

## 9. Phased build plan

**Phase A — Deterministic core.** `models.py`, `graph.py`,
`storage.py` (backed initially by hardcoded data, then Postgres),
`cli.py`. Zero LLM calls. This must be solid and tested before any
LLM layer is added — it's the ground truth everything else is judged
against.

**Phase B — Discovery, real evidence.** Scanners + rigid parsers
against the actual lab, feeding Storage directly. Still zero LLM
calls — prove the deterministic pipeline works end-to-end
(lab → discovery → storage → graph → path finder) with hand-verified
relationships before introducing inference.

**Phase C — Relationship inference.** Add `inference/relationship_llm.py`.
Findings already in storage get sent to the LLM; proposed edges come
back and are stored with `confirmed=False`. Extend `load_graph()` to
accept a `min_confidence` parameter. Compare LLM-proposed edges
against the hand-verified ones from Phase B as a sanity check on
quality before trusting the LLM on data you haven't manually verified.

**Phase D — Evidence interpretation upgrade.** Add
`discovery/evidence_llm.py` for ambiguous scan output that rigid
parsers in Phase B couldn't handle. This is additive — rigid parsers
keep handling what they already handle well; the LLM only covers the
gap.

**Phase E — Risk narration and remediation.** Add `narration/risk_llm.py`.
Given a path from the Path Finder, produce the narrative + remediation
JSON described above. Surfaced in the CLI/API output alongside the raw
path, never replacing it.

**Phase F — Natural language interface.** Add
`narration/nl_interface.py`, wrapping Layers 5/6 with intent parsing
and answer narration. This is the primary user-facing surface of the
finished product.

**Phase G — Continuous/agentic discovery (advanced).** Discovery
becomes a loop that decides what to probe next based on findings so
far, automatically re-triggering evidence interpretation and
relationship inference as new data arrives. Requires the most
guardrails: strictly read-only, strictly scoped to authorized
environments, and ideally a human-in-the-loop approval step before any
newly inferred high-confidence relationship is treated as fact.

Build strictly in this order. Each phase should be independently
demoable before starting the next — an LLM layer built on top of an
unproven deterministic core just produces confident-sounding nonsense
faster.

---

## 10. Testing strategy

- **Graph/Path Finder (Phase A):** pure unit tests, no infra —
  disconnected graphs, cyclic graphs, multi-path graphs, zero-path
  cases.
- **Discovery parsers (Phase B):** fixture-based — check checked-in
  sample scanner output against expected parsed `Finding`/`Node`
  output, no live lab required to run these tests.
- **LLM integration points (Phases C–F):** never test against a live
  model call in CI. Instead, test that (a) prompts are built correctly
  from given inputs, and (b) a set of fixture LLM *responses*
  (including deliberately malformed ones) are handled correctly by
  your schema validation and storage code. Validate the LLM's actual
  output quality separately, manually or in an offline eval script —
  don't couple correctness of your code to the nondeterminism of a
  live model in automated tests.
