"""examples/phase_e_demo.py — proves Layer 7 (Risk Narration &
Remediation, Phase E) end to end:

    lab -> discovery -> storage -> Layer 2 (relationship inference)
        -> Layers 4-5 (graph + path finder, deterministic, ranked)
        -> [NEW] Layer 7: plain-English narrative + remediations for
           the top-ranked path

Unlike phase_b_demo.py, this makes real calls to a model via OpenRouter
(needs OPENROUTER_API_KEY set) -- schema validation and the
parse-or-reject-whole-response logic are already covered without a
live key in tests/test_risk_llm.py; this demo proves the real
integration works end to end, per the master spec's "independently
demoable" requirement for each phase.

Run from the repo root: python3 examples/phase_e_demo.py
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from attackmapper import storage
from attackmapper.graph import AttackGraph
from attackmapper.narration import risk_llm
from attackmapper.storage import InMemoryStore


def main() -> None:
    if not os.environ.get("OPENROUTER_API_KEY"):
        print(
            "OPENROUTER_API_KEY is not set -- Layer 7 makes a real LLM call, "
            "so this demo needs it. Set it and re-run:\n"
            "    export OPENROUTER_API_KEY=sk-or-...\n"
            "(Schema validation and the narrate-path pipeline are already "
            "covered without a live key in tests/test_risk_llm.py.)"
        )
        return

    # The seeded Phase A demo topology already tells exactly the story
    # the master spec's own worked example uses (external -> web -> app
    # -> svc_account -> db -> customer_db), so it doubles as a
    # ready-made Layer 7 fixture -- no need to re-run discovery here.
    storage._default_store = InMemoryStore(seed_demo_data=True)

    print(
        "--- Layers 4-5 (unchanged, deterministic): find + rank paths "
        "from 'external' to 'customer_db' ---"
    )
    nodes, edges = storage.load_graph(min_confidence=0.0)  # include the
    # unconfirmed LLM-proposed shortcut edge too, so Layer 7 has an
    # unconfirmed hop to demonstrate its "UNCONFIRMED" handling on.
    graph = AttackGraph(nodes, edges)
    paths = graph.find_all_paths("external", "customer_db")
    ranked = sorted(paths, key=AttackGraph.path_confidence, reverse=True)

    print(f"found {len(ranked)} path(s):")
    for i, p in enumerate(ranked, start=1):
        print(
            f"  [{i}] confidence={graph.path_confidence(p):.2f}  "
            f"{graph.describe_path(p)}"
        )

    top_path = ranked[0]
    print(
        f"\n--- Layer 7 (NEW, Phase E): narrating path [1] "
        f"({len(top_path)} hop(s)) ---"
    )
    narration = risk_llm.narrate_path(top_path, nodes)
    if narration is None:
        print("  the LLM produced no usable narrative for this path.")
        return

    print(f"\nSummary:\n  {narration['summary']}")
    print(f"\nWeakest link:\n  {narration['weakest_link']}")
    print("\nSuggested fixes, in order:")
    for r in narration["remediations"]:
        print(f"  {r['priority']}. {r['suggestion']}")

    print(
        "\nNote: none of the above was written back to storage -- Layer 7 "
        "has no write path into storage.py at all. The raw path above "
        "(computed entirely by Layers 4-5) is the ground truth; this "
        "narrative is advisory text a human reads alongside it."
    )

    print(
        "\n--- for comparison, the lowest-confidence path (if more than "
        "one exists) ---"
    )
    if len(ranked) > 1:
        low_path = ranked[-1]
        print(f"  {graph.describe_path(low_path)}")
        low_narration = risk_llm.narrate_path(low_path, nodes)
        if low_narration:
            print(f"  weakest link: {low_narration['weakest_link']}")
    else:
        print("  (only one path exists between these nodes in the demo data)")


if __name__ == "__main__":
    main()
