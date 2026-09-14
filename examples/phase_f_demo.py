"""examples/phase_f_demo.py — proves Layer 8 (Natural Language
Interface, Phase F) end to end:

    English question -> [NEW] intent parsing (LLM)
        -> Layers 4-5 (graph + path finder, deterministic, unchanged)
        -> Layer 7 (risk narration, reused as-is)
        -> English answer

This is the exact question from the master spec's own Vision section
("how could someone get to our customer database from the internet?")
run against the same seeded demo topology phase_e_demo.py uses, plus a
couple of questions chosen to show the "unknown"/no-path/graceful-
decline paths that don't need a full narration call.

Unlike phase_b_demo.py, this makes real calls to a model via OpenRouter
(needs OPENROUTER_API_KEY set) -- schema validation and the full ask()
pipeline are already covered without a live key in
tests/test_nl_interface.py; this demo proves the real integration
works end to end, per the master spec's "independently demoable"
requirement for each phase.

Run from the repo root: python3 examples/phase_f_demo.py
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from attackmapper import storage
from attackmapper.narration import nl_interface
from attackmapper.storage import InMemoryStore


def _ask_and_print(question: str) -> None:
    print(f"\n> {question}")
    result = nl_interface.ask(question)
    print(f"  {result['answer']}")
    if result["intent"] == "find_path" and result["answered"] and result["narration"]:
        print(f"\n  Weakest link: {result['narration']['weakest_link']}")
        print("  Suggested fixes, in order:")
        for r in result["narration"]["remediations"]:
            print(f"    {r['priority']}. {r['suggestion']}")


def main() -> None:
    if not os.environ.get("OPENROUTER_API_KEY"):
        print(
            "OPENROUTER_API_KEY is not set -- Layer 8 makes real LLM calls "
            "(intent parsing, then Layer 7's narration), so this demo "
            "needs it. Set it and re-run:\n"
            "    export OPENROUTER_API_KEY=sk-or-...\n"
            "(The full ask() pipeline is already covered without a live "
            "key in tests/test_nl_interface.py.)"
        )
        return

    # Same seeded Phase A demo topology phase_e_demo.py uses -- it
    # already tells exactly the story the master spec's own Vision
    # section describes, so it doubles as a ready-made Layer 8
    # fixture.
    storage._default_store = InMemoryStore(seed_demo_data=True)

    print(
        "--- Layer 8 (NEW, Phase F): the primary user-facing surface -- "
        "plain English in, plain English out ---"
    )

    # The exact question from ATTACKMAPPER_MASTER.md section 1.
    _ask_and_print(
        "how could someone get to our customer database from the internet?"
    )

    # A question the seeded topology has no answer for in either
    # direction -- proves ask() reports "no path" cleanly rather than
    # hallucinating one, and does it without spending a Layer 7 call.
    _ask_and_print("can the database reach the internet?")

    # A question that doesn't resolve to two known nodes at all -- the
    # intent parser should decline rather than guess, and again no
    # Layer 7 call happens.
    _ask_and_print("what's the weather like today?")

    print(
        "\nNote: every answer above came from the exact same "
        "AttackGraph.find_all_paths() Layers 4-5 use everywhere else in "
        "this system -- Layer 8 has no path-finding logic of its own, "
        "it only translates English in and out around it."
    )


if __name__ == "__main__":
    main()
