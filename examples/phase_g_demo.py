"""examples/phase_g_demo.py — proves Phase G (continuous/agentic
discovery) end to end against a real, throwaway local target:

    LLM decides what to probe next
        -> existing Layer 1 pipeline functions (real nmap scan, real
           HTTP probe -- same functions phase_b_demo.py calls by hand)
        -> Layer 2 (relationship inference) re-triggered automatically
        -> a human-review queue of unconfirmed, high-confidence edges
           at the end (never auto-confirmed)

The whole point of this demo is the scope guardrail: it deliberately
authorizes only the throwaway lab server's own address, then shows
that the loop only ever touches that target even though the model is
never told exactly what's out there — "read-only, strictly scoped" is
enforced structurally, not by asking nicely.

Makes real calls to a model via OpenRouter (needs OPENROUTER_API_KEY set)
and runs a real nmap scan / real HTTP probe against 127.0.0.1 -- the
same throwaway local server phase_b_demo.py uses, so nothing outside
this machine is ever touched. Schema validation and scope enforcement
are already covered without a live key or a live scan in
tests/test_agentic_loop.py; this demo proves the real integration
works end to end, per the master spec's "independently demoable"
requirement for each phase.

Run from the repo root: python3 examples/phase_g_demo.py
"""

import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from attackmapper import storage
from attackmapper.discovery import agentic_loop
from attackmapper.storage import InMemoryStore

REPO_ROOT = Path(__file__).parent.parent


def main() -> None:
    if not os.environ.get("OPENROUTER_API_KEY"):
        print(
            "OPENROUTER_API_KEY is not set -- Phase G makes real LLM calls "
            "(probe selection, then Layer 2's relationship inference if "
            "anything new is found), so this demo needs it. Set it and "
            "re-run:\n"
            "    export OPENROUTER_API_KEY=sk-or-...\n"
            "(The full run_discovery_loop() pipeline, including scope "
            "enforcement, is already covered without a live key or a live "
            "scan in tests/test_agentic_loop.py.)"
        )
        return

    # Fresh, empty store for this demo -- not the seeded Phase A one,
    # so the model has to actually discover the lab target itself
    # rather than reasoning over a pre-populated inventory.
    storage._default_store = InMemoryStore(seed_demo_data=False)

    print("--- starting a throwaway local HTTP target (127.0.0.1:8765) ---")
    server = subprocess.Popen(
        [sys.executable, str(REPO_ROOT / "lab_http_server.py")],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1)

    try:
        # The load-bearing line in this whole demo: an explicit,
        # narrow authorization scope. Nothing outside "127.0.0.1" is
        # ever probed, no matter what the model proposes -- per the
        # master spec's non-negotiable scope-discipline principle.
        scope = ["127.0.0.1"]

        print(f"\n--- Phase G: running the agentic discovery loop, scope={scope} ---")
        result = agentic_loop.run_discovery_loop(
            scope,
            max_iterations=4,
            max_actions_per_iteration=2,
            review_threshold=0.6,
        )

        for it in result["iterations"]:
            print(f"\n[iteration {it['iteration']}]")
            if it["stopped"] and not it["actions_taken"]:
                print("  model proposed stopping -- no actions taken.")
                continue
            for t in it["actions_taken"]:
                status = "ran" if t["executed"] else f"SKIPPED ({t.get('reason')})"
                print(f"  [{status}] {t['action_type']} target={t.get('target')}")
                print(f"           rationale: {t['rationale']}")
                if t.get("executed"):
                    print(f"           result: {t['result']}")
            if it["new_relationships_proposed"]:
                print(
                    f"  -> relationship inference re-ran automatically: "
                    f"{it['new_relationships_proposed']} new proposal(s)"
                )

        print(f"\n--- current inventory after the loop ---")
        for h in storage.list_hosts():
            print(f"  host {h['id']}: {h['ip']} ({h.get('hostname')})")
        for f in storage.list_findings():
            print(f"  finding: [{f['severity']}] {f['type']}: {f['description']}")

        pending = result["pending_review"]
        print(
            f"\n--- human-in-the-loop queue: {len(pending)} unconfirmed "
            f"relationship(s) at/above confidence 0.60 ---"
        )
        for r in pending:
            print(
                f"  {r['id']}: {r['source']} -{r['relationship']}-> {r['target']} "
                f"(confidence={r['confidence']:.2f}): {r['evidence']}"
            )
            print(
                "    -> still confirmed=False; a human would run "
                f"`attackmapper confirm {r['id']}` after verifying this by hand."
            )
        if not pending:
            print("  (none yet at this confidence threshold)")

    finally:
        server.terminate()
        server.wait(timeout=5)

    print(
        "\nNote: every probe above went through the exact same "
        "discovery.pipeline.ingest_* functions Phases B/D already use by "
        "hand, and nothing was ever confirmed automatically -- Phase G "
        "only automates *deciding what to run next and when to re-check "
        "relationships*, not trust."
    )


if __name__ == "__main__":
    main()
