"""examples/phase_c_demo.py — proves Layer 2 (Relationship Inference)
end to end against real findings:

    lab -> discovery -> storage -> [NEW] LLM relationship inference
        -> compare against a hand-verified baseline -> graph -> path finder

Unlike phase_b_demo.py, this makes one real call to a model via OpenRouter
(needs OPENROUTER_API_KEY set) -- per the master spec, LLM *code* is
tested against fixtures in CI (tests/test_relationship_llm.py), but a
demo script proving the real integration works is exactly what this
phase's "independently demoable" requirement calls for.

Run from the repo root: python3 examples/phase_c_demo.py
"""

import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from attackmapper import storage
from attackmapper.discovery import pipeline
from attackmapper.graph import AttackGraph
from attackmapper.inference import relationship_llm
from attackmapper.models import Edge, Node
from attackmapper.storage import InMemoryStore

REPO_ROOT = Path(__file__).parent.parent


def main() -> None:
    if not os.environ.get("OPENROUTER_API_KEY"):
        print(
            "OPENROUTER_API_KEY is not set -- Layer 2 makes a real LLM call, "
            "so this demo needs it. Set it and re-run:\n"
            "    export OPENROUTER_API_KEY=sk-or-...\n"
            "(Schema validation and the store-as-unconfirmed pipeline are "
            "already covered without a live key in "
            "tests/test_relationship_llm.py.)"
        )
        return

    # Fresh, empty store for this demo -- not the seeded Phase A one.
    storage._default_store = InMemoryStore(seed_demo_data=False)
    storage._default_store._nodes["external"] = Node(
        id="external", type="external", label="Internet"
    )

    print("--- starting a throwaway local HTTP target (127.0.0.1:8765) ---")
    server = subprocess.Popen(
        [sys.executable, str(REPO_ROOT / "lab_http_server.py")],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1)

    try:
        print("\n--- Layer 1: real nmap scan + HTTP probe (unchanged from Phase B) ---")
        pipeline.ingest_nmap_scan("127.0.0.1", ports="8765")
        web_host_id = next(
            h["id"] for h in storage.list_hosts() if h["ip"] == "127.0.0.1"
        )
        pipeline.ingest_http_probe(
            "http://127.0.0.1:8765/internal/debug", web_host_id
        )
        for f in storage.list_findings():
            print(f"  finding: [{f['severity']}] {f['type']}: {f['description']}")

        print(
            "\n--- Layer 2 (NEW, Phase C): the LLM proposes relationships "
            "from those findings ---"
        )
        proposed = relationship_llm.infer_relationships()
        if not proposed:
            print("  the LLM proposed no relationships from this evidence.")
        for e in proposed:
            print(
                f"  proposed: {e.source} -{e.relationship}-> {e.target} "
                f"(conf={e.confidence:.2f}, unconfirmed): {e.evidence}"
            )

        print(
            "\n--- sanity check: same finding, but this time compare against "
            "the Phase B hand-verified edge for the identical scenario ---"
        )
        db_host_id = storage.save_host(
            {"hostname": "db01.lab.internal", "ip": "10.0.3.10", "os": "Linux"}
        )
        storage.save_relationship(
            Edge(
                source="external",
                target=web_host_id,
                relationship="CAN_REACH",
                evidence="nmap: port 8765 open, no ACL",
                confirmed=True,
                confidence=1.0,
                proposed_by="discovery",
            )
        )
        storage.save_relationship(
            Edge(
                source=web_host_id,
                target=db_host_id,
                relationship="CAN_ACCESS",
                evidence=(
                    "analyst verified the leaked service_account_token from "
                    "/internal/debug grants a live DB login (hand-tested)"
                ),
                confirmed=True,
                confidence=1.0,
                proposed_by="manual",
            )
        )
        report = relationship_llm.compare_proposed_to_confirmed()
        print(f"  agrees with hand-verified baseline:      {len(report['agrees'])}")
        print(f"  contradicts hand-verified baseline:      {len(report['contradicts'])}")
        print(f"  novel (no baseline to compare against):  {len(report['novel'])}")

        print(
            "\n--- Layers 4-5: path finder including unconfirmed LLM edges "
            "(min_confidence=0.0) ---"
        )
        nodes, edges = storage.load_graph(min_confidence=0.0)
        graph = AttackGraph(nodes, edges)
        paths = graph.find_all_paths("external", db_host_id)
        print(f"found {len(paths)} path(s) from 'external' to db host:")
        for p in paths:
            print(f"  {graph.describe_path(p)}  (confidence={graph.path_confidence(p):.2f})")

    finally:
        server.terminate()
        server.wait(timeout=5)


if __name__ == "__main__":
    main()
