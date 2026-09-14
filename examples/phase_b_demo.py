"""examples/phase_b_demo.py — proves the full pipeline end to end:

    lab -> discovery -> storage -> graph -> path finder

with real scanner output and hand-verified relationships, per the
Phase B build note: "prove the deterministic pipeline works end-to-end
... with hand-verified relationships before introducing inference."

Still zero LLM calls. Relationships below are added the way a human
analyst would after reading the findings — that's the point: nothing
here is inferred automatically. That automation is Phase C's job.

Run from the repo root: python3 examples/phase_b_demo.py
"""

import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from attackmapper import storage
from attackmapper.discovery import pipeline
from attackmapper.graph import AttackGraph
from attackmapper.models import Edge
from attackmapper.storage import InMemoryStore

REPO_ROOT = Path(__file__).parent.parent


def main() -> None:
    # Fresh, empty store for this demo -- not the seeded Phase A one.
    storage._default_store = InMemoryStore(seed_demo_data=False)

    print("--- starting a throwaway local HTTP target (127.0.0.1:8765) ---")
    server = subprocess.Popen(
        [sys.executable, str(REPO_ROOT / "lab_http_server.py")],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1)

    try:
        print("\n--- Layer 1: real nmap scan against the live target ---")
        summary = pipeline.ingest_nmap_scan("127.0.0.1", ports="8765")
        print(f"scan summary: {summary}")

        web_host_id = next(
            h["id"] for h in storage.list_hosts() if h["ip"] == "127.0.0.1"
        )

        print("\n--- Layer 1: real HTTP probe against the live target ---")
        probe_summary = pipeline.ingest_http_probe(
            "http://127.0.0.1:8765/internal/debug", web_host_id
        )
        print(f"probe summary: {probe_summary}")
        for f in storage.list_findings():
            print(f"  finding: [{f['severity']}] {f['type']}: {f['description']}")

        print("\n--- Layer 2 (simulated by hand, per Phase B): "
              "an analyst reads the finding and adds a verified edge ---")
        # A human read the leaked_credential finding above, confirmed
        # by hand that the leaked token is valid and grants DB access,
        # and records that as a CONFIRMED edge (not an LLM proposal --
        # that automation is Phase C).
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
                    "/internal/debug grants a live DB login (hand-tested "
                    "2026-09-13)"
                ),
                confirmed=True,
                confidence=1.0,
                proposed_by="manual",
            )
        )
        # 'external' is a virtual node the graph engine can traverse
        # from even though nothing "discovered" it -- add it explicitly.
        from attackmapper.models import Node

        storage._default_store._nodes["external"] = Node(
            id="external", type="external", label="Internet"
        )

        print("\n--- Layers 4-5: deterministic graph + path finder ---")
        nodes, edges = storage.load_graph(min_confidence=1.0)
        graph = AttackGraph(nodes, edges)
        paths = graph.find_all_paths("external", db_host_id)
        print(f"found {len(paths)} confirmed path(s) from 'external' to db host:")
        labels = {n.id: n.label or n.id for n in nodes}
        for p in paths:
            readable = " -> ".join(
                [labels.get(p[0].source, p[0].source)]
                + [f"[{e.relationship}] {labels.get(e.target, e.target)}" for e in p]
            )
            print(f"  {readable}  (confidence={graph.path_confidence(p):.2f})")

    finally:
        server.terminate()
        server.wait(timeout=5)


if __name__ == "__main__":
    main()
