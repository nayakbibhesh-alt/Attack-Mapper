"""examples/phase_d_demo.py — proves Layer 1's LLM half (Evidence
Interpretation, Phase D) end to end:

    an unfamiliar service banner and an odd config snippet -- exactly
    the kind of evidence discovery/parsers.py's rigid parsers were
    written to leave alone -- go to discovery/evidence_llm.py instead,
    which classifies and stores them as findings with
    source="llm_inferred", never as source="scanner" ground truth.

Unlike phase_b_demo.py, this makes real calls to a model via OpenRouter
(needs OPENROUTER_API_KEY set) -- per the master spec, LLM *code* is
tested against fixtures in CI (tests/test_evidence_llm.py), but a demo
script proving the real integration works is exactly what this
phase's "independently demoable" requirement calls for.

Run from the repo root: python3 examples/phase_d_demo.py
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from attackmapper import storage
from attackmapper.discovery import parsers, pipeline
from attackmapper.storage import InMemoryStore

# A banner nmap could grab, but that KNOWN_VULNERABLE_BANNERS in
# parsers.py has no rule for -- an invented, unfamiliar product/version
# string. Run through the rigid parser's own table first, below, to
# prove it really is a gap before handing it to the LLM.
UNFAMILIAR_BANNER = "GlacierFS-Admin/0.9.1-rc (debug-mode; auth=disabled-by-default)"

# A config snippet -- the other example the master spec names
# explicitly ("config snippets") -- that no rigid parser in this
# project attempts to interpret at all.
CONFIG_SNIPPET = """
# excerpt from /etc/glacierfs/admin.conf on app01
listen 0.0.0.0:9100
require_auth = false
cors_allow_origin = "*"
admin_token_file = "/var/run/glacierfs/admin.token"  # world-readable, 0644
"""


def main() -> None:
    if not os.environ.get("OPENROUTER_API_KEY"):
        print(
            "OPENROUTER_API_KEY is not set -- Layer 1's LLM half makes a real "
            "LLM call, so this demo needs it. Set it and re-run:\n"
            "    export OPENROUTER_API_KEY=sk-or-...\n"
            "(Schema validation and the store-as-llm_inferred pipeline are "
            "already covered without a live key in "
            "tests/test_evidence_llm.py.)"
        )
        return

    # Fresh, empty store for this demo -- not the seeded Phase A one.
    storage._default_store = InMemoryStore(seed_demo_data=False)

    host_id = storage.save_host(
        {"hostname": "app01.lab.internal", "ip": "10.0.2.10", "os": "Linux"}
    )

    print("--- confirming the rigid parser really has no rule for this banner ---")
    rigid_hits = []
    for rule in parsers.KNOWN_VULNERABLE_BANNERS:
        if rule["match"].search(UNFAMILIAR_BANNER):
            rigid_hits.append(rule["type"])
    print(
        f"  KNOWN_VULNERABLE_BANNERS matches: {rigid_hits or '(none -- confirmed gap)'}"
    )

    print(
        "\n--- Layer 1 LLM half (Phase D, NEW): interpreting the unfamiliar "
        "banner ---"
    )
    summary = pipeline.ingest_ambiguous_evidence(host_id, "service_banner", UNFAMILIAR_BANNER)
    print(f"  {summary['findings']} finding(s) stored from the banner")

    print(
        "\n--- Layer 1 LLM half: interpreting a config snippet (the other "
        "example the master spec names) ---"
    )
    summary2 = pipeline.ingest_ambiguous_evidence(host_id, "config_snippet", CONFIG_SNIPPET)
    print(f"  {summary2['findings']} finding(s) stored from the config snippet")

    print("\n--- everything currently in storage for this host ---")
    for f in storage.list_findings():
        if f["host_id"] != host_id:
            continue
        print(
            f"  [{f['severity']}] {f['type']} (source={f['source']}, "
            f"conf={f['confidence']:.2f}): {f['description']}"
        )
        print(f"      evidence: {f['evidence']}")

    print(
        "\nNote: every finding above is source='llm_inferred', never "
        "source='scanner' -- exactly as ground-truth as the LLM's own "
        "confidence score says it is, and no more. A human (or Phase C's "
        "relationship inference, which reads findings regardless of "
        "source) decides what to do with it next."
    )


if __name__ == "__main__":
    main()
