"""cli.py — Layer 6: orchestration + argparse entry point.

Orchestrates Layers 3-5 (storage -> graph -> path finder) and prints
results. Zero LLM calls in Phase A. `analyze` is the primary command;
`nodes`/`edges`/`findings` are small inspection commands that make the
in-memory demo data (and later, Postgres data) easy to poke at from a
terminal while building the rest of the system.
"""

from __future__ import annotations

import argparse
import sys

from . import storage
from .graph import AttackGraph


def cmd_analyze(args: argparse.Namespace) -> int:
    nodes, edges = storage.load_graph(min_confidence=args.min_confidence)
    node_ids = {n.id for n in nodes}

    if args.start not in node_ids:
        print(f"error: unknown start node {args.start!r}", file=sys.stderr)
        print(f"known nodes: {sorted(node_ids)}", file=sys.stderr)
        return 1
    if args.target not in node_ids:
        print(f"error: unknown target node {args.target!r}", file=sys.stderr)
        print(f"known nodes: {sorted(node_ids)}", file=sys.stderr)
        return 1

    graph = AttackGraph(nodes, edges)
    paths = graph.find_all_paths(args.start, args.target)

    if not paths:
        print(
            f"No path found from {args.start!r} to {args.target!r} "
            f"at min_confidence={args.min_confidence}."
        )
        if args.min_confidence >= 1.0:
            print(
                "(Try --min-confidence below 1.0 to include unconfirmed, "
                "LLM-proposed edges.)"
            )
        return 0

    ranked = sorted(paths, key=AttackGraph.path_confidence, reverse=True)

    print(
        f"Found {len(ranked)} path(s) from {args.start!r} to {args.target!r} "
        f"(min_confidence={args.min_confidence}):\n"
    )
    for i, path in enumerate(ranked, start=1):
        conf = AttackGraph.path_confidence(path)
        print(f"[{i}] confidence={conf:.2f}  ({len(path)} hop(s))")
        print(f"    {graph.describe_path(path)}")
        unconfirmed = [e for e in path if not e.confirmed]
        if unconfirmed:
            print(f"    ! includes {len(unconfirmed)} unconfirmed edge(s):")
            for e in unconfirmed:
                print(
                    f"      - {e.source} -{e.relationship}-> {e.target} "
                    f"(conf={e.confidence:.2f}, proposed_by={e.proposed_by}): "
                    f"{e.evidence}"
                )
        print()

    if args.narrate:
        from .narration import risk_llm

        top_path = ranked[0]
        print(f"--- Layer 7: risk narration for path [1] (highest confidence) ---")
        try:
            narration = risk_llm.narrate_path(top_path, nodes)
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        if narration is None:
            print("(the LLM produced no usable narrative for this path)")
            return 0
        print(f"\n{narration['summary']}\n")
        print(f"Weakest link: {narration['weakest_link']}\n")
        print("Suggested fixes, in order:")
        for r in narration["remediations"]:
            print(f"  {r['priority']}. {r['suggestion']}")

    return 0


def cmd_nodes(args: argparse.Namespace) -> int:
    nodes, _ = storage.load_graph(min_confidence=0.0)
    for n in sorted(nodes, key=lambda n: n.id):
        print(f"{n.id:15s} type={n.type:10s} {n.label}")
    return 0


def cmd_edges(args: argparse.Namespace) -> int:
    confirmed_filter = {"all": None, "confirmed": True, "unconfirmed": False}[
        args.filter
    ]
    rels = storage.list_relationships(confirmed=confirmed_filter)
    for r in rels:
        flag = "confirmed" if r["confirmed"] else f"proposed({r['proposed_by']})"
        print(
            f"{r['id']:10s} {r['source']} -{r['relationship']}-> {r['target']} "
            f"conf={r['confidence']:.2f} [{flag}]"
        )
    return 0


def cmd_hosts(args: argparse.Namespace) -> int:
    for h in storage.list_hosts():
        print(f"{h['id']:10s} {h['ip']:15s} {h['hostname']:25s} os={h.get('os')}")
    return 0


def cmd_services(args: argparse.Namespace) -> int:
    for s in storage.list_services(host_id=args.host_id):
        print(
            f"{s['host_id']:10s} {s['port']:>5d}/{s['protocol']:3s} {s['service_name']}"
        )
    return 0


def cmd_scan_nmap(args: argparse.Namespace) -> int:
    from .discovery import pipeline

    try:
        summary = pipeline.ingest_nmap_scan(args.target, ports=args.ports)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(
        f"scanned {args.target}: {summary['hosts']} host(s), "
        f"{summary['services']} service(s), {summary['findings']} finding(s)"
    )
    return 0


def cmd_scan_url(args: argparse.Namespace) -> int:
    from . import remediation
    from .discovery import pipeline

    try:
        result = pipeline.scan_target_url(args.target, run_nmap=not args.no_nmap)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"target: {result['target']}  ({result['hostname']} -> {result['ip']})\n")

    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings = sorted(
        result["findings"], key=lambda f: severity_rank.get(f.get("severity"), 4)
    )
    if findings:
        print(f"findings ({len(findings)}):")
        for f in findings:
            print(f"  [{f['severity'].upper():8s}] {f['type']}: {f['description']}")
            print(f"             remedy: {remediation.remedy_for(f['type'])}")
    else:
        print("findings: none")

    print(f"\nattack paths from external to this host ({len(result['paths'])}):")
    graph = AttackGraph([], [])  # only used for its (static) describe_path/path_confidence
    for path in result["paths"]:
        print(f"  ({graph.path_confidence(path):.2f}) {graph.describe_path(path)}")

    for err in result["errors"]:
        print(f"note: {err}", file=sys.stderr)
    return 0


def cmd_interpret(args: argparse.Namespace) -> int:
    from .discovery import pipeline

    if args.file:
        with open(args.file, encoding="utf-8", errors="replace") as fh:
            raw_evidence = fh.read()
    else:
        raw_evidence = args.text

    try:
        summary = pipeline.ingest_ambiguous_evidence(
            args.host_id, args.evidence_type, raw_evidence
        )
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(
        f"evidence interpretation for host {args.host_id}: "
        f"{summary['findings']} finding(s) stored (source=llm_inferred)"
    )
    if summary["findings"]:
        for f in storage.list_findings():
            if f["host_id"] == args.host_id and f["source"] == "llm_inferred":
                print(
                    f"  [{f['severity']}] {f['type']} "
                    f"(conf={f['confidence']:.2f}): {f['description']}"
                )
    return 0


def cmd_infer(args: argparse.Namespace) -> int:
    from .inference import relationship_llm

    try:
        proposed = relationship_llm.infer_relationships()
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if not proposed:
        print("no new relationships proposed (no findings, or LLM found nothing).")
        return 0

    print(f"proposed {len(proposed)} new relationship(s), stored as unconfirmed:\n")
    for e in proposed:
        print(
            f"  {e.source} -{e.relationship}-> {e.target} "
            f"(conf={e.confidence:.2f}): {e.evidence}"
        )

    if args.compare:
        report = relationship_llm.compare_proposed_to_confirmed(proposed)
        print("\nsanity check against hand-verified (confirmed) relationships:")
        print(f"  agrees:      {len(report['agrees'])}")
        print(f"  contradicts: {len(report['contradicts'])}")
        for e in report["contradicts"]:
            print(
                f"    ! {e.source} -{e.relationship}-> {e.target} "
                f"conflicts with a confirmed relationship for that pair"
            )
        print(f"  novel:       {len(report['novel'])}")
    return 0


def cmd_ask(args: argparse.Namespace) -> int:
    from .narration import nl_interface

    try:
        result = nl_interface.ask(args.question, min_confidence=args.min_confidence)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(result["answer"])

    if result["intent"] == "find_path" and result["answered"]:
        print(f"\n(resolved to: {result['start']} -> {result['target']}, "
              f"{result['paths_found']} path(s) found)")
        narration = result["narration"]
        if narration is not None:
            print(f"\nWeakest link: {narration['weakest_link']}")
            print("Suggested fixes, in order:")
            for r in narration["remediations"]:
                print(f"  {r['priority']}. {r['suggestion']}")
    return 0


def cmd_discover(args: argparse.Namespace) -> int:
    from .discovery import agentic_loop

    try:
        result = agentic_loop.run_discovery_loop(
            args.scope,
            max_iterations=args.max_iterations,
            max_actions_per_iteration=args.max_actions,
            review_threshold=args.review_threshold,
        )
    except (agentic_loop.ScopeError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"authorized scope: {result['scope']}\n")
    for it in result["iterations"]:
        print(f"--- iteration {it['iteration']} ---")
        if it["stopped"] and not it["actions_taken"]:
            print("  model proposed stopping; no actions taken.")
            continue
        for t in it["actions_taken"]:
            status = "ran" if t["executed"] else f"SKIPPED ({t.get('reason')})"
            target = t.get("target")
            print(f"  [{status}] {t['action_type']} target={target}")
            print(f"           rationale: {t['rationale']}")
            if t.get("executed"):
                print(f"           result: {t['result']}")
        if it["new_relationships_proposed"]:
            print(
                f"  -> relationship inference re-ran: "
                f"{it['new_relationships_proposed']} new proposal(s)"
            )
        print()

    pending = result["pending_review"]
    if pending:
        print(
            f"{len(pending)} unconfirmed relationship(s) at/above "
            f"confidence {args.review_threshold:.2f} awaiting human review "
            f"(nothing here has been auto-confirmed):\n"
        )
        for r in pending:
            print(
                f"  {r['id']:10s} {r['source']} -{r['relationship']}-> "
                f"{r['target']} conf={r['confidence']:.2f} "
                f"proposed_by={r['proposed_by']}: {r['evidence']}"
            )
        print(
            "\nReview with `attackmapper edges --filter unconfirmed`, then "
            "`attackmapper confirm <id>` for anything you've verified."
        )
    else:
        print("no unconfirmed relationships currently meet the review threshold.")

    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    from . import webapp

    webapp.main(host=args.host, port=args.port, open_browser=not args.no_browser)
    return 0


def cmd_confirm(args: argparse.Namespace) -> int:
    try:
        storage.confirm_relationship(args.edge_id)
    except KeyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"confirmed {args.edge_id}")
    return 0


def cmd_seed_demo(args: argparse.Namespace) -> int:
    storage.seed_demo_data()
    print(
        "loaded the demo topology (external -> web -> app -> svc_account "
        "-> db -> customer_db) into the current store."
    )
    print("try: attackmapper analyze --start external --target db")
    return 0


def cmd_reset(args: argparse.Namespace) -> int:
    if not args.yes:
        answer = input(
            "This clears every host, service, finding, and relationship "
            "from the current store (keeping only the 'external' node). "
            "Type 'yes' to continue: "
        )
        if answer.strip().lower() != "yes":
            print("aborted, nothing was changed.")
            return 1
    storage.reset()
    print("store reset.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="attackmapper",
        description="Continuously map and rank realistic attack paths "
        "through an authorized environment.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_analyze = sub.add_parser(
        "analyze", help="find and rank attack paths between two nodes"
    )
    p_analyze.add_argument("--start", required=True, help="starting node id")
    p_analyze.add_argument("--target", required=True, help="target node id")
    p_analyze.add_argument(
        "--min-confidence",
        type=float,
        default=1.0,
        dest="min_confidence",
        help="minimum edge confidence to include (default 1.0 = confirmed only)",
    )
    p_analyze.add_argument(
        "--narrate",
        action="store_true",
        help="also produce a plain-English risk narrative + remediation "
        "suggestions for the top-ranked path via LLM (Layer 7)",
    )
    p_analyze.set_defaults(func=cmd_analyze)

    p_nodes = sub.add_parser("nodes", help="list all known nodes")
    p_nodes.set_defaults(func=cmd_nodes)

    p_edges = sub.add_parser("edges", help="list all known relationships")
    p_edges.add_argument(
        "--filter",
        choices=["all", "confirmed", "unconfirmed"],
        default="all",
    )
    p_edges.set_defaults(func=cmd_edges)

    p_interpret = sub.add_parser(
        "interpret-evidence",
        help="classify one piece of ambiguous evidence via LLM (Layer 1)",
    )
    p_interpret.add_argument(
        "--host-id", required=True, dest="host_id", help="host this evidence came from"
    )
    p_interpret.add_argument(
        "--type",
        required=True,
        dest="evidence_type",
        help="short label, e.g. service_banner, http_response, config_snippet",
    )
    group = p_interpret.add_mutually_exclusive_group(required=True)
    group.add_argument("--text", help="the raw evidence text")
    group.add_argument("--file", help="path to a file containing the raw evidence")
    p_interpret.set_defaults(func=cmd_interpret)

    p_infer = sub.add_parser(
        "infer",
        help="propose new relationships from stored findings via LLM (Layer 2)",
    )
    p_infer.add_argument(
        "--compare",
        action="store_true",
        help="also compare proposals against confirmed relationships",
    )
    p_infer.set_defaults(func=cmd_infer)

    p_confirm = sub.add_parser(
        "confirm", help="promote a proposed relationship to confirmed"
    )
    p_confirm.add_argument("edge_id")
    p_confirm.set_defaults(func=cmd_confirm)

    p_seed_demo = sub.add_parser(
        "seed-demo",
        help="load the hand-verified demo topology into the current store "
        "(additive, opt-in -- a fresh store starts empty)",
    )
    p_seed_demo.set_defaults(func=cmd_seed_demo)

    p_reset = sub.add_parser(
        "reset",
        help="wipe the current store back to empty (asks for confirmation "
        "unless --yes is given)",
    )
    p_reset.add_argument(
        "--yes", action="store_true", help="skip the confirmation prompt"
    )
    p_reset.set_defaults(func=cmd_reset)

    p_serve = sub.add_parser(
        "serve", help="launch the browser UI (Layer 6, same store as this CLI)"
    )
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8765)
    p_serve.add_argument("--no-browser", action="store_true", dest="no_browser")
    p_serve.set_defaults(func=cmd_serve)

    p_hosts = sub.add_parser("hosts", help="list discovered hosts")
    p_hosts.set_defaults(func=cmd_hosts)

    p_services = sub.add_parser("services", help="list discovered services")
    p_services.add_argument("--host-id", dest="host_id", default=None)
    p_services.set_defaults(func=cmd_services)

    p_scan = sub.add_parser("scan-nmap", help="run a real nmap scan and store results")
    p_scan.add_argument("--target", required=True)
    p_scan.add_argument("--ports", default="1-1024")
    p_scan.set_defaults(func=cmd_scan_nmap)

    p_scan_url = sub.add_parser(
        "scan-url",
        help="run every read-only web probe (headers, TLS, exposed paths, "
        "CORS, nmap) against a target URL and report findings + attack paths",
    )
    p_scan_url.add_argument("--target", required=True, help="e.g. https://example.com")
    p_scan_url.add_argument(
        "--no-nmap", action="store_true", help="skip the nmap port-scan step"
    )
    p_scan_url.set_defaults(func=cmd_scan_url)

    p_ask = sub.add_parser(
        "ask",
        help="ask an English question about attack paths (Layer 8)",
    )
    p_ask.add_argument("question", help="e.g. 'how could someone reach the db from the internet?'")
    p_ask.add_argument(
        "--min-confidence",
        type=float,
        default=1.0,
        dest="min_confidence",
        help="minimum edge confidence to include (default 1.0 = confirmed only)",
    )
    p_ask.set_defaults(func=cmd_ask)

    p_discover = sub.add_parser(
        "discover",
        help="run the continuous/agentic discovery loop (Phase G, read-only, "
        "strictly scoped)",
    )
    p_discover.add_argument(
        "--scope",
        required=True,
        nargs="+",
        help="explicit authorization scope: one or more exact hostnames/IPs "
        "and/or CIDR blocks (e.g. --scope 10.0.1.10 10.0.2.0/24). No target "
        "outside this list is ever probed, regardless of what the model "
        "proposes.",
    )
    p_discover.add_argument(
        "--max-iterations",
        type=int,
        default=5,
        dest="max_iterations",
        help="stop after this many probe/inference rounds even if the model "
        "keeps finding leads (default: 5)",
    )
    p_discover.add_argument(
        "--max-actions",
        type=int,
        default=3,
        dest="max_actions",
        help="cap on probes executed per iteration (default: 3)",
    )
    p_discover.add_argument(
        "--review-threshold",
        type=float,
        default=0.75,
        dest="review_threshold",
        help="surface unconfirmed relationships at/above this confidence as "
        "needing priority human review (default: 0.75); nothing is ever "
        "auto-confirmed regardless of this value",
    )
    p_discover.set_defaults(func=cmd_discover)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
