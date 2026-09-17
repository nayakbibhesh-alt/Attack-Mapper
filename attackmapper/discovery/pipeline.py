"""discovery/pipeline.py — the only place in Layer 1 that touches both
"the real world" (scanners.py) and storage (storage.py). scanners.py
and parsers.py individually never import storage, which is what keeps
parsers unit-testable on pure fixtures. No LLM calls happen here
either — this whole module is Phase B territory.
"""

from __future__ import annotations

import shutil
import socket
from urllib.parse import urlsplit

from .. import storage
from ..graph import AttackGraph
from ..models import Edge
from . import evidence_llm, parsers, scanners


def ingest_nmap_scan(target: str, ports: str = "1-1024") -> dict:
    """Run a real nmap scan, parse it, and persist hosts/services/
    findings. Returns a small summary dict for the caller (e.g. the
    CLI) to print."""
    xml_text = scanners.run_nmap_scan(target, ports=ports)
    return ingest_nmap_xml(xml_text)


def ingest_nmap_xml(xml_text: str) -> dict:
    """Same as ingest_nmap_scan but takes already-captured XML —
    useful for replaying a saved scan, and what the fixture-based
    tests exercise instead of calling nmap live."""
    hosts, services, findings = parsers.parse_nmap_xml(xml_text)

    ip_to_host_id: dict[str, str] = {}
    for h in hosts:
        host_id = storage.save_host(
            {"hostname": h["hostname"], "ip": h["ip"], "os": h["os"]}
        )
        ip_to_host_id[h["ip"]] = host_id

    stored_services = 0
    for s in services:
        host_id = ip_to_host_id.get(s["ip"])
        if host_id:
            storage.save_service(
                {
                    "host_id": host_id,
                    "port": s["port"],
                    "protocol": s["protocol"],
                    "service_name": s["service_name"],
                }
            )
            stored_services += 1

    stored_findings = 0
    for f in findings:
        host_id = ip_to_host_id.get(f["ip"])
        if host_id:
            storage.save_finding({k: v for k, v in f.items() if k != "ip"} | {"host_id": host_id})
            stored_findings += 1

    return {
        "hosts": len(hosts),
        "services": stored_services,
        "findings": stored_findings,
    }


def ingest_http_probe(url: str, host_id: str) -> dict:
    """Probe a URL known to belong to `host_id` and persist any
    findings the rigid parser can extract."""
    probe = scanners.http_probe(url)
    findings = parsers.parse_http_probe(probe)
    for f in findings:
        storage.save_finding({**f, "host_id": host_id})
    return {"findings": len(findings)}


def ingest_postgres_roles(dsn: str, host_id: str) -> dict:
    """Introspect role privileges on the Postgres instance behind
    `dsn` (already known to be `host_id`) and persist findings."""
    rows = scanners.introspect_postgres_roles(dsn)
    findings = parsers.parse_postgres_roles(host_id, rows)
    for f in findings:
        storage.save_finding(f)
    return {"findings": len(findings)}


def ingest_ambiguous_evidence(
    host_id: str, evidence_type: str, raw_evidence: str
) -> dict:
    """Phase D: hand one piece of evidence the rigid parsers in
    parsers.py couldn't confidently classify -- an unfamiliar service
    banner, an HTTP response shape, a config snippet -- to Layer 1's
    LLM half instead.

    This is deliberately a separate, explicit entry point rather than
    a change to ingest_nmap_xml/ingest_http_probe: per the master
    spec, "rigid parsers keep handling what they already handle well;
    the LLM only covers the gap," and the caller (CLI, an analyst
    script, or a future Phase G loop) is the one who knows a given
    piece of evidence fell outside what parsers.py already handles --
    this function doesn't try to detect that automatically.

    Looks up `host_id` in storage so the LLM gets the same host
    context relationship_llm's prompt gets (hostname/ip/os), but
    proceeds even if the host isn't in inventory yet (host=None is a
    valid prompt input).
    """
    host = next(
        (h for h in storage.list_hosts() if h["id"] == host_id), None
    )
    findings = evidence_llm.interpret_evidence(
        host_id, evidence_type, raw_evidence, host=host
    )
    return {"findings": len(findings)}


def scan_target_url(
    target_url: str,
    run_nmap: bool = True,
    nmap_ports: str = "21,22,25,80,443,3306,3389,5432,6379,8080,8443",
) -> dict:
    """The one-box "give me a URL" entry point: runs every read-only
    web-facing probe this module has (HTTP headers/secrets, TLS,
    exposed sensitive paths, CORS, and — if nmap is installed and not
    disabled — a scan of a short list of common ports) against a
    single target, persists everything through the same storage/graph
    layers the CLI and other pipeline functions use, and returns the
    resulting findings plus every attack path the deterministic graph
    engine can currently trace from `external` to this host.

    Every probe here is read-only and unauthenticated-GET-only; this
    function does not attempt exploitation, brute-forcing, or anything
    that writes to the target. Per the project's scope discipline
    (see discovery/scanners.py's module docstring): only point this at
    a target you own or are explicitly authorized to test.
    """
    if "://" not in target_url:
        target_url = f"https://{target_url}"
    parsed = urlsplit(target_url)
    hostname = parsed.hostname
    if not hostname:
        raise RuntimeError(f"could not parse a hostname out of {target_url!r}")

    try:
        ip = socket.gethostbyname(hostname)
    except OSError as exc:
        raise RuntimeError(f"could not resolve {hostname!r}: {exc}") from exc

    host_id = storage.save_host({"hostname": hostname, "ip": ip, "os": None})

    # external -> host: we resolved and reached it just now, which is
    # itself the evidence for this edge -- same "CAN_REACH" semantics
    # nmap-based ingestion uses, just established via a live probe
    # instead of an open-port scan.
    already_linked = any(
        r["source"] == "external" and r["target"] == host_id
        for r in storage.list_relationships()
    )
    if not already_linked:
        storage.save_relationship(
            Edge(
                source="external",
                target=host_id,
                relationship="CAN_REACH",
                evidence=f"{hostname} ({ip}) resolved and responded to recon probes",
                confirmed=True,
                confidence=1.0,
                proposed_by="discovery",
            )
        )

    errors: list[str] = []
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    try:
        probe = scanners.http_probe(target_url)
        for f in parsers.parse_http_probe(probe):
            storage.save_finding({**f, "host_id": host_id})
    except RuntimeError as exc:
        errors.append(str(exc))

    if parsed.scheme == "https":
        try:
            tls_info = scanners.tls_probe(hostname, parsed.port or 443)
            for f in parsers.parse_tls_probe(hostname, tls_info):
                storage.save_finding({**f, "host_id": host_id})
        except RuntimeError as exc:
            errors.append(str(exc))

    try:
        hits = scanners.exposed_paths_probe(base_url)
        for f in parsers.parse_exposed_paths(base_url, hits):
            storage.save_finding({**f, "host_id": host_id})
    except RuntimeError as exc:
        errors.append(str(exc))

    try:
        cors_info = scanners.cors_probe(target_url)
        for f in parsers.parse_cors_probe(target_url, cors_info):
            storage.save_finding({**f, "host_id": host_id})
    except RuntimeError as exc:
        errors.append(str(exc))

    if run_nmap and shutil.which("nmap"):
        try:
            xml_text = scanners.run_nmap_scan(ip, ports=nmap_ports, timeout=90.0)
            _, services, nmap_findings = parsers.parse_nmap_xml(xml_text)
            for s in services:
                storage.save_service(
                    {
                        "host_id": host_id,
                        "port": s["port"],
                        "protocol": s["protocol"],
                        "service_name": s["service_name"],
                    }
                )
            for f in nmap_findings:
                storage.save_finding(
                    {k: v for k, v in f.items() if k != "ip"} | {"host_id": host_id}
                )
        except RuntimeError as exc:
            errors.append(str(exc))
    elif run_nmap:
        errors.append("nmap is not installed -- skipped the port scan step")

    findings = [f for f in storage.list_findings() if f["host_id"] == host_id]

    nodes, edges = storage.load_graph(min_confidence=0.0)
    graph = AttackGraph(nodes, edges)
    paths = graph.find_all_paths("external", host_id)
    ranked_paths = sorted(paths, key=AttackGraph.path_confidence, reverse=True)

    return {
        "target": target_url,
        "hostname": hostname,
        "ip": ip,
        "host_id": host_id,
        "findings": findings,
        "paths": ranked_paths,
        "errors": errors,
    }
