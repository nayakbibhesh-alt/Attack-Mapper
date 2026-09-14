"""discovery/pipeline.py — the only place in Layer 1 that touches both
"the real world" (scanners.py) and storage (storage.py). scanners.py
and parsers.py individually never import storage, which is what keeps
parsers unit-testable on pure fixtures. No LLM calls happen here
either — this whole module is Phase B territory.
"""

from __future__ import annotations

from .. import storage
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
