"""discovery/parsers.py — rigid parsers for well-known scanner output
formats (Layer 1's non-LLM interpretation path).

Every function here is a pure function: raw text/dict in, plain dicts
out, ready to hand to storage.save_host/save_service/save_finding. No
network calls, no LLM calls, no side effects — which is exactly what
makes these fixture-testable with no live lab required (see
tests/fixtures/ and tests/test_parsers.py, matching the testing
strategy in the master spec).

Evidence that doesn't fit these rigid shapes — an unfamiliar banner, a
config snippet in a format not handled below — is left alone here.
That gap is Phase D's discovery/evidence_llm.py, not this module's
job: rigid parsers should never guess.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

# ---------------------------------------------------------------------
# A small, illustrative table of known-vulnerable service banners. This
# is exactly the kind of evidence a rigid parser CAN handle
# deterministically: an exact version string tied to a well-documented,
# publicly known issue. Genuinely ambiguous/unfamiliar banners are NOT
# handled here — see the module docstring. Detection/classification
# only; no exploitation details are included or needed.
# ---------------------------------------------------------------------
KNOWN_VULNERABLE_BANNERS = [
    {
        "match": re.compile(r"vsftpd\s*2\.3\.4", re.IGNORECASE),
        "type": "known_backdoored_software",
        "severity": "critical",
        "description": (
            "Service banner matches vsftpd 2.3.4, a version whose "
            "distribution archive was maliciously modified in 2011 "
            "(publicly documented, CVE-2011-2523). Treat as compromised "
            "if actually running this build."
        ),
    },
]

_OLD_OPENSSH_RE = re.compile(r"OpenSSH[_ ]([0-9]+)\.([0-9]+)", re.IGNORECASE)

# Security headers we check for on HTTPS responses. Absence isn't
# proof of a vulnerability by itself, hence the "low" severity and
# confidence 1.0 (we're certain the header is absent — that's a fact,
# not a guess — even though its security impact is context-dependent).
_EXPECTED_HTTPS_HEADERS = [
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "content-security-policy",
]

# Loose patterns for common secret-shaped values in a response body.
# A regex hit here is a HEURISTIC, not a confirmation — false positives
# are possible (e.g. a field literally named "token" with a placeholder
# value) — hence confidence < 1.0 even though this is deterministic
# code, not an LLM. That's a deliberate reading of "confidence" as
# "how sure are we this is real," not "was this produced by code."
_SECRET_PATTERN = re.compile(
    r'["\']?(?:token|api[_-]?key|secret|password)["\']?\s*[:=]\s*'
    r'["\']?([A-Za-z0-9\-_.]{12,})',
    re.IGNORECASE,
)


def parse_nmap_xml(xml_text: str) -> tuple[list[dict], list[dict], list[dict]]:
    """Parse nmap -oX output into (hosts, services, findings) dicts.

    Each host dict: {"ip", "hostname", "os"}.
    Each service dict: {"ip", "port", "protocol", "service_name", "banner"}
      (keyed by "ip" rather than "host_id" — the caller/ingest glue is
      responsible for resolving ip -> host_id after save_host()).
    Each finding dict follows the same "ip"-keyed convention, plus the
    usual type/severity/description/evidence/source/confidence fields.

    Only handles the XML shapes nmap actually produces for -sT -sV
    scans; deliberately does not try to guess at malformed XML.
    """
    root = ET.fromstring(xml_text)
    hosts: list[dict] = []
    services: list[dict] = []
    findings: list[dict] = []

    for host_el in root.findall("host"):
        status = host_el.find("status")
        if status is not None and status.get("state") != "up":
            continue

        addr_el = host_el.find("address")
        if addr_el is None:
            continue
        ip = addr_el.get("addr")

        hostname_el = host_el.find("hostnames/hostname")
        hostname = hostname_el.get("name") if hostname_el is not None else ip

        osmatch_el = host_el.find("os/osmatch")
        os_name = osmatch_el.get("name") if osmatch_el is not None else None

        hosts.append({"ip": ip, "hostname": hostname, "os": os_name})

        for port_el in host_el.findall("ports/port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            portid = int(port_el.get("portid"))
            protocol = port_el.get("protocol")
            service_el = port_el.find("service")
            service_name = (
                service_el.get("name") if service_el is not None else "unknown"
            )
            product = service_el.get("product") if service_el is not None else None
            version = service_el.get("version") if service_el is not None else None
            banner = " ".join(x for x in [product, version] if x) or None

            services.append(
                {
                    "ip": ip,
                    "port": portid,
                    "protocol": protocol,
                    "service_name": service_name,
                    "banner": banner,
                }
            )

            if banner:
                for rule in KNOWN_VULNERABLE_BANNERS:
                    if rule["match"].search(banner):
                        findings.append(
                            {
                                "ip": ip,
                                "type": rule["type"],
                                "severity": rule["severity"],
                                "description": rule["description"],
                                "evidence": (
                                    f"nmap detected service banner {banner!r} "
                                    f"on {ip}:{portid}"
                                ),
                                "source": "scanner",
                                "confidence": 1.0,
                            }
                        )

                m = _OLD_OPENSSH_RE.search(banner)
                if m and int(m.group(1)) < 7:
                    findings.append(
                        {
                            "ip": ip,
                            "type": "outdated_software",
                            "severity": "medium",
                            "description": (
                                f"OpenSSH {m.group(1)}.{m.group(2)} predates "
                                "several years of security patches"
                            ),
                            "evidence": (
                                f"nmap detected service banner {banner!r} "
                                f"on {ip}:{portid}"
                            ),
                            "source": "scanner",
                            "confidence": 1.0,
                        }
                    )

    return hosts, services, findings


def parse_http_probe(probe: dict) -> list[dict]:
    """Turn a scanners.http_probe() result into finding dicts (no
    host_id yet — the caller attaches that, since this function only
    knows about the URL it was given). Checks for two things a rigid
    parser CAN judge deterministically: secret-shaped values in the
    response body, and missing standard security headers on HTTPS
    responses.
    """
    findings: list[dict] = []
    body = probe.get("body", "") or ""
    url = probe.get("url", "")

    m = _SECRET_PATTERN.search(body)
    if m:
        findings.append(
            {
                "type": "leaked_credential",
                "severity": "high",
                "description": (
                    f"Response body from {url} contains what looks like a "
                    "credential or token"
                ),
                "evidence": (
                    f"GET {url} -> {probe.get('status_code')}, body matched "
                    "a secret-shaped pattern"
                ),
                "source": "scanner",
                "confidence": 0.85,
            }
        )

    if url.startswith("https"):
        headers_lower = {k.lower() for k in probe.get("headers", {})}
        missing = [h for h in _EXPECTED_HTTPS_HEADERS if h not in headers_lower]
        if missing:
            findings.append(
                {
                    "type": "missing_security_headers",
                    "severity": "low",
                    "description": f"Missing security headers: {', '.join(missing)}",
                    "evidence": (
                        f"GET {url} response headers omitted: {', '.join(missing)}"
                    ),
                    "source": "scanner",
                    "confidence": 1.0,
                }
            )

    return findings


def parse_postgres_roles(host_id: str, rows: list[dict]) -> list[dict]:
    """Turn scanners.introspect_postgres_roles() rows into finding
    dicts, already keyed by host_id (the caller knows which host it
    introspected, unlike the nmap case)."""
    findings: list[dict] = []
    for row in rows:
        if row.get("rolcanlogin") and row.get("rolsuper"):
            findings.append(
                {
                    "host_id": host_id,
                    "type": "overprivileged_role",
                    "severity": "high",
                    "description": (
                        f"Role '{row['rolname']}' can log in and has "
                        "superuser privileges"
                    ),
                    "evidence": (
                        f"pg_roles: rolname={row['rolname']} rolsuper=True "
                        "rolcanlogin=True"
                    ),
                    "source": "scanner",
                    "confidence": 1.0,
                }
            )
    return findings
