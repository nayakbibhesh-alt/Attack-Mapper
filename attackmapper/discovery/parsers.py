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
    "referrer-policy",
    "permissions-policy",
]

# Response headers that commonly leak software/version info. A version
# NUMBER in the value is what makes this worth flagging (e.g. "nginx"
# alone is far less useful to an attacker than "nginx/1.18.0").
_DISCLOSURE_HEADERS = ["server", "x-powered-by", "x-aspnet-version"]
_VERSION_RE = re.compile(r"\d+\.\d+")

# Deprecated/weak TLS versions worth an automatic finding.
WEAK_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

# Well-known TCP ports that should almost never be reachable from the
# public internet unauthenticated -- flagged purely from the port
# being open, independent of whatever banner nmap did or didn't grab.
# Maps port -> (severity, human label). Kept here (not in scanners.py)
# since this is classification, exactly like KNOWN_VULNERABLE_BANNERS
# above -- scanners.py stays limited to "how to reach the network."
SENSITIVE_PORTS: dict[int, tuple[str, str]] = {
    21: ("medium", "FTP (often anonymous-auth or cleartext credentials)"),
    23: ("high", "Telnet (cleartext remote administration)"),
    445: ("medium", "SMB (frequent lateral-movement / ransomware vector)"),
    1433: ("high", "Microsoft SQL Server"),
    1521: ("high", "Oracle database listener"),
    2375: ("critical", "Docker Engine API without TLS (unauthenticated = host takeover)"),
    2379: ("high", "etcd client API (often unauthenticated; stores cluster secrets)"),
    3306: ("high", "MySQL/MariaDB"),
    3389: ("medium", "RDP (common ransomware entry point)"),
    5432: ("high", "PostgreSQL"),
    5601: ("medium", "Kibana (frequently unauthenticated by default)"),
    5672: ("medium", "RabbitMQ AMQP"),
    5900: ("high", "VNC (often unauthenticated or weak-auth remote desktop)"),
    6379: ("high", "Redis (frequently deployed with no authentication)"),
    6443: ("high", "Kubernetes API server"),
    8009: ("high", "AJP (Apache JServ Protocol -- Ghostcat-class request smuggling)"),
    9042: ("medium", "Cassandra"),
    9092: ("medium", "Kafka broker"),
    9200: ("high", "Elasticsearch (frequently unauthenticated by default)"),
    9300: ("medium", "Elasticsearch transport"),
    11211: ("medium", "Memcached (frequently unauthenticated; also a DDoS amplifier)"),
    15672: ("medium", "RabbitMQ management UI"),
    27017: ("high", "MongoDB (frequently unauthenticated by default)"),
    27018: ("high", "MongoDB (sharded cluster)"),
}

# Sensitive-path exposure: split into "always worth flagging" (VCS
# dirs, secrets, backups) vs. paths that are normal/expected to be
# public and shouldn't generate a finding just for existing.
_CRITICAL_EXPOSED_PATHS = {
    "/.git/HEAD",
    "/.git/config",
    "/.env",
    "/.env.local",
    "/.aws/credentials",
    "/wp-config.php.bak",
    "/config.php.bak",
    "/backup.sql",
    "/backup.zip",
}
_BENIGN_EXPOSED_PATHS = {"/robots.txt", "/sitemap.xml", "/.well-known/security.txt"}

# Per-path (or path-family) content signatures. These are what actually
# confirm a 200 response IS the sensitive file/output it claims to be,
# rather than some other 200 (a generic error page, a custom 404, an
# unrelated app route) that merely happens to share the status code.
# Each pattern is intentionally loose/heuristic — see the confidence
# semantics note above _SECRET_PATTERN — which is exactly why a match
# earns full confidence/severity but a non-match does NOT get treated
# as a confirmed false positive, only as "can't confirm from content
# alone" (see _signature_check below and parse_exposed_paths).
_ENV_LINE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=.*$", re.MULTILINE)
_HTML_MARKER_RE = re.compile(r"<html|<!DOCTYPE\s+html", re.IGNORECASE)
_GIT_HEAD_RE = re.compile(r"^(ref:\s*refs/heads/\S+|[0-9a-f]{40})\s*$", re.MULTILINE)
_GIT_CONFIG_RE = re.compile(r"^\s*\[core\]", re.MULTILINE)
_ZIP_MAGIC = "PK\x03\x04"  # body is decoded latin-1, so this is an exact byte match
_SQL_DUMP_RE = re.compile(r"\b(INSERT INTO|CREATE TABLE)\b", re.IGNORECASE)
_PHP_RE = re.compile(r"<\?php")
_AWS_CREDENTIALS_RE = re.compile(
    r"\[[\w-]+\][^\[]{0,500}?aws_access_key_id\s*=", re.IGNORECASE | re.DOTALL
)
_APACHE_MOD_STATUS_RE = re.compile(
    r"Apache Server Status|Scoreboard Key", re.IGNORECASE
)


def _signature_check(path: str, body: str) -> bool | None:
    """Return True if `body` looks like the real file/output expected
    at `path`, False if a signature is defined for this path and the
    body clearly doesn't match it, or None if this path has no defined
    signature at all (content alone can neither confirm nor rule it
    out). Used by parse_exposed_paths to decide whether a 200 that
    survives the baseline diff is actually independent evidence."""
    if path in ("/.env", "/.env.local"):
        return bool(_ENV_LINE_RE.search(body)) and not _HTML_MARKER_RE.search(body)
    if path == "/.git/HEAD":
        return bool(_GIT_HEAD_RE.search(body))
    if path == "/.git/config":
        return bool(_GIT_CONFIG_RE.search(body))
    if path == "/backup.zip":
        return body.startswith(_ZIP_MAGIC)
    if path == "/backup.sql":
        return bool(_SQL_DUMP_RE.search(body)) and not _HTML_MARKER_RE.search(body)
    if path in ("/wp-config.php.bak", "/config.php.bak"):
        return bool(_PHP_RE.search(body)) and not _HTML_MARKER_RE.search(body)
    if path == "/.aws/credentials":
        return bool(_AWS_CREDENTIALS_RE.search(body))
    if path == "/server-status":
        return bool(_APACHE_MOD_STATUS_RE.search(body))
    return None

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

            # Port-level exposure, independent of any banner: some
            # services should essentially never be directly reachable
            # from the public internet at all, regardless of whether
            # they turn out to require auth once you're on them. See
            # scanners.SENSITIVE_PORTS for the full table + rationale
            # per port.
            sensitive = SENSITIVE_PORTS.get(portid)
            if sensitive:
                severity, label = sensitive
                findings.append(
                    {
                        "ip": ip,
                        "type": "sensitive_port_exposed",
                        "severity": severity,
                        "description": (
                            f"Port {portid}/{protocol} ({label}) is reachable "
                            f"on {ip} — this class of service is a common "
                            "target for direct exploitation or credential-"
                            "less access once discovered by a port scan."
                        ),
                        "evidence": f"nmap found port {portid}/{protocol} open on {ip}",
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

    headers = probe.get("headers", {}) or {}
    headers_lower = {k.lower(): v for k, v in headers.items()}

    if url.startswith("https"):
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

    for h in _DISCLOSURE_HEADERS:
        val = headers_lower.get(h)
        if val and _VERSION_RE.search(val):
            findings.append(
                {
                    "type": "information_disclosure",
                    "severity": "low",
                    "description": (
                        f"{h.title()} header discloses software/version info: {val}"
                    ),
                    "evidence": f"GET {url} response header {h}: {val}",
                    "source": "scanner",
                    "confidence": 1.0,
                }
            )

    set_cookie = headers_lower.get("set-cookie")
    if set_cookie and url.startswith("https"):
        cookie_lower = set_cookie.lower()
        missing_flags = [f for f in ("secure", "httponly") if f not in cookie_lower]
        if missing_flags:
            findings.append(
                {
                    "type": "insecure_cookie",
                    "severity": "medium",
                    "description": f"Set-Cookie is missing: {', '.join(missing_flags)}",
                    "evidence": (
                        f"GET {url} response Set-Cookie omits {', '.join(missing_flags)}"
                    ),
                    "source": "scanner",
                    "confidence": 0.9,
                }
            )

    return findings


def parse_tls_probe(hostname: str, info: dict) -> list[dict]:
    """Turn a scanners.tls_probe() result into finding dicts (no
    host_id yet — same convention as parse_http_probe)."""
    findings: list[dict] = []
    port = info.get("port")

    if info.get("verify_error"):
        findings.append(
            {
                "type": "invalid_tls_certificate",
                "severity": "high",
                "description": (
                    f"TLS certificate for {hostname} failed verification: "
                    f"{info['verify_error']}"
                ),
                "evidence": f"TLS handshake to {hostname}:{port} — {info['verify_error']}",
                "source": "scanner",
                "confidence": 1.0,
            }
        )

    protocol = info.get("protocol")
    if protocol in WEAK_TLS_VERSIONS:
        findings.append(
            {
                "type": "weak_tls_protocol",
                "severity": "high",
                "description": f"Server negotiated {protocol}, a deprecated TLS/SSL version",
                "evidence": f"TLS handshake to {hostname}:{port} negotiated {protocol}",
                "source": "scanner",
                "confidence": 1.0,
            }
        )

    days = info.get("days_until_expiry")
    if days is not None:
        if days < 0:
            findings.append(
                {
                    "type": "expired_certificate",
                    "severity": "critical",
                    "description": f"TLS certificate for {hostname} expired {-days} day(s) ago",
                    "evidence": f"TLS handshake to {hostname}:{port}, notAfter={info.get('not_after')}",
                    "source": "scanner",
                    "confidence": 1.0,
                }
            )
        elif days <= 14:
            findings.append(
                {
                    "type": "certificate_expiring_soon",
                    "severity": "medium",
                    "description": f"TLS certificate for {hostname} expires in {days} day(s)",
                    "evidence": f"TLS handshake to {hostname}:{port}, notAfter={info.get('not_after')}",
                    "source": "scanner",
                    "confidence": 1.0,
                }
            )

    return findings


def parse_exposed_paths(base_url: str, probe_result: dict) -> list[dict]:
    """Turn a scanners.exposed_paths_probe() result into finding
    dicts. Paths that are normal/expected to be public (robots.txt
    etc.) are deliberately not flagged.

    A bare 200 is never treated as confirmation by itself:

    1. Each hit is diffed against `probe_result["baseline"]` (a probe
       of a known-nonexistent path). A hit that's indistinguishable
       from the baseline is the server's generic fallback response,
       not evidence the path exists — those are rolled into a single
       low-confidence "treat these results with caution" note instead
       of being reported as individual critical findings.
    2. Anything left is checked against a per-path content signature
       (see _signature_check). Only a signature match earns the
       path's full severity at confidence 1.0. A 200 that clears the
       baseline but matches no known signature isn't dropped (that
       would risk a false negative) but also isn't called critical —
       it's reported at reduced confidence, flagged for manual
       confirmation.
    """
    base = base_url.rstrip("/")
    baseline = probe_result.get("baseline") or {}
    hits = probe_result.get("hits") or {}

    findings: list[dict] = []
    fallback_matched_paths: list[str] = []

    for path, info in hits.items():
        if path in _BENIGN_EXPOSED_PATHS:
            continue

        url = f"{base}{path}"
        body = info.get("body", "") or ""

        matches_baseline = bool(baseline) and (
            info.get("status_code") == baseline.get("status_code")
            and info.get("length") == baseline.get("length")
            and info.get("body_hash") == baseline.get("body_hash")
        )
        if matches_baseline:
            fallback_matched_paths.append(path)
            continue

        full_severity = "critical" if path in _CRITICAL_EXPOSED_PATHS else "medium"

        if _signature_check(path, body):
            findings.append(
                {
                    "type": "exposed_sensitive_path",
                    "severity": full_severity,
                    "description": (
                        f"{path} is publicly accessible and its content matches "
                        f"the expected signature for this file type "
                        f"({info['status_code']}, {info['length']} bytes)"
                    ),
                    "evidence": (
                        f"GET {url} -> {info['status_code']}; body content "
                        "signature-matched this path's expected file type and "
                        "differs from this server's baseline (fallback) "
                        "response — actual secret values, if any, are redacted "
                        "from this evidence"
                    ),
                    "source": "scanner",
                    "confidence": 1.0,
                }
            )
        else:
            findings.append(
                {
                    "type": "exposed_sensitive_path",
                    "severity": "medium",
                    "description": (
                        f"{path} returned 200 ({info['status_code']}, "
                        f"{info['length']} bytes), but its content could not "
                        "be confirmed as the real file — needs manual review"
                    ),
                    "evidence": (
                        f"GET {url} -> {info['status_code']}; response differs "
                        "from this server's baseline (fallback) response, but "
                        "did not match a known content signature for this path "
                        "— unconfirmed, not yet ruled a false positive"
                    ),
                    "source": "scanner",
                    "confidence": 0.5,
                }
            )

    if fallback_matched_paths:
        findings.append(
            {
                "type": "exposed_path_scan_unreliable",
                "severity": "low",
                "description": (
                    "This server returns an identical 200 response for a "
                    "known-nonexistent path, so a 200 on a sensitive path is "
                    "not independent evidence it exists — treat exposed-path "
                    "results for this host with caution"
                ),
                "evidence": (
                    f"Baseline probe and {len(fallback_matched_paths)} "
                    "sensitive path(s) "
                    f"({', '.join(sorted(fallback_matched_paths))}) all "
                    f"returned status {baseline.get('status_code')}, "
                    f"{baseline.get('length')} bytes, and an identical body "
                    "hash"
                ),
                "source": "scanner",
                "confidence": 0.1,
            }
        )

    return findings


def parse_cors_probe(url: str, info: dict) -> list[dict]:
    """Turn a scanners.cors_probe() result into finding dicts."""
    allow_origin = info.get("allow_origin")
    allow_creds = (info.get("allow_credentials") or "").lower() == "true"
    probe_origin = info.get("probe_origin")
    reflects = allow_origin == probe_origin or allow_origin == "*"

    findings: list[dict] = []
    if reflects and allow_creds:
        findings.append(
            {
                "type": "cors_misconfiguration",
                "severity": "high",
                "description": (
                    "Server reflects an arbitrary Origin in "
                    "Access-Control-Allow-Origin while also allowing "
                    "credentials — lets any website read this site's "
                    "authenticated responses on a victim's behalf"
                ),
                "evidence": (
                    f"GET {url} with Origin: {probe_origin} -> "
                    f"Access-Control-Allow-Origin: {allow_origin}, "
                    f"Access-Control-Allow-Credentials: {info.get('allow_credentials')}"
                ),
                "source": "scanner",
                "confidence": 1.0,
            }
        )
    elif allow_origin == "*":
        findings.append(
            {
                "type": "cors_wildcard",
                "severity": "low",
                "description": (
                    "Access-Control-Allow-Origin is '*', allowing any site "
                    "to read this endpoint's (non-credentialed) responses"
                ),
                "evidence": f"GET {url} -> Access-Control-Allow-Origin: *",
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


# ---------------------------------------------------------------------
# Phase H additions -- parsers for the new discovery sources in
# scanners.py. Same rules as everything above: pure functions, no
# network, no host_id yet unless noted (caller fills that in, same
# convention as parse_http_probe/parse_tls_probe).
# ---------------------------------------------------------------------


def parse_dns_probe(hostname: str, info: dict) -> list[dict]:
    """Turn a scanners.dns_probe() result into finding dicts. Absence
    of SPF/DMARC isn't an exploitable vulnerability in the traditional
    sense, but it's real, commonly-abused exposure: it's what makes a
    domain trivially easy to spoof for phishing, which Layer 7's
    attack-chain reasoning can combine with other findings (e.g. an
    exposed employee email format) into a concrete social-engineering
    path."""
    findings: list[dict] = []
    domain = info.get("domain", hostname)

    if not info.get("spf_record"):
        findings.append(
            {
                "type": "missing_spf_record",
                "severity": "medium",
                "description": (
                    f"{domain} has no SPF (Sender Policy Framework) TXT "
                    "record, making it easier for attackers to send "
                    "phishing email that appears to come from this domain"
                ),
                "evidence": f"no TXT record starting 'v=spf1' found for {domain}",
                "source": "scanner",
                "confidence": 1.0,
            }
        )

    dmarc = info.get("dmarc_record")
    if not dmarc:
        findings.append(
            {
                "type": "missing_dmarc_record",
                "severity": "medium",
                "description": (
                    f"{domain} has no DMARC record, so mail servers have no "
                    "policy to consult when a message claiming to be from "
                    "this domain fails SPF/DKIM"
                ),
                "evidence": f"no TXT record found at _dmarc.{domain}",
                "source": "scanner",
                "confidence": 1.0,
            }
        )
    elif info.get("dmarc_policy") == "none":
        findings.append(
            {
                "type": "weak_dmarc_policy",
                "severity": "low",
                "description": (
                    f"{domain}'s DMARC policy is 'p=none' -- failing "
                    "messages are only reported, never quarantined or "
                    "rejected"
                ),
                "evidence": f"_dmarc.{domain} TXT record: {dmarc}",
                "source": "scanner",
                "confidence": 1.0,
            }
        )

    return findings


# Subdomain name fragments that, if discovered via certificate-
# transparency logs, suggest an internal/administrative system that
# was probably never meant to be publicly indexed in the first place.
_SENSITIVE_SUBDOMAIN_HINTS = (
    "dev", "stage", "staging", "test", "uat", "qa", "internal", "intranet",
    "admin", "adminer", "phpmyadmin", "jenkins", "gitlab", "git",
    "grafana", "kibana", "prometheus", "vpn", "backup", "db", "database",
    "sftp", "ftp", "old", "legacy", "beta",
)


def parse_subdomains(domain: str, subdomains: list[str]) -> list[dict]:
    """Not every discovered subdomain is a finding -- most are exactly
    what you'd expect (www, api, mail). This flags the subset whose
    name suggests an internal/admin/staging system that a certificate-
    transparency log has now made public knowledge, which is itself
    useful attacker recon even before anyone probes it."""
    findings: list[dict] = []
    for sub in subdomains:
        label = sub.split(".")[0] if sub != domain else None
        if not label:
            continue
        if any(hint == part for part in label.split("-") for hint in _SENSITIVE_SUBDOMAIN_HINTS):
            findings.append(
                {
                    "type": "sensitive_subdomain_exposed",
                    "severity": "low",
                    "description": (
                        f"Certificate transparency logs reveal {sub}, whose "
                        "name suggests an internal, administrative, or "
                        "non-production system -- worth checking that it "
                        "isn't reachable, or isn't meant to be public"
                    ),
                    "evidence": f"crt.sh certificate transparency log lists {sub}",
                    "source": "scanner",
                    "confidence": 0.6,
                }
            )
    return findings


def parse_http_methods(url: str, info: dict) -> list[dict]:
    """Turn a scanners.http_methods_probe() result into finding dicts.
    TRACE enables cross-site tracing/header-reflection attacks; PUT/
    DELETE accepted at the application root suggests write methods
    were left enabled without access control in front of them."""
    findings: list[dict] = []
    methods = set(info.get("methods", []))

    if "TRACE" in methods:
        findings.append(
            {
                "type": "http_trace_enabled",
                "severity": "medium",
                "description": (
                    f"{url} accepts the HTTP TRACE method, which can be "
                    "used for cross-site tracing (XST) to read headers "
                    "(e.g. cookies) a script shouldn't have access to"
                ),
                "evidence": f"OPTIONS {url} -> Allow: {', '.join(sorted(methods))}",
                "source": "scanner",
                "confidence": 1.0,
            }
        )

    write_methods = methods & {"PUT", "DELETE"}
    if write_methods:
        findings.append(
            {
                "type": "dangerous_http_methods_enabled",
                "severity": "high",
                "description": (
                    f"{url} advertises {', '.join(sorted(write_methods))} "
                    "as accepted methods -- if these aren't gated by "
                    "authentication, they allow direct content modification "
                    "or deletion"
                ),
                "evidence": f"OPTIONS {url} -> Allow: {', '.join(sorted(methods))}",
                "source": "scanner",
                "confidence": 0.7,
            }
        )

    return findings


def parse_graphql_probe(info: dict) -> list[dict]:
    """Turn a scanners.graphql_introspection_probe() result into a
    finding. Introspection isn't itself a breach, but it hands an
    attacker the complete schema -- every type, field, and mutation --
    which is normally the single most time-consuming part of attacking
    a GraphQL API."""
    if not info.get("introspection_enabled"):
        return []
    endpoint = info.get("endpoint")
    return [
        {
            "type": "graphql_introspection_enabled",
            "severity": "medium",
            "description": (
                f"GraphQL introspection is enabled at {endpoint}, exposing "
                "the complete schema (types, fields, mutations) to any "
                "unauthenticated caller"
            ),
            "evidence": f"POST {endpoint} with an introspection query returned a full __schema",
            "source": "scanner",
            "confidence": 1.0,
        }
    ]


def parse_open_redirect(url: str, info: dict) -> list[dict]:
    """Turn a scanners.open_redirect_probe() result into a finding.
    Open redirects are commonly chained into phishing (a link that
    starts on the real domain, then bounces to an attacker's page) and
    into OAuth token theft."""
    params = info.get("vulnerable_params", [])
    if not params:
        return []
    return [
        {
            "type": "open_redirect",
            "severity": "medium",
            "description": (
                f"{url} redirects to an attacker-controlled URL via the "
                f"{', '.join(params)} parameter without validating it stays "
                "on-site -- commonly abused to make phishing links look "
                "like they start on a trusted domain"
            ),
            "evidence": f"GET {url}?{params[0]}=<external URL> returned a redirect to that URL",
            "source": "scanner",
            "confidence": 0.8,
        }
    ]


def parse_unauth_datastore(
    service: str, host: str, port: int, info: dict
) -> list[dict]:
    """Shared shape for the three unauthenticated-datastore probes
    (Redis, Memcached, Elasticsearch) -- each returns
    {"open": bool, "unauthenticated": bool, ...}, and an unauthenticated
    hit is always a critical finding: it means full read/write (Redis,
    Memcached) or full read (Elasticsearch) access to whatever the
    service holds, with zero credentials."""
    if not info.get("unauthenticated"):
        return []
    extra = f" (cluster_name={info['cluster_name']!r})" if info.get("cluster_name") else ""
    return [
        {
            "type": f"unauthenticated_{service}",
            "severity": "critical",
            "description": (
                f"{service.capitalize()} on {host}:{port} answers requests "
                f"with no authentication configured{extra} -- anyone who can "
                "reach this port has full access to whatever it holds"
            ),
            "evidence": f"unauthenticated protocol probe to {host}:{port} succeeded",
            "source": "scanner",
            "confidence": 1.0,
        }
    ]
