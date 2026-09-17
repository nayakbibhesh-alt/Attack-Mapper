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
