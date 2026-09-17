"""discovery/scanners.py — the non-LLM half of Layer 1.

Runs real scanners against a live environment and returns their raw
output untouched. No parsing, no classification, no Finding objects
happen here — that's parsers.py's job, kept deliberately separate so
parsers can be unit-tested on fixtures without ever touching a
network (see tests/test_parsers.py).

Read-only by construction: every call here is an information-gathering
probe (TCP connect + banner grab, HTTP GET, a single SELECT against a
Postgres system catalog). Nothing here ever creates, modifies, deletes,
authenticates destructively, or attempts exploitation.

Scope discipline (non-negotiable, per the project's core principles):
only ever point these at hosts you own or are explicitly authorized to
test.
"""

from __future__ import annotations

import datetime
import hashlib
import secrets
import shutil
import socket
import ssl
import subprocess

import requests

# A small, fixed list of well-known paths worth checking for public
# exposure. Every request below is a plain, unauthenticated GET to an
# exact path — the same request any visitor's browser makes for
# /robots.txt — never a brute-force wordlist, never a guess at
# credentials, never anything beyond this list.
SENSITIVE_PATHS: list[str] = [
    "/.git/HEAD",
    "/.git/config",
    "/.env",
    "/.env.local",
    "/.aws/credentials",
    "/.DS_Store",
    "/.svn/entries",
    "/wp-config.php.bak",
    "/config.php.bak",
    "/backup.zip",
    "/backup.sql",
    "/server-status",
    "/.well-known/security.txt",
    "/robots.txt",
    "/sitemap.xml",
]


def run_nmap_scan(target: str, ports: str = "1-1024", timeout: float = 120.0) -> str:
    """TCP-connect + service/version detection scan (-sT -sV — no raw
    sockets, so no elevated privileges required) against `target`.
    Returns nmap's raw XML output as a string for parsers.parse_nmap_xml
    to interpret. Raises RuntimeError with a clear message if nmap
    isn't installed, the process errors, or it times out — callers
    should not have to guess why a scan failed.
    """
    if shutil.which("nmap") is None:
        raise RuntimeError(
            "nmap is not installed on this machine (try: apt-get install nmap)"
        )
    cmd = ["nmap", "-sT", "-sV", "-Pn", "-p", ports, "-oX", "-", target]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"nmap scan of {target!r} timed out after {timeout}s"
        ) from exc
    if result.returncode != 0:
        raise RuntimeError(
            f"nmap exited {result.returncode} scanning {target!r}: "
            f"{result.stderr.strip()}"
        )
    return result.stdout


def http_probe(url: str, timeout: float = 15.0) -> dict:
    """A single read-only GET against `url`. Returns the raw shape
    parsers.parse_http_probe needs: status code, headers, and body
    text (truncated so nothing downstream — storage, an LLM prompt —
    has to deal with an unbounded blob). Never issues a follow-up
    request of any kind, and never a state-changing verb (POST/PUT/
    DELETE)."""
    try:
        resp = requests.get(url, timeout=timeout)
    except requests.RequestException as exc:
        raise RuntimeError(f"HTTP probe of {url!r} failed: {exc}") from exc
    return {
        "url": url,
        "status_code": resp.status_code,
        "headers": dict(resp.headers),
        "body": resp.text[:8000],
    }


def tls_probe(hostname: str, port: int = 443, timeout: float = 5.0) -> dict:
    """Read-only TLS handshake against hostname:port — inspects
    whatever certificate and protocol version the server presents
    during a normal handshake, exactly what a browser visiting the
    site would see. Never sends application data.

    Pass 1 does a real, hostname-verifying handshake (what a browser
    does). If that fails verification, pass 2 reconnects with
    verification disabled purely so we can still learn which
    protocol/cipher the server negotiates — a host with a bad
    certificate should still get a protocol-level finding rather than
    an opaque failure.
    """
    info: dict = {
        "hostname": hostname,
        "port": port,
        "protocol": None,
        "cipher": None,
        "not_after": None,
        "days_until_expiry": None,
        "verified": False,
        "verify_error": None,
    }

    ctx = ssl.create_default_context()
    cert = None
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
                info["protocol"] = tls_sock.version()
                cipher = tls_sock.cipher()
                info["cipher"] = cipher[0] if cipher else None
                info["verified"] = True
    except ssl.SSLCertVerificationError as exc:
        info["verify_error"] = exc.verify_message or str(exc)
    except (OSError, ssl.SSLError) as exc:
        raise RuntimeError(f"TLS probe of {hostname}:{port} failed: {exc}") from exc

    if cert:
        not_after = cert.get("notAfter")
        info["not_after"] = not_after
        if not_after:
            expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            info["days_until_expiry"] = (expiry - datetime.datetime.utcnow()).days

    if not info["verified"]:
        try:
            noverify_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            noverify_ctx.check_hostname = False
            noverify_ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with noverify_ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                    info["protocol"] = tls_sock.version()
                    cipher = tls_sock.cipher()
                    info["cipher"] = cipher[0] if cipher else None
        except (OSError, ssl.SSLError):
            pass  # best-effort only -- a hard connect failure already
            # would have raised RuntimeError above in pass 1

    return info


# How much of a hit's (or the baseline's) body we keep, both to feed
# parsers.py's content-signature checks and to hash for the baseline
# diff. Matches the truncation pattern already used in http_probe —
# nothing downstream has to deal with an unbounded blob.
_CAPTURED_BODY_BYTES = 4000


def _hash_body(raw: bytes) -> str:
    """sha256 over a fixed prefix of the raw body. Not a full-body
    hash — this is a cheap "is this byte-for-byte the same response
    as our baseline probe" signal, not a content-integrity check."""
    return hashlib.sha256(raw[:_CAPTURED_BODY_BYTES]).hexdigest()


def _capture_response(resp: requests.Response) -> dict:
    """Shared shape for both the baseline probe and a real hit: status
    code, full body length, a truncated body (decoded latin-1 so exact
    byte values — e.g. a ZIP file's magic bytes — round-trip losslessly
    instead of being mangled or dropped the way utf-8 decoding would),
    and a hash of that truncated body for the baseline diff."""
    raw = resp.content[:_CAPTURED_BODY_BYTES]
    return {
        "status_code": resp.status_code,
        "length": len(resp.content),
        "body": raw.decode("latin-1"),
        "body_hash": _hash_body(resp.content),
    }


def _baseline_probe(base_url: str, timeout: float) -> dict:
    """GET one path that's certain not to exist on `base_url`, so
    exposed_paths_probe has something to diff real hits against. A
    server that answers every unmatched route with the same page (SPA
    catch-alls, a misconfigured default vhost) would otherwise make
    every entry in SENSITIVE_PATHS look like a confirmed hit. Same
    constraints as every other probe here — read-only, GET, no auth —
    and raises RuntimeError on failure rather than failing silently,
    since a failed baseline means the rest of this probe can't be
    trusted either."""
    probe_path = f"/__attackmapper-baseline-{secrets.token_hex(16)}__"
    url = base_url.rstrip("/") + probe_path
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=False)
    except requests.RequestException as exc:
        raise RuntimeError(f"baseline probe of {url!r} failed: {exc}") from exc
    return _capture_response(resp)


def exposed_paths_probe(base_url: str, timeout: float = 5.0) -> dict:
    """GET each path in SENSITIVE_PATHS against base_url and report
    which ones return 200, alongside a baseline probe of a known-
    nonexistent path. Read-only, GET-only, fixed list — this is
    reconnaissance identical in kind to what a normal page load or a
    search-engine crawler already does against a public site.

    A bare 200 isn't reported as a confirmed hit by parsers.py unless
    it's backed by actual evidence, so each hit here carries its body
    content (not just length) for content-signature checks, and the
    baseline lets parsers.py tell "this path genuinely exists" apart
    from "this server returns the same fallback response for
    everything." Returns {"baseline": {...}, "hits": {path: {...}}}.
    """
    baseline = _baseline_probe(base_url, timeout)

    hits: dict[str, dict] = {}
    for path in SENSITIVE_PATHS:
        url = base_url.rstrip("/") + path
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=False)
        except requests.RequestException:
            continue
        if resp.status_code == 200:
            hits[path] = _capture_response(resp)
    return {"baseline": baseline, "hits": hits}


def cors_probe(url: str, timeout: float = 5.0) -> dict:
    """Single read-only GET carrying a foreign Origin header, purely
    to observe how the server's CORS policy reflects it in response
    headers — the same signal a browser-based CORS check reads.
    Sends no credentials of its own and issues no follow-up request."""
    probe_origin = "https://cors-probe.invalid.example"
    try:
        resp = requests.get(url, timeout=timeout, headers={"Origin": probe_origin})
    except requests.RequestException as exc:
        raise RuntimeError(f"CORS probe of {url!r} failed: {exc}") from exc
    return {
        "allow_origin": resp.headers.get("Access-Control-Allow-Origin"),
        "allow_credentials": resp.headers.get("Access-Control-Allow-Credentials"),
        "probe_origin": probe_origin,
    }


def introspect_postgres_roles(dsn: str, timeout: float = 5.0) -> list[dict]:
    """Read-only introspection of role privileges via a single SELECT
    against the pg_roles system catalog. Never creates, alters, or
    drops anything, and never touches user tables/data."""
    import psycopg2  # imported lazily so Phase A/B installs without it

    try:
        conn = psycopg2.connect(dsn, connect_timeout=int(timeout))
    except psycopg2.OperationalError as exc:
        raise RuntimeError(f"could not connect to {dsn!r}: {exc}") from exc
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, "
                "rolcanlogin FROM pg_roles;"
            )
            rows = cur.fetchall()
        return [
            {
                "rolname": r[0],
                "rolsuper": r[1],
                "rolcreaterole": r[2],
                "rolcreatedb": r[3],
                "rolcanlogin": r[4],
            }
            for r in rows
        ]
    finally:
        conn.close()
