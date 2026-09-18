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
import re
import secrets
import shutil
import socket
import ssl
import struct
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
    # Admin panels / management consoles -- never meant to face the
    # public internet unauthenticated.
    "/wp-login.php",
    "/wp-admin/",
    "/administrator/",
    "/phpmyadmin/",
    "/pgadmin4/",
    # Framework/app debug + info-disclosure endpoints.
    "/actuator/env",
    "/actuator/health",
    "/_profiler/",
    "/debug",
    "/.well-known/openid-configuration",
    # API schema disclosure -- not a vuln by itself, but tells an
    # attacker the exact shape of every endpoint to target next.
    "/swagger.json",
    "/swagger-ui.html",
    "/openapi.json",
    "/api-docs",
    # More of the same family as .env/.git -- deploy artifacts that
    # should never ship to a public webroot.
    "/.htpasswd",
    "/docker-compose.yml",
    "/Dockerfile",
    "/.idea/workspace.xml",
    "/id_rsa",
]

# Superset of ports worth an active TCP-connect check from the one-box
# scan_target_url entry point -- see parsers.SENSITIVE_PORTS for which
# of these (plus the original 11) get flagged as findings when found
# open.
COMMON_TARGET_PORTS = ",".join(
    str(p)
    for p in sorted(
        {21, 22, 23, 25, 80, 110, 143, 443, 445, 1433, 1521, 2375, 2379,
         3306, 3389, 5432, 5601, 5672, 5900, 5985, 6379, 6443, 8009, 8080,
         8443, 9042, 9092, 9200, 9300, 11211, 15672, 27017, 27018}
    )
)


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


# ---------------------------------------------------------------------
# Phase H additions: more discovery sources, same read-only-probe
# discipline as everything above (a handshake, a GET, a single
# protocol-greeting command, a public certificate-transparency lookup
# -- never a write, never a credential guess, never exploitation).
# ---------------------------------------------------------------------


# -- DNS (SPF/DMARC/NS/MX) -- minimal stdlib-only resolver -----------
#
# No dnspython dependency: this project's whole scanners.py already
# hand-rolls protocol clients over raw sockets (see tls_probe above),
# so a compact DNS-over-UDP client in the same style keeps the "stdlib
# first" pattern rather than adding a dependency for four record
# types. Truncated/malformed responses degrade to an empty answer list
# rather than raising -- DNS posture (SPF/DMARC absence) is a "nice to
# have" signal, not something a scan should abort over.

_DNS_TYPES = {"A": 1, "NS": 2, "MX": 15, "TXT": 16}


def _encode_dns_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        encoded = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode("ascii")
        out += bytes([len(encoded)]) + encoded
    return out + b"\x00"


def _decode_dns_name(msg: bytes, offset: int) -> tuple[str, int]:
    """Decode a (possibly compressed) DNS name starting at `offset`.
    Returns (name, offset_after_name) where offset_after_name is where
    to resume reading the *containing* record -- a pointer jump moves
    the read position for name-decoding only, never the caller's
    resume point (per RFC 1035 4.1.4)."""
    labels: list[str] = []
    pos = offset
    resume_at: int | None = None
    seen_pointers = 0
    while True:
        if pos >= len(msg):
            break
        length = msg[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            if resume_at is None:
                resume_at = pos + 2
            seen_pointers += 1
            if seen_pointers > 20:  # guard against a malicious/looping pointer chain
                break
            pos = ((length & 0x3F) << 8) | msg[pos + 1]
            continue
        pos += 1
        labels.append(msg[pos : pos + length].decode("ascii", errors="replace"))
        pos += length
    return ".".join(labels), (resume_at if resume_at is not None else pos)


def _dns_query(
    name: str, rtype: str, server: str = "8.8.8.8", timeout: float = 4.0
) -> list[str]:
    """One UDP DNS query for `rtype` records of `name`. Returns decoded
    RDATA as strings (dotted IP for A, "priority exchange" for MX, the
    text itself for TXT, the target name for NS) or [] on any failure
    (timeout, SERVFAIL, truncation, no answers) -- never raises, since
    an absent/broken DNS answer is itself informative (e.g. "no SPF
    record" IS the finding) rather than an error condition."""
    qtype = _DNS_TYPES[rtype]
    txid = secrets.token_bytes(2)
    header = txid + b"\x01\x00" + b"\x00\x01" + b"\x00\x00" * 3
    question = _encode_dns_name(name) + struct.pack(">HH", qtype, 1)
    packet = header + question

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, 53))
        data, _ = sock.recvfrom(4096)
    except OSError:
        return []
    finally:
        sock.close()

    if len(data) < 12 or data[:2] != txid:
        return []
    ancount = struct.unpack(">H", data[6:8])[0]
    if ancount == 0:
        return []

    pos = 12
    _, pos = _decode_dns_name(data, pos)
    pos += 4  # QTYPE + QCLASS

    results: list[str] = []
    for _ in range(ancount):
        if pos >= len(data):
            break
        _, pos = _decode_dns_name(data, pos)
        if pos + 10 > len(data):
            break
        rr_type, _rr_class, _ttl, rdlength = struct.unpack(">HHIH", data[pos : pos + 10])
        pos += 10
        rdata = data[pos : pos + rdlength]
        if rr_type == 1 and len(rdata) == 4:  # A
            results.append(".".join(str(b) for b in rdata))
        elif rr_type == 2:  # NS
            target, _ = _decode_dns_name(data, pos)
            results.append(target)
        elif rr_type == 15 and len(rdata) > 2:  # MX
            pref = struct.unpack(">H", rdata[:2])[0]
            exchange, _ = _decode_dns_name(data, pos + 2)
            results.append(f"{pref} {exchange}")
        elif rr_type == 16:  # TXT -- one or more length-prefixed strings
            chunks = []
            i = 0
            while i < len(rdata):
                seg_len = rdata[i]
                chunks.append(rdata[i + 1 : i + 1 + seg_len].decode("ascii", errors="replace"))
                i += 1 + seg_len
            results.append("".join(chunks))
        pos += rdlength
    return results


def dns_probe(hostname: str, timeout: float = 4.0) -> dict:
    """Read-only DNS posture check: A/NS/MX records, plus whether an
    SPF record (a TXT record starting 'v=spf1') and a DMARC record
    (TXT at _dmarc.<domain>) exist, and DMARC's policy if so. Absence
    of either is a real, commonly-exploited weakness (it's what makes
    a domain easy to spoof in phishing) -- exactly the kind of
    building block Layer 7's attack-chain reasoning can combine with
    other findings (e.g. a leaked internal email address) into a
    concrete story, even though DNS itself isn't a "hackable" service.
    """
    domain = hostname.split(":")[0]
    a_records = _dns_query(domain, "A", timeout=timeout)
    ns_records = _dns_query(domain, "NS", timeout=timeout)
    mx_records = _dns_query(domain, "MX", timeout=timeout)
    txt_records = _dns_query(domain, "TXT", timeout=timeout)
    dmarc_records = _dns_query(f"_dmarc.{domain}", "TXT", timeout=timeout)

    spf = next((t for t in txt_records if t.lower().startswith("v=spf1")), None)
    dmarc = next((t for t in dmarc_records if t.lower().startswith("v=dmarc1")), None)
    dmarc_policy = None
    if dmarc:
        m = re.search(r"p=(\w+)", dmarc, re.IGNORECASE)
        dmarc_policy = m.group(1).lower() if m else None

    return {
        "domain": domain,
        "a_records": a_records,
        "ns_records": ns_records,
        "mx_records": mx_records,
        "spf_record": spf,
        "dmarc_record": dmarc,
        "dmarc_policy": dmarc_policy,
    }


# -- Subdomain enumeration via certificate transparency ---------------


def subdomain_enum(domain: str, timeout: float = 10.0, limit: int = 60) -> list[str]:
    """Passive subdomain discovery via crt.sh's public certificate-
    transparency search -- read-only lookup of a public log, never a
    probe against the target itself, so it's information anyone can
    already get by visiting crt.sh directly. Returns a deduplicated,
    sorted list of hostnames (wildcard entries like '*.example.com'
    have the '*.' stripped), capped at `limit`. Returns [] on any
    failure (crt.sh is occasionally slow/rate-limited) rather than
    raising -- this is a bonus signal, not something a scan should
    fail over."""
    domain = domain.split(":")[0]
    try:
        resp = requests.get(
            "https://crt.sh/", params={"q": f"%.{domain}", "output": "json"},
            timeout=timeout, headers={"User-Agent": "AttackMapper/1.0"},
        )
        resp.raise_for_status()
        entries = resp.json()
    except (requests.RequestException, ValueError):
        return []

    names: set[str] = set()
    for entry in entries:
        for raw in str(entry.get("name_value", "")).splitlines():
            raw = raw.strip().lower().lstrip("*.")
            if raw and domain in raw:
                names.add(raw)
    return sorted(names)[:limit]


# -- HTTP verb / method exposure ---------------------------------------


def http_methods_probe(url: str, timeout: float = 5.0) -> dict:
    """A single OPTIONS request, reading the `Allow` header the same
    way a browser's CORS preflight already does -- never actually
    issues the dangerous verb itself, just observes which ones the
    server says it accepts."""
    try:
        resp = requests.options(url, timeout=timeout)
    except requests.RequestException as exc:
        raise RuntimeError(f"HTTP methods probe of {url!r} failed: {exc}") from exc
    allow = resp.headers.get("Allow", "")
    methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
    return {"status_code": resp.status_code, "methods": methods}


# -- GraphQL introspection --------------------------------------------

_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/graphql/console"]
_INTROSPECTION_QUERY = '{"query": "{__schema{queryType{name}}}"}'


def graphql_introspection_probe(base_url: str, timeout: float = 6.0) -> dict:
    """Tries a handful of conventional GraphQL endpoint paths with a
    minimal, read-only introspection query (the same query any GraphQL
    client's schema-autocomplete feature sends). Never sends a
    mutation. Returns the first endpoint that both exists and answers
    with a real schema, or {"endpoint": None} if none do."""
    base = base_url.rstrip("/")
    for path in _GRAPHQL_PATHS:
        url = base + path
        try:
            resp = requests.post(
                url, data=_INTROSPECTION_QUERY, timeout=timeout,
                headers={"Content-Type": "application/json"},
            )
        except requests.RequestException:
            continue
        if resp.status_code != 200:
            continue
        try:
            payload = resp.json()
        except ValueError:
            continue
        schema = (payload.get("data") or {}).get("__schema") if isinstance(payload, dict) else None
        if schema:
            return {"endpoint": url, "introspection_enabled": True}
    return {"endpoint": None, "introspection_enabled": False}


# -- Open redirect ------------------------------------------------------

_OPEN_REDIRECT_PARAMS = ["next", "url", "redirect", "return", "returnUrl", "continue", "dest"]
_OPEN_REDIRECT_TARGET = "https://attackmapper-redirect-check.invalid.example/"


def open_redirect_probe(base_url: str, timeout: float = 5.0) -> dict:
    """For each of a short list of common redirect-parameter names,
    GET the site root with that param pointing at an off-site,
    guaranteed-nonexistent URL, without following the redirect, and
    check whether the server's Location header sends the browser
    straight there. Read-only, no state change, no real destination
    ever contacted (the target domain is invalid/reserved-for-testing
    and resolves nowhere)."""
    base = base_url.rstrip("/") + "/"
    vulnerable: list[str] = []
    for param in _OPEN_REDIRECT_PARAMS:
        try:
            resp = requests.get(
                base, params={param: _OPEN_REDIRECT_TARGET},
                timeout=timeout, allow_redirects=False,
            )
        except requests.RequestException:
            continue
        location = resp.headers.get("Location", "")
        if resp.status_code in (301, 302, 303, 307, 308) and _OPEN_REDIRECT_TARGET.rstrip("/") in location:
            vulnerable.append(param)
    return {"vulnerable_params": vulnerable}


# -- Unauthenticated data-store checks ----------------------------------
#
# Each of these is a single, read-only protocol greeting -- the
# equivalent of a client library's own connection handshake -- against
# a well-known port. None of them authenticate, write, or read
# anything beyond a one-line server status/ping response.


def redis_unauth_probe(host: str, port: int = 6379, timeout: float = 3.0) -> dict:
    """Connects to `host:port` and sends a single Redis PING. A
    `+PONG` reply means the server answered a command with no
    AUTH -- i.e. it's running with no authentication configured at
    all. Returns {"open": False} for anything that isn't a live Redis
    responding to PING (connection refused, timeout, wrong protocol)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(b"PING\r\n")
            reply = sock.recv(64)
    except OSError:
        return {"open": False, "unauthenticated": False}
    return {"open": True, "unauthenticated": reply.startswith(b"+PONG")}


def memcached_unauth_probe(host: str, port: int = 11211, timeout: float = 3.0) -> dict:
    """Connects to `host:port` and sends the classic-protocol `stats`
    command. A reply starting `STAT` means the server answered with no
    authentication step at all (memcached's classic protocol has none
    by design -- the finding is that it's reachable from the internet
    in the first place)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(b"stats\r\n")
            reply = sock.recv(256)
    except OSError:
        return {"open": False, "unauthenticated": False}
    return {"open": True, "unauthenticated": reply.startswith(b"STAT")}


def elasticsearch_unauth_probe(host: str, port: int = 9200, timeout: float = 5.0) -> dict:
    """A single unauthenticated GET against the cluster info endpoint
    Elasticsearch serves at its root. A 200 with a `cluster_name` field
    means the cluster answers without credentials -- the same request
    an attacker's first probe would make."""
    try:
        resp = requests.get(f"http://{host}:{port}/", timeout=timeout)
    except requests.RequestException:
        return {"open": False, "unauthenticated": False}
    if resp.status_code != 200:
        return {"open": True, "unauthenticated": False}
    try:
        payload = resp.json()
    except ValueError:
        return {"open": True, "unauthenticated": False}
    cluster_name = payload.get("cluster_name") if isinstance(payload, dict) else None
    return {"open": True, "unauthenticated": cluster_name is not None, "cluster_name": cluster_name}
