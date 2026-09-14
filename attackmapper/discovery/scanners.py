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

import shutil
import subprocess

import requests


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
    cmd = ["nmap", "-sT", "-sV", "-p", ports, "-oX", "-", target]
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


def http_probe(url: str, timeout: float = 5.0) -> dict:
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
