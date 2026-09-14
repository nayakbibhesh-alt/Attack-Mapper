"""Fixture-based tests for discovery/parsers.py. No live lab, no
network calls — exactly what the master spec's testing strategy calls
for. tests/fixtures/nmap_localhost_scan.xml is a REAL nmap scan
captured against a throwaway local HTTP server (see the repo's
lab_http_server.py); tests/fixtures/nmap_vsftpd_backdoor_synthetic.xml
is hand-crafted (clearly labeled as such in the file) since standing
up an actually-backdoored vsftpd build isn't something to do even in
a sandbox.
"""

from pathlib import Path

from attackmapper.discovery.parsers import (
    parse_http_probe,
    parse_nmap_xml,
    parse_postgres_roles,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_real_captured_nmap_scan():
    xml_text = (FIXTURES / "nmap_localhost_scan.xml").read_text()
    hosts, services, findings = parse_nmap_xml(xml_text)

    assert len(hosts) == 1
    assert hosts[0]["ip"] == "127.0.0.1"
    assert hosts[0]["hostname"] == "localhost"

    assert len(services) == 1
    assert services[0]["port"] == 8765
    assert services[0]["protocol"] == "tcp"
    assert services[0]["service_name"] == "http"
    assert "BaseHTTPServer" in services[0]["banner"]

    # Python's stdlib HTTP server isn't in the known-vulnerable-banner
    # table, so this scan should not generate any findings.
    assert findings == []


def test_parse_synthetic_vsftpd_backdoor_scan():
    xml_text = (FIXTURES / "nmap_vsftpd_backdoor_synthetic.xml").read_text()
    hosts, services, findings = parse_nmap_xml(xml_text)

    assert hosts == [
        {"ip": "10.0.9.50", "hostname": "legacy-ftp.lab.internal", "os": None}
    ]
    assert len(services) == 2

    finding_types = {f["type"] for f in findings}
    assert "known_backdoored_software" in finding_types
    assert "outdated_software" in finding_types  # OpenSSH 4.3

    backdoor = next(f for f in findings if f["type"] == "known_backdoored_software")
    assert backdoor["severity"] == "critical"
    assert backdoor["confidence"] == 1.0
    assert backdoor["ip"] == "10.0.9.50"
    assert "vsftpd" in backdoor["evidence"]


def test_parse_nmap_xml_skips_down_hosts_and_closed_ports():
    xml_text = """<?xml version="1.0"?><nmaprun>
    <host><status state="down"/><address addr="10.0.0.1" addrtype="ipv4"/></host>
    <host><status state="up"/><address addr="10.0.0.2" addrtype="ipv4"/>
      <ports><port protocol="tcp" portid="80">
        <state state="closed"/><service name="http"/>
      </port></ports>
    </host>
    </nmaprun>"""
    hosts, services, findings = parse_nmap_xml(xml_text)
    assert len(hosts) == 1  # the down host is excluded
    assert hosts[0]["ip"] == "10.0.0.2"
    assert services == []  # the closed port is excluded
    assert findings == []


def test_parse_http_probe_flags_leaked_credential():
    probe = {
        "url": "http://web01.lab.internal/internal/debug",
        "status_code": 200,
        "headers": {"Content-Type": "application/json"},
        "body": '{"status": "ok", "service_account_token": "sa-tok-EXAMPLE1234567890abcdef"}',
    }
    findings = parse_http_probe(probe)
    assert len(findings) == 1
    assert findings[0]["type"] == "leaked_credential"
    assert findings[0]["confidence"] < 1.0  # heuristic, not a certainty


def test_parse_http_probe_flags_missing_security_headers_on_https():
    probe = {
        "url": "https://app01.lab.internal/",
        "status_code": 200,
        "headers": {"Content-Type": "text/html"},
        "body": "<html>ok</html>",
    }
    findings = parse_http_probe(probe)
    types = {f["type"] for f in findings}
    assert "missing_security_headers" in types


def test_parse_http_probe_no_findings_on_clean_https_response():
    probe = {
        "url": "https://app01.lab.internal/",
        "status_code": 200,
        "headers": {
            "Content-Type": "text/html",
            "Strict-Transport-Security": "max-age=63072000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
        },
        "body": "<html>nothing interesting here</html>",
    }
    assert parse_http_probe(probe) == []


def test_parse_http_probe_ignores_missing_headers_on_plain_http():
    # Missing-header check is HTTPS-specific; plain http:// shouldn't
    # trigger it (it has bigger problems, but that's a different check).
    probe = {
        "url": "http://internal-tool.lab/",
        "status_code": 200,
        "headers": {},
        "body": "<html>ok</html>",
    }
    assert parse_http_probe(probe) == []


def test_parse_postgres_roles_flags_login_superuser():
    rows = [
        {
            "rolname": "postgres",
            "rolsuper": True,
            "rolcreaterole": True,
            "rolcreatedb": True,
            "rolcanlogin": True,
        },
        {
            "rolname": "svc_app",
            "rolsuper": False,
            "rolcreaterole": False,
            "rolcreatedb": False,
            "rolcanlogin": True,
        },
    ]
    findings = parse_postgres_roles("host-db-1", rows)
    assert len(findings) == 1
    assert findings[0]["host_id"] == "host-db-1"
    assert findings[0]["type"] == "overprivileged_role"
    assert "postgres" in findings[0]["description"]


def test_parse_postgres_roles_no_findings_when_none_overprivileged():
    rows = [
        {
            "rolname": "readonly",
            "rolsuper": False,
            "rolcreaterole": False,
            "rolcreatedb": False,
            "rolcanlogin": True,
        }
    ]
    assert parse_postgres_roles("host-db-1", rows) == []
