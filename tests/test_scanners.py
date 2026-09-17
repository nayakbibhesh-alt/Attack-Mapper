"""Tests for discovery/scanners.py. Per the master spec's testing
strategy, LLM/live-integration points aren't tested against the real
thing in CI — the same principle applies here to live network calls.
These tests mock subprocess/requests/psycopg2 to verify scanners.py
builds the right commands and handles failures the way callers expect;
actually reaching a live target is exercised manually (see
lab_http_server.py + tests/fixtures/nmap_localhost_scan.xml, a real
captured scan) rather than in the automated suite.
"""

import subprocess
from unittest.mock import MagicMock, patch

import pytest
import requests

from attackmapper.discovery import scanners


def test_run_nmap_scan_raises_if_nmap_missing():
    with patch("shutil.which", return_value=None):
        with pytest.raises(RuntimeError, match="nmap is not installed"):
            scanners.run_nmap_scan("127.0.0.1")


def test_run_nmap_scan_builds_expected_command():
    fake_result = MagicMock(returncode=0, stdout="<xml/>", stderr="")
    with patch("shutil.which", return_value="/usr/bin/nmap"), patch(
        "subprocess.run", return_value=fake_result
    ) as mock_run:
        out = scanners.run_nmap_scan("10.0.0.5", ports="1-100")
    assert out == "<xml/>"
    args = mock_run.call_args[0][0]
    assert args == ["nmap", "-sT", "-sV", "-Pn", "-p", "1-100", "-oX", "-", "10.0.0.5"]


def test_run_nmap_scan_raises_on_nonzero_exit():
    fake_result = MagicMock(returncode=1, stdout="", stderr="permission denied")
    with patch("shutil.which", return_value="/usr/bin/nmap"), patch(
        "subprocess.run", return_value=fake_result
    ):
        with pytest.raises(RuntimeError, match="permission denied"):
            scanners.run_nmap_scan("10.0.0.5")


def test_run_nmap_scan_raises_on_timeout():
    with patch("shutil.which", return_value="/usr/bin/nmap"), patch(
        "subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="nmap", timeout=1),
    ):
        with pytest.raises(RuntimeError, match="timed out"):
            scanners.run_nmap_scan("10.0.0.5", timeout=1)


def test_http_probe_returns_expected_shape():
    fake_resp = MagicMock(
        status_code=200, headers={"Content-Type": "text/html"}, text="<html/>"
    )
    with patch("requests.get", return_value=fake_resp) as mock_get:
        result = scanners.http_probe("http://10.0.0.5/debug")
    mock_get.assert_called_once_with("http://10.0.0.5/debug", timeout=15.0)
    assert result == {
        "url": "http://10.0.0.5/debug",
        "status_code": 200,
        "headers": {"Content-Type": "text/html"},
        "body": "<html/>",
    }


def test_http_probe_truncates_long_body():
    fake_resp = MagicMock(status_code=200, headers={}, text="x" * 20000)
    with patch("requests.get", return_value=fake_resp):
        result = scanners.http_probe("http://10.0.0.5/")
    assert len(result["body"]) == 8000


def test_http_probe_raises_runtime_error_on_request_exception():
    with patch("requests.get", side_effect=requests.ConnectionError("refused")):
        with pytest.raises(RuntimeError, match="HTTP probe"):
            scanners.http_probe("http://10.0.0.5/")


def test_introspect_postgres_roles_raises_on_connection_failure():
    import psycopg2

    with patch(
        "psycopg2.connect",
        side_effect=psycopg2.OperationalError("could not connect"),
    ):
        with pytest.raises(RuntimeError, match="could not connect"):
            scanners.introspect_postgres_roles("postgresql://bad-dsn")


def test_introspect_postgres_roles_parses_rows():
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = [
        ("postgres", True, True, True, True),
        ("svc_app", False, False, False, True),
    ]
    mock_cursor.__enter__.return_value = mock_cursor
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    with patch("psycopg2.connect", return_value=mock_conn):
        rows = scanners.introspect_postgres_roles("postgresql://good-dsn")
    assert rows == [
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
    mock_conn.close.assert_called_once()
