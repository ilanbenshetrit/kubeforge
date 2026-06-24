"""
tests/test_scanner.py
──────────────────────
Unit tests for the DataScanner.
Tests run against a temporary directory with synthetic files —
no real filesystem access needed.
"""

import pytest
import asyncio
import tempfile
import os
from pathlib import Path

from kubeforge.scanner.data_scanner import DataScanner
from kubeforge.models.threat import Severity, ThreatCategory


def write_temp_file(dir_path: str, filename: str, content: str) -> str:
    """Helper: create a temp file with given content."""
    path = os.path.join(dir_path, filename)
    Path(path).write_text(content)
    return path


@pytest.mark.asyncio
async def test_detects_aws_key():
    with tempfile.TemporaryDirectory() as tmpdir:
        write_temp_file(tmpdir, "config.py", 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"')
        scanner = DataScanner(target_paths=[tmpdir])
        summary = await scanner.run()

    assert summary.total_threats_found >= 1
    severities = [e.severity for e in summary.events]
    assert Severity.CRITICAL in severities


@pytest.mark.asyncio
async def test_detects_password():
    with tempfile.TemporaryDirectory() as tmpdir:
        write_temp_file(tmpdir, "settings.yml", "database:\n  password: supersecret123")
        scanner = DataScanner(target_paths=[tmpdir])
        summary = await scanner.run()

    assert summary.total_threats_found >= 1
    categories = [e.category for e in summary.events]
    assert ThreatCategory.SENSITIVE_DATA_EXPOSED in categories


@pytest.mark.asyncio
async def test_detects_private_key():
    with tempfile.TemporaryDirectory() as tmpdir:
        write_temp_file(
            tmpdir, "key.pem",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
        )
        scanner = DataScanner(target_paths=[tmpdir])
        summary = await scanner.run()

    assert summary.total_threats_found >= 1
    assert any(e.severity == Severity.CRITICAL for e in summary.events)


@pytest.mark.asyncio
async def test_clean_file_no_threats():
    with tempfile.TemporaryDirectory() as tmpdir:
        write_temp_file(tmpdir, "clean.py", "def hello():\n    return 'Hello, World!'")
        scanner = DataScanner(target_paths=[tmpdir])
        summary = await scanner.run()

    assert summary.total_threats_found == 0


@pytest.mark.asyncio
async def test_skips_nonexistent_path():
    scanner = DataScanner(target_paths=["/nonexistent/path/xyz"])
    summary = await scanner.run()
    assert summary.total_files_scanned == 0


@pytest.mark.asyncio
async def test_scan_summary_counts():
    with tempfile.TemporaryDirectory() as tmpdir:
        write_temp_file(tmpdir, "a.env", 'API_KEY="abc123secretkey456789"')
        write_temp_file(tmpdir, "b.py",  'password = "hunter2"')
        scanner = DataScanner(target_paths=[tmpdir])
        summary = await scanner.run()

    assert summary.total_files_scanned == 2
    assert summary.total_threats_found >= 2
    assert len(summary.events) == summary.total_threats_found
