"""Offline validation of the deployment configuration and credential alternatives."""

import os
import runpy
import subprocess
import sys
from pathlib import Path

import pytest

PREFLIGHT = Path(__file__).parents[1] / "docker-compose" / "check_config.py"


@pytest.fixture
def preflight(tmp_path, monkeypatch):
    monkeypatch.setenv("DLT_PROJECT_DIR", str(tmp_path))
    monkeypatch.setenv("RUNTIME__LOG_PATH", str(tmp_path / "logs"))
    return runpy.run_path(str(PREFLIGHT))


@pytest.mark.parametrize("value", [None, "", "  ", "REPLACE_WITH_SECRET"])
def test_reject_missing_and_placeholder_values(preflight, value):
    with pytest.raises(preflight["PreflightError"], match="Set token"):
        preflight["required"]("token", value)


@pytest.mark.parametrize(
    "value",
    [
        "http://example.invalid",
        "https://user:secret@example.invalid",
        "https://example.invalid/api",
        "https://example.invalid?secret=value",
        "https://example.invalid#fragment",
        "https://example.invalid:bad",
        "https://bad host.invalid",
        "https://example.invalid:0",
        "https://",
    ],
)
def test_reject_invalid_https_origins(preflight, value):
    with pytest.raises(preflight["PreflightError"], match="HTTPS"):
        preflight["https_url"]("host", value)


def test_accept_https_origin(preflight):
    preflight["https_url"]("host", "https://example.invalid:443/")


@pytest.mark.parametrize(
    ("credentials", "expected"),
    [
        ('client_id = "offline-id"\nclient_secret = "offline-secret"', "client"),
        ('username = "offline-user"\npassword = "offline-password"', "password"),
    ],
)
def test_resolve_actual_credential_classes_offline(tmp_path, credentials, expected):
    config_dir = tmp_path / ".dlt"
    config_dir.mkdir()
    (config_dir / "secrets.toml").write_text(
        '[sources.source.jamf.credentials]\nhost = "https://example.invalid"\n'
        + credentials
        + "\n"
    )
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("SOURCES__", "DLT_", "DESTINATION__", "RUNTIME__"))
    }
    env.update(DLT_PROJECT_DIR=str(tmp_path), RUNTIME__LOG_PATH=str(tmp_path / "logs"))
    script = """
import runpy
import sys
from unittest.mock import patch
from dlt.common.configuration import resolve_configuration
with patch('requests.sessions.Session.request', side_effect=AssertionError('network access')):
    module = runpy.run_path(sys.argv[1])
    credentials = resolve_configuration(
        module['SourceConfiguration'](), sections=('sources', 'source', 'jamf')
    ).credentials
    assert credentials.auth == sys.argv[2]
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(PREFLIGHT), expected],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
