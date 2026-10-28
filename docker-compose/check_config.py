"""Check Jamf/BHE configuration and writable storage without network requests."""

import importlib.metadata
import os
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

import dlt
from dlt.common.configuration import configspec, resolve_configuration
from dlt.common.configuration.specs import BaseConfiguration

from openhound_jamf.auth import JamfClientCredentials, JamfPasswordCredentials


@configspec
class SourceConfiguration(BaseConfiguration):
    # Match the source's union and its resolution order, without constructing a source.
    credentials: JamfPasswordCredentials | JamfClientCredentials = None


class PreflightError(ValueError):
    """A configuration error safe to display without credential values."""


def required(name: str, value: object) -> str:
    """Reject missing values and unchanged example placeholders."""
    if value is None or not str(value).strip() or "REPLACE_WITH" in str(value):
        raise PreflightError(f"Set {name} in .dlt configuration or the environment")
    return str(value)


def https_url(name: str, value: str) -> None:
    """Require an HTTPS origin without embedded credentials or a query."""
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError:
        raise PreflightError(f"Set a valid HTTPS URL for {name}") from None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or any(character.isspace() for character in value)
        or "\\" in value
        or parsed.username
        or parsed.password
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or port == 0
    ):
        raise PreflightError(f"Set a valid HTTPS origin URL for {name}")


def main() -> None:
    """Validate credentials through DLT without requesting authentication tokens."""
    print("Jamf collector version:", importlib.metadata.version("openhound-jamf"))
    print("Preflight does not authenticate to Jamf or BHE.")
    for field in ("url", "token_id", "token_key"):
        name = f"destination.bloodhoundenterprise.{field}"
        value = required(name, dlt.secrets.get(name))
        if field == "url":
            https_url(name, value)
    name = "destination.bloodhoundenterprise.collector_name"
    if required(name, dlt.config.get(name)) != "jamf":
        raise PreflightError(f"Set {name} to jamf")

    credentials = resolve_configuration(
        SourceConfiguration(), sections=("sources", "source", "jamf")
    ).credentials
    required("Jamf host", credentials.host)
    https_url("Jamf host", credentials.host)
    fields = (
        ("client_id", "client_secret")
        if isinstance(credentials, JamfClientCredentials)
        else ("username", "password")
    )
    for field in fields:
        required(f"sources.source.jamf.credentials.{field}", getattr(credentials, field))
    # Accessing credentials.token would authenticate; only resolve fields here.
    for directory in (
        Path.cwd(),
        Path(os.environ["DLT_DATA_DIR"]),
        Path(os.environ["PIPELINES_DIR"]),
        Path(os.environ["RUNTIME__LOG_PATH"]),
        Path("/tmp/openhound"),
    ):
        with tempfile.TemporaryFile(mode="w+", dir=directory) as probe:
            probe.write("ok")
    print(f"PASS: BHE and Jamf {credentials.auth} credentials resolve locally.")
    print("PASS: working, DLT, pipeline, log, and raw-output directories are writable.")


if __name__ == "__main__":
    try:
        main()
    except PreflightError as exc:
        sys.exit(f"Preflight failed: {exc}")
    except Exception:  # noqa: BLE001 - third-party exceptions may contain secrets
        sys.exit(
            "Preflight failed: check required configuration, mounted-file permissions, "
            "and writable storage. Error details suppressed."
        )
