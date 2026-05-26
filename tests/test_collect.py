from __future__ import annotations

from collections import Counter

import pytest

pytestmark = pytest.mark.usefixtures("mock_dlt_requests")

EXPECTED_RESOURCES = [
    "account_details",
    "account_group_details",
    "api_integrations",
    "api_roles",
    "computerextensionattributes",
    "computers",
    "policy_details",
    "script_details",
    "sites",
    "sso",
    "tenant",
    "user_details",
]


BASE_EXPECTED_CALLS = Counter(
    {
        "users": 1,
        "user_details": 1,
        "accounts": 2,
        "account_details": 1,
        "account_group_details": 1,
        "policies": 1,
        "policy_details": 1,
        "scripts": 1,
        "script_details": 1,
        "computerextensionattributes": 1,
        "sites": 1,
        "computers": 2,
        "api_integrations": 1,
        "api_roles": 1,
        "sso": 1,
    }
)


def _run_collect_and_assert(tmp_path, mock_jamf_api, credentials, expected_calls):
    import os

    os.environ["DLT_DATA_DIR"] = str(tmp_path / "dlt")
    os.environ["RUNTIME__LOG_PATH"] = str(tmp_path / "logs")

    from openhound.core.collect import Collector

    from openhound_jamf.source import source as source_module

    collector = Collector(name="jamf", output_path=tmp_path / "output")
    load_info = collector.run(source_module(credentials=credentials))

    assert load_info.loads_ids
    assert not load_info.has_failed_jobs

    output_root = tmp_path / "output" / "jamf"
    for resource in EXPECTED_RESOURCES:
        resource_dir = output_root / resource
        assert resource_dir.exists()
        assert any(resource_dir.glob("*.jsonl*"))

    actual_calls = Counter(mock_jamf_api.app.state.calls)
    assert actual_calls == expected_calls, (
        "Jamf API calls did not match expectations. "
        f"actual={actual_calls}, expected={expected_calls}, "
        f"call_order={mock_jamf_api.app.state.calls}"
    )


def test_collect_pipeline_runs_successfully(tmp_path, mock_jamf_api):
    from openhound_jamf.auth import JamfPasswordCredentials

    credentials = JamfPasswordCredentials(
        host="https://jamf.test",
        username="jamf-user",
        password="jamf-pass",
    )
    assert credentials.auth == "password"

    expected_calls = BASE_EXPECTED_CALLS + Counter({"auth_token": 1})

    _run_collect_and_assert(tmp_path, mock_jamf_api, credentials, expected_calls)


def test_collect_pipeline_runs_successfully_with_client_credentials_auth(
    tmp_path, mock_jamf_api
):
    from openhound_jamf.auth import JamfClientCredentials

    credentials = JamfClientCredentials(
        host="https://jamf.test",
        client_id="jamf-client-id",
        client_secret="jamf-client-secret",
    )
    assert credentials.auth == "client"

    expected_calls = BASE_EXPECTED_CALLS + Counter({"oauth_token": 1})

    _run_collect_and_assert(tmp_path, mock_jamf_api, credentials, expected_calls)
