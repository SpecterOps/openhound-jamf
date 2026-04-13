from __future__ import annotations

from collections import Counter

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


EXPECTED_CALLS = Counter(
    {
        "auth_token": 1,
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

#
# def _reload_source_module():
#     for module_name in list(sys.modules):
#         if module_name.startswith("openhound_jamf"):
#             sys.modules.pop(module_name, None)
#     return importlib.import_module("openhound_jamf.source")


def test_collect_pipeline_runs_successfully(tmp_path, mock_dlt_requests, mock_jamf_api):
    import os

    os.environ["DLT_DATA_DIR"] = str(tmp_path / "dlt")
    os.environ["RUNTIME__LOG_PATH"] = str(tmp_path / "logs")

    from openhound.core.collect import Collector

    from openhound_jamf.source import source as source_module

    # source_module = _reload_source_module()
    # source_module.CustomAuth.token.cache_clear()

    collector = Collector(name="jamf", output_path=tmp_path / "output")
    load_info = collector.run(
        source_module(
            username="jamf-user",
            password="jamf-pass",
            host="https://jamf.test",
        )
    )

    assert load_info.loads_ids
    assert not load_info.has_failed_jobs

    output_root = tmp_path / "output" / "jamf"
    for resource in EXPECTED_RESOURCES:
        resource_dir = output_root / resource
        assert resource_dir.exists()
        assert any(resource_dir.glob("*.jsonl*"))

    assert Counter(mock_jamf_api.app.state.calls) == EXPECTED_CALLS
