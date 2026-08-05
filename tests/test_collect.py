from __future__ import annotations

from collections import Counter
import json

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
    "saml_assertion_consumer_service",
    "saml_issuer",
    "saml_service_provider",
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
        "jamf_sp_metadata": 1,
        "okta_idp_metadata": 1,
    }
)

PREPROC_RESOURCES = {
    "account_details": "account_details",
    "account_group_details": "account_group_details",
    "computers": "computers",
    "policy_details": "policy_details",
    "script_details": "script_details",
    "api_integrations": "api_integrations",
    "api_roles": "api_roles",
    "computerextensionattributes": "computerextensionattributes",
    "sites": "sites",
    "user_details": "user_details",
    "tenant": "tenant",
    "sso": "sso",
    "saml_service_provider": "saml_service_provider",
    "saml_issuer": "saml_issuer",
    "saml_assertion_consumer_service": "saml_assertion_consumer_service",
}


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

    return output_root


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


def test_convert_emits_normalized_saml_graph(tmp_path, mock_jamf_api):
    import duckdb
    import os

    from openhound.core.collect import Collector
    from openhound.core.convert import Converter
    from openhound.core.preproc import PreProcessor
    from openhound.core.progress import Progress
    from openhound_jamf.auth import JamfPasswordCredentials
    from openhound_jamf.lookup import JamfLookup
    from openhound_jamf.main import app
    from openhound_jamf.source import source as source_module
    from openhound_jamf.transforms import transforms

    os.environ["DLT_DATA_DIR"] = str(tmp_path / "dlt")
    os.environ["RUNTIME__LOG_PATH"] = str(tmp_path / "logs")

    credentials = JamfPasswordCredentials(
        host="https://jamf.test",
        username="jamf-user",
        password="jamf-pass",
    )

    collect_root = tmp_path / "output"
    collector = Collector(name="jamf", output_path=collect_root)
    collector.run(source_module(credentials=credentials))

    lookup_file = tmp_path / "lookup.duckdb"
    preprocessor = PreProcessor(
        name="jamf",
        input_path=collect_root / "jamf",
        output_file=lookup_file,
        transformer=transforms,
        progress=Progress.log,
    )
    preprocessor.run(PREPROC_RESOURCES)

    con = duckdb.connect(str(lookup_file), read_only=True)
    try:
        converter = Converter(
            name="jamf",
            input_path=collect_root / "jamf",
            lookup=JamfLookup(con),
            output_path=tmp_path / "graph",
            source_kind="jamf",
            progress=Progress.log,
        )
        converter.run(source_module(credentials=credentials), app.assets, {})
    finally:
        con.close()

    graph_nodes = []
    graph_edges = []
    for graph_file in (tmp_path / "graph").glob("*.json"):
        payload = json.loads(graph_file.read_text(encoding="utf-8"))
        graph_nodes.extend(payload["graph"]["nodes"])
        graph_edges.extend(payload["graph"]["edges"])

    node_kinds = {kind for node in graph_nodes for kind in node["kinds"]}
    edge_kinds = {edge["kind"] for edge in graph_edges}

    assert "SAML_ServiceProvider" in node_kinds
    assert "SAML_Issuer" in node_kinds
    assert "SAML_AssertionConsumerService" in node_kinds
    assert "SAML_Implements" in edge_kinds
    assert "SAML_TrustsIssuer" in edge_kinds
    assert "SAML_HasAssertionConsumerService" in edge_kinds
    assert "SAML_HasAccount" in edge_kinds

    email_rule = next(
        node
        for node in graph_nodes
        if "SAML_AccountResolutionRule" in node["kinds"]
    )
    assert email_rule["properties"]["expression"] == (
        "assertion.email_match_values.exists(value, value in "
        "account.email_match_values)"
    )
    assert email_rule["properties"]["summary"] == (
        "Any assertion email value exactly matches an account email value"
    )

    account_edge = next(
        edge for edge in graph_edges if edge["kind"] == "SAML_HasAccount"
    )
    assert account_edge["start"]["match_by"] == "id"
    assert account_edge["end"]["match_by"] == "id"
    assert account_edge["properties"]["email_match_values"] == [
        "john.smith@company.com"
    ]
