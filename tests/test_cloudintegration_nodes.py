import json
from dataclasses import asdict
from pathlib import Path
from unittest.mock import MagicMock

import duckdb
import pytest
from pydantic import ValidationError
from requests import HTTPError

from openhound_jamf.graph import JAMFNode
from openhound_jamf.kinds import edges as ek
from openhound_jamf.kinds import nodes as nk
from openhound_jamf.models.cloudintegration import (
    CloudIntegrationAsset,
    flatten_cloud_properties,
)
from openhound_jamf.source import (
    SourceContext,
    cloud_integration_details,
    cloud_integrations,
)

TENANT = "jamf.example.com"
SAMPLE = Path(__file__).parent / "test_data" / "v1" / "cloud-azure.json"


def summary(id="201", enabled=True, kind="AZURE"):
    """Build a synthetic provider summary with configurable identity, state, and kind."""
    return dict(
        id=id,
        displayName="Example Azure Provider",
        enabled=enabled,
        providerName=kind,
        providerDescription="Entra ID",
    )


def detail():
    """Load a fresh copy of the synthetic Azure configuration fixture."""
    return json.loads(SAMPLE.read_text())


def asset(details=True, **overrides):
    """Build a validated provider asset with optional details and field overrides."""
    values = dict(
        summary=summary(),
        details=detail() if details is True else None if details is False else details,
        tenant=TENANT,
        graph_id=JAMFNode.guid("201", nk.CLOUD_INTEGRATION, TENANT),
    )
    values.update(overrides)
    return CloudIntegrationAsset.model_validate(values)


def test_every_sample_property_is_preserved_and_flattened():
    """Verify provider properties are flattened and exported with stable graph metadata."""
    node = asset().as_node.model_dump(mode="json")
    expected = {
        "id": "201",
        "display_name": "Example Azure Provider",
        "enabled": True,
        "provider_name": "AZURE",
        "provider_description": "Entra ID",
        "cloud_idp_common_id": "201",
        "cloud_idp_common_display_name": "Example Azure Provider",
        "cloud_idp_common_provider_name": "AZURE",
        "server_id": "201",
        "server_tenant_id": "33333333-3333-4333-8333-333333333333",
        "server_enabled": True,
        "server_migrated": False,
        "server_type": "PUBLIC",
        "server_mappings_user_id": "id",
        "server_mappings_user_name": "userPrincipalName",
        "server_mappings_real_name": "displayName",
        "server_mappings_email": "mail",
        "server_mappings_department": "department",
        "server_mappings_building": "",
        "server_mappings_room": "",
        "server_mappings_phone": "mobilePhone",
        "server_mappings_position": "jobTitle",
        "server_mappings_group_id": "id",
        "server_mappings_group_name": "displayName",
        "server_search_timeout": 30,
        "server_transitive_membership_enabled": True,
        "server_transitive_membership_user_field": "userPrincipalName",
        "server_transitive_directory_membership_enabled": True,
        "server_membership_calculation_optimization_enabled": True,
        "server_deprecated_consent": False,
        "server_scim_support_settings_username_change_enabled": False,
        "server_scim_support_settings_group_name_change_enabled": False,
    }
    assert expected.items() <= node["properties"].items()
    assert node["id"] == JAMFNode.guid("201", nk.CLOUD_INTEGRATION, TENANT)
    assert node["kinds"] == ["jamf_CloudIntegration"]
    properties = node["properties"]
    assert properties["name"] == "EXAMPLE AZURE PROVIDER"
    assert properties["displayname"] == "Example Azure Provider"
    assert properties["environmentid"] == JAMFNode.guid(TENANT, nk.TENANT, TENANT)
    assert properties["details_collected"] is True
    assert properties["collected"] is True
    assert "objectid" not in properties
    assert "graph_id" not in node
    assert all(
        value is not None and not isinstance(value, dict)
        for value in properties.values()
    )


def test_identity_is_stable_across_rename_and_distinct_across_tenants_and_kinds():
    """Verify graph identity survives renames and serialization without cross-scope collisions."""
    original = asset()
    renamed = asset(summary=summary() | {"displayName": "Renamed"})
    assert original.as_node.id == renamed.as_node.id
    assert original.as_node.id != JAMFNode.guid("201", nk.ACCOUNT, TENANT)
    assert original.as_node.id != JAMFNode.guid(
        "201", nk.CLOUD_INTEGRATION, "other.example.com"
    )
    restored = CloudIntegrationAsset.model_validate_json(original.model_dump_json())
    assert restored.as_node.id == original.graph_id


@pytest.mark.parametrize("enabled", [True, False])
def test_cloud_links_target_jamf_ids_and_azure_objectid(enabled):
    """Verify enabled and disabled assets link Jamf IDs to Azure objectid non-traversably."""
    payload = detail()
    payload["server"]["tenantId"] = "abcdef12-3456-4789-abcd-123456789abc"
    payload["server"]["enabled"] = enabled
    integration = asset(details=payload, summary=summary(enabled=enabled))
    # Exercise the saved representation used by preprocessing and conversion.
    restored = CloudIntegrationAsset.model_validate_json(integration.model_dump_json())
    tenant_link, azure_link = [asdict(edge) for edge in restored.edges]
    assert tenant_link["start"] == {
        "match_by": "id",
        "value": JAMFNode.guid(TENANT, nk.TENANT, TENANT),
    }
    assert (
        tenant_link["end"]
        == azure_link["start"]
        == {
            "match_by": "id",
            "value": restored.as_node.id,
        }
    )
    assert azure_link["end"] == {
        "match_by": "property",
        "kind": "AZTenant",
        "property_matchers": [
            {
                "key": "objectid",
                "value": "ABCDEF12-3456-4789-ABCD-123456789ABC",
                "operator": "equals",
            }
        ],
    }
    for edge in (tenant_link, azure_link):
        assert edge["kind"] == ek.CLOUD_INTEGRATION_LINK
        assert edge["properties"]["traversable"] is False


@pytest.mark.parametrize("tenant_id", [None, "", "not-a-uuid", "/TENANTS/invalid"])
def test_unavailable_azure_identity_retains_jamf_link(tenant_id, caplog):
    """Verify missing or invalid Azure identity skips only the Azure link with a warning."""
    if tenant_id is None:
        integration = asset(details=False, details_error="HTTPError")
    else:
        payload = detail()
        payload["server"]["tenantId"] = tenant_id
        integration = asset(details=payload)
    links = list(integration.edges)
    assert len(links) == 1
    assert links[0].end.value == integration.as_node.id
    assert links[0].properties.traversable is False
    assert "Skipping Azure tenant link" in caplog.text


def test_cloud_link_schema_is_registered_and_non_traversable():
    """Verify the integration relationship is non-traversable and kind names are unique."""
    schema_file = Path(__file__).parents[1] / "extension" / "schema.json"
    schema = json.loads(schema_file.read_text())
    relationship = next(
        kind
        for kind in schema["relationship_kinds"]
        if kind["name"] == ek.CLOUD_INTEGRATION_LINK
    )
    assert relationship["is_traversable"] is False
    names = [
        kind["name"]
        for collection in ("node_kinds", "relationship_kinds")
        for kind in schema[collection]
    ]
    assert len(names) == len(set(names))


@pytest.mark.parametrize("change", ["graph", "server", "common", "provider"])
def test_inconsistent_source_identity_is_rejected(change):
    """Verify mismatched graph, server, common, or provider identities fail validation."""
    values = asset().model_dump(mode="json")
    if change == "graph":
        values["graph_id"] = "invalid"
    if change == "server":
        values["details"]["server"]["id"] = "202"
    if change == "common":
        values["details"]["server"]["id"] = "202"
        values["details"]["cloud_idp_common"]["id"] = "202"
    if change == "provider":
        values["summary"]["provider_name"] = "GOOGLE"
    with pytest.raises(ValidationError):
        CloudIntegrationAsset.model_validate(values)


def test_nulls_are_omitted_and_false_zero_empty_strings_are_preserved():
    """Verify serialization omits nulls while retaining valid false, zero, and empty values."""
    payload = detail()
    payload["server"]["migrated"] = None
    payload["server"]["searchTimeout"] = 0
    payload["server"]["mappings"]["department"] = None
    payload["server"]["newSetting"] = False
    properties = asset(details=payload).as_node.model_dump(mode="json")["properties"]
    assert "server_migrated" not in properties
    assert "server_mappings_department" not in properties
    assert properties["server_search_timeout"] == 0
    assert properties["server_new_setting"] is False
    assert properties["server_mappings_building"] == ""
    partial = asset(details=False, details_error="HTTPError").as_node.model_dump(
        mode="json"
    )
    assert partial["properties"]["details_collected"] is False
    assert partial["properties"]["details_error"] == "HTTPError"
    assert not any(key.startswith("server_") for key in partial["properties"])


@pytest.mark.parametrize("value", [[{"id": "x"}], [True, "x"], [["x"]], float("inf")])
def test_unsupported_graph_values_are_rejected(value):
    """Verify nested, mixed-type, and non-finite property values are rejected."""
    with pytest.raises(ValueError):
        flatten_cloud_properties({"setting": value})


def test_flattening_detects_collisions_and_reserved_names():
    """Verify flattening rejects conflicting paths and reserved property names."""
    with pytest.raises(ValueError):
        flatten_cloud_properties({"userName": "a", "user_name": "b"})
    with pytest.raises(ValueError):
        flatten_cloud_properties({"objectid": "x"})
    assert flatten_cloud_properties({"names": ["a", "b"], "values": [0, 2.5]}) == {
        "names": ["a", "b"],
        "values": [0, 2.5],
    }


@pytest.mark.parametrize("failure", [None, "http", "identity", "type"])
def test_collection_retains_provider_when_details_fail(failure):
    """Verify detail collection failures preserve the provider summary and graph identity."""
    client = MagicMock()
    listing, detailed = MagicMock(), MagicMock()
    listing.json.return_value = {"totalCount": 1, "results": [summary(enabled=False)]}
    payload = detail()
    payload["server"]["enabled"] = False
    if failure == "http":
        detailed.raise_for_status.side_effect = HTTPError("403")
    if failure == "identity":
        payload["server"]["id"] = "202"
    if failure == "type":
        payload["server"]["enabled"] = "false"
    detailed.json.return_value = payload
    client.get.side_effect = [listing, detailed]
    ctx = SourceContext(client=client, tenant_id=TENANT)
    rows = list(cloud_integration_details(ctx))
    assert len(rows) == 1
    assert rows[0]["graph_id"] == JAMFNode.guid("201", nk.CLOUD_INTEGRATION, TENANT)
    assert rows[0]["summary"]["enabled"] is False
    assert (rows[0]["details"] is not None) == (failure is None)
    assert client.get.call_args.args == ("/api/v1/cloud-azure/201",)
    assert list(cloud_integrations(ctx))[0]["total_count"] == 1
    assert client.get.call_count == 2


def test_google_is_logged_once_without_creating_nodes(caplog):
    """Verify unsupported Google providers are logged once and create no graph assets."""
    client = MagicMock()
    client.get.return_value.json.return_value = {
        "totalCount": 1,
        "results": [summary(kind="GOOGLE")],
    }
    ctx = SourceContext(client=client, tenant_id=TENANT)
    assert list(cloud_integration_details(ctx)) == []
    ctx.log_unsupported_provider(ctx.cloud_snapshot().results[0])
    assert caplog.text.count("Google cloud integrations are unsupported.") == 1
    assert client.get.call_count == 1


@pytest.mark.usefixtures("mock_dlt_requests")
@pytest.mark.parametrize("outcome", ["full", "partial", "nulls", "disabled", "google"])
def test_provider_node_collect_preprocess_convert(
    tmp_path, monkeypatch, mock_jamf_api, outcome
):
    """Verify mocked collection through conversion preserves provider nodes and links offline."""
    from openhound.core.collect import Collector
    from openhound.core.convert import Converter
    from openhound.core.preproc import PreProcessor
    from openhound_jamf.auth import JamfPasswordCredentials
    from openhound_jamf.lookup import JamfLookup
    from openhound_jamf.models.tenant import Tenant
    from openhound_jamf.source import source

    monkeypatch.setenv("DLT_DATA_DIR", str(tmp_path / "dlt"))
    providers = [
        summary(
            enabled=outcome != "disabled",
            kind="GOOGLE" if outcome == "google" else "AZURE",
        )
    ]
    mock_jamf_api.app.state.cloud_idp_pages = [{"totalCount": 1, "results": providers}]
    if outcome == "partial":
        mock_jamf_api.app.state.cloud_azure_status["201"] = 403
    if outcome == "nulls":
        payload = detail()
        payload["server"]["mappings"]["department"] = None
        payload["server"]["migrated"] = None
        mock_jamf_api.app.state.cloud_azure_overrides["201"] = payload
    credentials = JamfPasswordCredentials(
        host="https://jamf.example.com", username="test", password="test"
    )

    def selected_source():
        """Select provider summaries, Azure details, and tenant resources for this pipeline test."""
        return source(credentials=credentials).with_resources(
            "cloud_integrations", "cloud_integration_details", "tenant"
        )

    collected = tmp_path / "collected"
    assert (
        not Collector(name="jamf", output_path=collected)
        .run(selected_source())
        .has_failed_jobs
    )
    lookup_file = tmp_path / "lookup.duckdb"
    info = PreProcessor(
        name="jamf", input_path=collected / "jamf", output_file=lookup_file
    ).run(
        resources={
            "cloud_integrations": "cloud_integrations",
            "cloud_integration_details": "cloud_integration_details",
            "tenant": "tenant",
        }
    )
    assert not info.has_failed_jobs
    output = tmp_path / "output"
    calls_before = list(mock_jamf_api.app.state.calls)
    with duckdb.connect(str(lookup_file)) as con:
        if outcome != "google":
            stored_id = con.execute(
                "SELECT graph_id FROM jamf.cloud_integration_details"
            ).fetchone()[0]
            assert stored_id == JAMFNode.guid("201", nk.CLOUD_INTEGRATION, TENANT)
        info = Converter(
            name="jamf",
            input_path=collected / "jamf",
            output_path=output,
            lookup=JamfLookup(con),
            source_kind="jamf",
        ).run(selected_source(), [CloudIntegrationAsset, Tenant], {})
        assert not info.has_failed_jobs
    nodes = [
        node
        for path in output.glob("*.json")
        for node in json.loads(path.read_text())["graph"]["nodes"]
    ]
    providers = [node for node in nodes if nk.CLOUD_INTEGRATION in node["kinds"]]
    assert len(providers) == (0 if outcome == "google" else 1)
    links = [
        edge
        for path in output.glob("*.json")
        for edge in json.loads(path.read_text())["graph"]["edges"]
        if edge["kind"] == ek.CLOUD_INTEGRATION_LINK
    ]
    assert len(links) == (
        0 if outcome == "google" else 1 if outcome == "partial" else 2
    )
    assert all(edge["properties"]["traversable"] is False for edge in links)
    if providers:
        node = providers[0]
        assert node["id"] == stored_id
        assert node["properties"]["details_collected"] is (outcome != "partial")
        assert node["properties"]["enabled"] is (outcome != "disabled")
        assert all(value is not None for value in node["properties"].values())
        assert "objectid" not in node["properties"]
        tenant_link = next(edge for edge in links if edge["end"]["match_by"] == "id")
        assert tenant_link["start"]["value"] == JAMFNode.guid(TENANT, nk.TENANT, TENANT)
        assert tenant_link["end"]["value"] == node["id"]
        if outcome != "partial":
            azure_link = next(
                edge for edge in links if edge["end"]["match_by"] == "property"
            )
            assert azure_link["start"]["value"] == node["id"]
            assert azure_link["end"]["kind"] == "AZTenant"
            assert azure_link["end"]["property_matchers"] == [
                {
                    "key": "objectid",
                    "value": "33333333-3333-4333-8333-333333333333",
                    "operator": "equals",
                }
            ]
    assert mock_jamf_api.app.state.calls == calls_before
