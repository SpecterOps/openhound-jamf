from dataclasses import asdict
from unittest.mock import MagicMock

import duckdb
import pytest
from requests import HTTPError

from openhound_jamf.lookup import JamfLookup
from openhound_jamf.main import app
from openhound_jamf.models.cloudintegration import CloudIntegrationSnapshot
from openhound_jamf.models.tenant import Tenant
from openhound_jamf.source import SourceContext, cloud_integrations


def integration(enabled):
    """Build a synthetic cloud-provider summary with the requested enabled state."""
    return {
        "id": "1001",
        "displayName": "Entra ID",
        "enabled": enabled,
        "providerName": "AZURE",
        "providerDescription": "Entra ID",
    }


def collect_pages(pages, status_error=None):
    """Collect configured mock provider pages and return emitted rows and the client."""
    client = MagicMock()
    responses = []
    for page in pages:
        response = MagicMock()
        response.json.return_value = page
        response.raise_for_status.side_effect = status_error
        responses.append(response)
    client.get.side_effect = responses
    return list(cloud_integrations(SourceContext(client=client))), client


@pytest.mark.parametrize(
    "enabled_values,expected",
    [([], False), ([False], False), ([False, True], True), ([True, True], True)],
)
def test_snapshot_enabled_status(enabled_values, expected):
    """Verify the tenant flag reflects whether any collected provider is enabled."""
    rows, _ = collect_pages(
        [
            {
                "totalCount": len(enabled_values),
                "results": [integration(value) for value in enabled_values],
            }
        ]
    )
    assert len(rows) == 1
    snapshot = CloudIntegrationSnapshot.model_validate(rows[0])
    assert snapshot.cloudintegrationenabled is expected
    assert snapshot.total_count == len(enabled_values)
    assert CloudIntegrationSnapshot not in app.assets


def test_enabled_integration_on_later_page():
    """Verify provider pagination includes enabled integrations beyond the first page."""
    rows, client = collect_pages(
        [
            {"totalCount": 2, "results": [integration(False)]},
            {"totalCount": 2, "results": [{**integration(True), "id": "1002"}]},
        ]
    )
    assert rows[0]["cloudintegrationenabled"] is True
    assert rows[0]["total_count"] == 2
    assert [call.kwargs["params"]["page"] for call in client.get.call_args_list] == [
        0,
        1,
    ]


@pytest.mark.parametrize(
    "pages",
    [
        [{"totalCount": 1, "results": []}],
        [{"totalCount": 0, "results": [integration(True)]}],
        [
            {"totalCount": 2, "results": [integration(False)]},
            {"totalCount": 3, "results": []},
        ],
        [{"totalCount": 1, "results": [integration("false")]}],
        [{"totalCount": 1, "results": [{"id": "1001"}]}],
    ],
)
def test_failed_collection_never_emits_disabled_snapshot(pages):
    # OpenHound's resource wrapper logs errors and suppresses the failed resource.
    """Verify invalid or incomplete enumeration emits no misleading disabled snapshot."""
    rows, _ = collect_pages(pages)
    assert rows == []


def test_http_failure_never_emits_snapshot():
    """Verify a provider enumeration HTTP error emits no snapshot."""
    rows, _ = collect_pages([{}], status_error=HTTPError("403 Forbidden"))
    assert rows == []


@pytest.mark.parametrize("enabled", [False, True])
def test_lookup_exports_native_tenant_boolean(enabled):
    """Verify tenant conversion exports the stored integration flag as a boolean."""
    with duckdb.connect() as con:
        con.execute("CREATE SCHEMA jamf")
        con.execute("CREATE TABLE jamf.tenant AS SELECT 'example.jamfcloud.com' AS id")
        con.execute(
            "CREATE TABLE jamf.cloud_integrations (cloudintegrationenabled BOOLEAN)"
        )
        con.execute("INSERT INTO jamf.cloud_integrations VALUES (?)", [enabled])
        tenant = Tenant(id="example.jamfcloud.com", name="example.jamfcloud.com")
        tenant._lookup = JamfLookup(con)
        assert (
            asdict(tenant.as_node)["properties"]["cloudintegrationenabled"] is enabled
        )


@pytest.mark.parametrize("values", [[True, False], [None], ["False"]])
def test_lookup_rejects_multiple_or_invalid_snapshots(values):
    with duckdb.connect() as con:
        con.execute("CREATE SCHEMA jamf")
        column_type = "VARCHAR" if values == ["False"] else "BOOLEAN"
        con.execute(
            f"CREATE TABLE jamf.cloud_integrations (cloudintegrationenabled {column_type})"
        )
        for value in values:
            con.execute("INSERT INTO jamf.cloud_integrations VALUES (?)", [value])
        with pytest.raises(RuntimeError):
            JamfLookup(con).cloud_integration_enabled()


def test_lookup_rejects_missing_schema():
    with duckdb.connect() as con:
        with pytest.raises(duckdb.CatalogException):
            JamfLookup(con).cloud_integration_enabled()


@pytest.mark.usefixtures("mock_dlt_requests")
@pytest.mark.parametrize("enabled_values", [[], [False], [False, True]])
def test_collection_preprocessing_and_tenant_export(
    tmp_path, monkeypatch, mock_jamf_api, enabled_values
):
    """Verify mocked collection and preprocessing preserve the tenant integration flag."""
    from openhound.core.collect import Collector
    from openhound.core.preproc import PreProcessor

    from openhound_jamf.auth import JamfPasswordCredentials
    from openhound_jamf.source import source

    monkeypatch.setenv("DLT_DATA_DIR", str(tmp_path / "dlt"))
    mock_jamf_api.app.state.cloud_idp_pages = [
        {
            "totalCount": len(enabled_values),
            "results": [
                {**integration(enabled), "id": str(index)}
                for index, enabled in enumerate(enabled_values)
            ],
        }
    ]
    credentials = JamfPasswordCredentials(
        host="https://jamf.test", username="test", password="test"
    )
    collected = tmp_path / "collected"
    resources = source(credentials=credentials).with_resources(
        "cloud_integrations", "tenant"
    )
    info = Collector(name="jamf", output_path=collected).run(resources)
    assert not info.has_failed_jobs

    lookup_file = tmp_path / "lookup.duckdb"
    info = PreProcessor(
        name="jamf",
        input_path=collected / "jamf",
        output_file=lookup_file,
    ).run(resources={"cloud_integrations": "cloud_integrations", "tenant": "tenant"})
    assert not info.has_failed_jobs

    with duckdb.connect(str(lookup_file)) as con:
        count, results = con.execute(
            "SELECT total_count, results FROM jamf.cloud_integrations"
        ).fetchone()
        import json

        assert count == len(enabled_values)
        assert len(json.loads(results)) == len(enabled_values)
        tenant = Tenant(id="jamf.test", name="jamf.test")
        tenant._lookup = JamfLookup(con)
        assert asdict(tenant.as_node)["properties"]["cloudintegrationenabled"] is any(
            enabled_values
        )
