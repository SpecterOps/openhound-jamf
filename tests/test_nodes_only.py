import json
import runpy
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

import duckdb
import pytest
from dlt.common.runtime.run_context import RunContext, switched_run_context
from typer import BadParameter


@pytest.mark.usefixtures("mock_dlt_requests")
def test_preview_matches_full_graph_without_building_edges(
    tmp_path, monkeypatch, mock_jamf_api
):
    from openhound.core.collect import Collector
    from openhound.core.convert import Converter, Method
    from openhound.core.progress import Progress
    from openhound.main import app as cli
    from typer.testing import CliRunner

    from openhound_jamf.lookup import JamfLookup
    from openhound_jamf.kinds.nodes import API_CLIENT, CLOUD_INTEGRATION
    from openhound_jamf.main import app, nodes_only_enabled
    from openhound_jamf.models.cloudintegration import (
        CloudIntegrationAsset,
        CloudIntegrationNode,
    )
    from openhound_jamf.source import source

    monkeypatch.setenv("PIPELINES_DIR", str(tmp_path / "pipelines"))
    monkeypatch.setenv("SOURCES__SOURCE__JAMF__CREDENTIALS__HOST", "https://jamf.test")
    monkeypatch.setenv("SOURCES__SOURCE__JAMF__CREDENTIALS__USERNAME", "test")
    monkeypatch.setenv("SOURCES__SOURCE__JAMF__CREDENTIALS__PASSWORD", "test")
    monkeypatch.chdir(tmp_path)
    config_dir = tmp_path / ".dlt"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text("NodesOnly = true\n")
    cloud_page = mock_jamf_api.app.state.cloud_idp_pages[0]
    cloud_page["results"][0]["id"] = "1"
    cloud_page["results"][1]["enabled"] = False
    cloud_page["results"].append(
        {
            "id": "3",
            "displayName": "Google",
            "enabled": True,
            "providerName": "GOOGLE",
            "providerDescription": "Google",
        }
    )
    cloud_page["totalCount"] = len(cloud_page["results"])
    mock_jamf_api.app.state.cloud_azure_status["1002"] = 403
    group_details = json.loads(
        (Path(__file__).parent / "test_data/jss_resource/group-by-id.json").read_text()
    )
    group_details["group"]["ldap_server"] = {"id": 1, "name": "Directory Server"}
    mock_jamf_api.app.state.group_details_override = group_details

    raw = tmp_path / "raw"
    graph = tmp_path / "graph"
    graph.mkdir()
    collected = Collector("jamf", raw, [], Progress.log).run(source())
    collected.raise_on_failed_jobs()
    app.preprocessor(raw / "jamf", tmp_path / "lookup.duckdb", Progress.log)

    def serialize_graph_entry(entry):
        # OpenHound 0.9.10 uses asdict for both dataclasses and Pydantic nodes.
        if isinstance(entry, CloudIntegrationNode):
            return entry.model_dump()
        return asdict(entry)

    with (
        duckdb.connect("lookup.duckdb", read_only=True) as connection,
        patch("openhound.sources.opengraph.source.asdict", serialize_graph_entry),
    ):
        converted = Converter(
            name="jamf",
            input_path=raw / "jamf",
            lookup=JamfLookup(connection),
            output_path=graph,
            source_kind="jamf",
            progress=Progress.log,
        ).run(source(), app.assets, {})
        converted.raise_on_failed_jobs()

    nodes = [
        node
        for path in graph.glob("*.json")
        for node in json.loads(path.read_text())["graph"]["nodes"]
    ]
    node_ids = {node["id"] for node in nodes}
    assert any(API_CLIENT in node["kinds"] for node in nodes)
    assert sorted(
        node["properties"]["enabled"]
        for node in nodes
        if CLOUD_INTEGRATION in node["kinds"]
    ) == [False, True]
    assert {
        "api_roles",
        "cloud_azure_details",
        "cloud_user_test",
        "cloud_group_test",
    } <= set(mock_jamf_api.app.state.calls)
    mock_jamf_api.app.state.calls.clear()

    def fail_on_edges(self):
        pytest.fail(f"Preview evaluated edges on {type(self).__name__}")

    for model in app.assets:
        monkeypatch.setattr(model, "edges", property(fail_on_edges))

    def fail_on_cloud_properties(self):
        pytest.fail("Preview built cloud integration node properties")

    monkeypatch.setattr(
        CloudIntegrationAsset, "as_node", property(fail_on_cloud_properties)
    )

    preview_output = tmp_path / "preview-output"
    preview_output.mkdir()
    with (
        switched_run_context(RunContext(str(tmp_path))),
        patch.object(Converter, "run", side_effect=AssertionError("graph conversion")),
    ):
        monkeypatch.setenv("SOURCES__JAMF__NODESONLY", "false")
        assert not nodes_only_enabled()
        monkeypatch.delenv("SOURCES__JAMF__NODESONLY")
        result = CliRunner().invoke(cli, ["collect", "jamf", str(preview_output)])
        with pytest.raises(BadParameter, match="NodesOnly prints the count"):
            app.converter(
                input_path=raw / "jamf",
                output_path=graph,
                method=Method.ingest,
                progress=Progress.log,
            )
    assert result.exit_code == 0, result.output
    assert result.stdout.strip() == f"{len(node_ids)} Projected Nodes"
    assert not list(preview_output.iterdir())

    calls = set(mock_jamf_api.app.state.calls)
    assert "api_integrations" in calls
    assert mock_jamf_api.app.state.calls.count("cloud_integrations") == 1
    assert calls.isdisjoint(
        {
            "api_roles",
            "cloud_azure_details",
            "policies",
            "policy_details",
            "scripts",
            "script_details",
            "computerextensionattributes",
            "cloud_user_test",
            "cloud_group_test",
        }
    )


def test_scheduler_startup_does_not_run_preview(monkeypatch):
    monkeypatch.setenv("SOURCES__JAMF__NODESONLY", "true")
    monkeypatch.setenv("DESTINATION__BLOODHOUNDENTERPRISE__COLLECTOR_NAME", "jamf")
    monkeypatch.setenv(
        "DESTINATION__BLOODHOUNDENTERPRISE__URL", "https://bhe.example.invalid"
    )
    monkeypatch.setenv("DESTINATION__BLOODHOUNDENTERPRISE__TOKEN_ID", "test-id")
    monkeypatch.setenv("DESTINATION__BLOODHOUNDENTERPRISE__TOKEN_KEY", "test-key")
    scheduler = Path(__file__).parents[1] / "src" / "scheduler.py"

    with (
        patch("openhound_jamf.preview.print_projected_nodes") as preview,
        patch("openhound.scheduler.service.Service") as service,
    ):
        runpy.run_path(str(scheduler), run_name="__main__")

    service.assert_called_once_with(
        bhe_uri="https://bhe.example.invalid",
        token_id="test-id",
        token_key="test-key",
        collector_name="jamf",
    )
    service.return_value.start.assert_called_once_with()
    preview.assert_not_called()
