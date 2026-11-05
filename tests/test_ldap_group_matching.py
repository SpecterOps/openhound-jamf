import json
from dataclasses import asdict
from unittest.mock import MagicMock

import duckdb
import pytest
from pydantic import ValidationError
from requests import HTTPError

from openhound_jamf.lookup import JamfLookup
from openhound_jamf.models.cloudintegration import CloudIntegrationSnapshot
from openhound_jamf.models.cloudldap import (
    CloudGroupResponse,
    CloudGroupTest,
    matched_cloud_groups,
)
from openhound_jamf.models.group import Group
from openhound_jamf.source import SourceContext
from openhound_jamf.transforms import cloud_ldap_group_matches

GROUP_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
OTHER_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
GROUP_NAME = "Example Directory Group"


def provider(id="201", enabled=True, kind="AZURE"):
    """Build a synthetic provider summary with configurable identity, state, and kind."""
    return dict(
        id=id,
        displayName="Example Provider",
        enabled=enabled,
        providerName=kind,
        providerDescription="Example Directory",
    )


def result(uuid=GROUP_ID, name=GROUP_NAME, server="201"):
    """Build a synthetic group search result bound to the specified provider."""
    return dict(id=uuid, uuid=uuid, serverId=server, name=name)


def group():
    """Build Jamf directory group details associated with the synthetic provider."""
    return dict(
        id=1,
        name=GROUP_NAME,
        access_level="Full Access",
        privilege_set="Administrator",
        ldap_server={"id": 201, "name": "Example Provider"},
    )


def context(providers=None, results=None):
    """Build a source context whose provider and group-search responses are mocked."""
    providers = [provider()] if providers is None else providers
    results = [result()] if results is None else results
    client = MagicMock()
    client.get.return_value.json.return_value = {
        "totalCount": len(providers),
        "results": providers,
    }
    client.post.return_value.json.return_value = {
        "totalCount": len(results),
        "results": results,
    }
    return SourceContext(client=client)


def evidence(results, **overrides):
    """Build validated group search evidence with optional field overrides."""
    values = dict(
        provider_id="201",
        provider_name="AZURE",
        requested_groupname=GROUP_NAME,
        status="success",
        total_count=len(results),
        results=results,
    )
    values.update(overrides)
    return CloudGroupTest.model_validate(values)


def test_group_search_uses_displayname_and_cached_snapshot():
    """Verify group searches POST the display name and reuse provider enumeration."""
    ctx = context()
    assert ctx.group_cloud_tests(group())[0]["status"] == "success"
    ctx.client.post.assert_called_once_with(
        "/api/v1/cloud-idp/201/test-group", json={"groupname": GROUP_NAME}
    )
    ctx.cloud_snapshot()
    assert ctx.client.get.call_count == 1


@pytest.mark.parametrize(
    "servers,providers",
    [
        (None, [provider()]),
        ({}, [provider()]),
        ([], [provider()]),
        ({"id": 201}, []),
        ({"id": 201}, [provider(enabled=False)]),
        ({"id": 999}, [provider()]),
    ],
)
def test_ineligible_groups_never_post(servers, providers):
    """Verify missing associations, disabled providers, and unrelated providers skip searches."""
    ctx = context(providers)
    values = group()
    values["ldap_server"] = servers
    assert ctx.group_cloud_tests(values) == []
    ctx.client.post.assert_not_called()


def test_false_tenant_flag_blocks_group_search():
    """Verify a disabled tenant integration flag prevents group search POSTs."""
    ctx = context()
    ctx._cloud_snapshot = CloudIntegrationSnapshot(
        total_count=1, results=[provider()], cloudintegrationenabled=False
    )
    assert ctx.group_cloud_tests(group()) == []
    ctx.client.post.assert_not_called()


def test_google_logging_is_shared_with_account_searches(caplog):
    """Verify user and group searches share one Google warning and never POST to it."""
    ctx = context([provider(kind="GOOGLE")])
    for _ in range(2):
        assert ctx.group_cloud_tests(group())[0]["status"] == "unsupported"
    values = group() | {"directory_user": True}
    ctx.account_cloud_tests(values)
    assert caplog.text.count("Google cloud integrations are unsupported.") == 1
    ctx.client.post.assert_not_called()


def test_multiple_associated_providers_are_tested():
    """Verify group searches query each associated enabled provider with bound results."""
    ctx = context([provider(), provider(id="202")])
    first, second = MagicMock(), MagicMock()
    first.json.return_value = {"totalCount": 1, "results": [result()]}
    second.json.return_value = {"totalCount": 1, "results": [result(server="202")]}
    ctx.client.post.side_effect = [first, second]
    values = group()
    values["ldap_server"] = [{"id": 201}, {"id": 202}]
    assert [test["status"] for test in ctx.group_cloud_tests(values)] == [
        "success",
        "success",
    ]


@pytest.mark.parametrize(
    "failure", ["http", "uuid", "identity", "server", "incomplete"]
)
def test_failed_search_produces_error_evidence(failure):
    """Verify HTTP errors and invalid group responses produce unusable error evidence."""
    ctx = context()
    payload = {"totalCount": 1, "results": [result()]}
    if failure == "http":
        ctx.client.post.return_value.raise_for_status.side_effect = HTTPError("403")
    elif failure == "uuid":
        payload["results"][0]["uuid"] = "invalid"
    elif failure == "identity":
        payload["results"][0]["id"] = OTHER_ID
    elif failure == "server":
        payload["results"][0]["serverId"] = "202"
    else:
        payload["totalCount"] = 2
    ctx.client.post.return_value.json.return_value = payload
    test = CloudGroupTest.model_validate(ctx.group_cloud_tests(group())[0])
    assert test.status == "error"
    assert matched_cloud_groups(test, GROUP_NAME) == []


@pytest.mark.parametrize(
    "results,name,expected",
    [
        ([], GROUP_NAME, []),
        (
            [result(name="Different Name")],
            GROUP_NAME,
            [(GROUP_ID.upper(), "single_result")],
        ),
        (
            [result(), result(OTHER_ID, "Other")],
            " example directory group ",
            [(GROUP_ID.upper(), "name")],
        ),
        (
            [result(), result(OTHER_ID)],
            GROUP_NAME,
            [(GROUP_ID.upper(), "name"), (OTHER_ID.upper(), "name")],
        ),
        ([result(), result()], GROUP_NAME, [(GROUP_ID.upper(), "name")]),
        ([result(), result(OTHER_ID)], "", []),
        ([result(), result(OTHER_ID)], "No Match", []),
    ],
)
def test_group_matching_rules(results, name, expected):
    """Verify single-result, name-based, empty, and duplicate group resolution rules."""
    assert matched_cloud_groups(evidence(results), name) == expected


def test_generic_id_may_be_group_name_but_uuid_is_used():
    """Verify group names are allowed as generic IDs while UUIDs identify Azure groups."""
    payload = {"totalCount": 1, "results": [{**result(), "id": GROUP_NAME}]}
    parsed = CloudGroupResponse.model_validate(payload)
    assert str(parsed.results[0].uuid) == GROUP_ID
    with pytest.raises(ValidationError):
        CloudGroupResponse.model_validate({**payload, "totalCount": 2})


@pytest.mark.parametrize(
    "change",
    ["none", "unassociated", "disabled", "tenant_disabled", "wrong_name", "error"],
)
def test_preprocessing_and_edge_binding(change):
    """Verify preprocessing filters ineligible evidence and emits deduplicated group edges."""
    values = group()
    test = evidence([result()]).model_dump(mode="json")
    providers = [provider(enabled=change != "disabled")]
    if change == "unassociated":
        values["ldap_server"] = [{"id": 999}]
    if change == "wrong_name":
        test["requested_groupname"] = "Different Group"
    if change == "error":
        test["status"] = "error"
    with duckdb.connect() as con:
        con.execute("CREATE SCHEMA jamf")
        con.execute(
            "CREATE TABLE jamf.account_group_details (id BIGINT, name VARCHAR, ldap_server JSON, cloud_idp_group_tests JSON)"
        )
        con.execute(
            "INSERT INTO jamf.account_group_details VALUES (?, ?, ?, ?)",
            [
                1,
                GROUP_NAME,
                json.dumps(values["ldap_server"]),
                json.dumps([test, test]),
            ],
        )
        con.execute(
            "CREATE TABLE jamf.cloud_integrations (total_count BIGINT, results JSON, cloudintegrationenabled BOOLEAN)"
        )
        con.execute(
            "INSERT INTO jamf.cloud_integrations VALUES (?, ?, ?)",
            [1, json.dumps(providers), change not in ("disabled", "tenant_disabled")],
        )
        con.execute("CREATE TABLE jamf.tenant AS SELECT 'jamf.example.com' AS id")
        cloud_ldap_group_matches(con)
        lookup = JamfLookup(con)
        ids = lookup.ldap_match_group_ids(1)
        assert ids == ([GROUP_ID.upper()] if change == "none" else [])
        parsed = Group.model_validate(values)
        parsed._lookup = lookup
        edges = list(parsed._ldap_match_edges)
        if change == "none":
            assert len(edges) == 1
            edge = asdict(edges[0])
            assert edge["kind"] == "jamf_LDAPMatch"
            assert edge["start"]["kind"] == "AZGroup"
            assert edge["start"]["property_matchers"][0]["value"] == GROUP_ID.upper()
            assert edge["end"] == {"match_by": "id", "value": parsed.as_node.id}
            assert edge["properties"]["traversable"] is True
        else:
            assert edges == []


def test_old_collections_create_empty_lookup_table(caplog):
    """Verify collections lacking group search evidence produce an empty lookup and warning."""
    with duckdb.connect() as con:
        con.execute("CREATE SCHEMA jamf")
        con.execute("CREATE TABLE jamf.account_group_details (id BIGINT)")
        cloud_ldap_group_matches(con)
        assert JamfLookup(con).ldap_match_group_ids(1) == []
        assert "recollect group details" in caplog.text


@pytest.mark.usefixtures("mock_dlt_requests")
@pytest.mark.parametrize("outcome", ["single", "multiple", "empty", "error", "google"])
def test_group_collection_preprocessing_and_conversion(
    tmp_path, monkeypatch, mock_jamf_api, outcome
):
    """Verify the mocked group pipeline emits matching edges without conversion API calls."""
    from openhound.core.collect import Collector
    from openhound.core.convert import Converter
    from openhound.core.preproc import PreProcessor

    from openhound_jamf.auth import JamfPasswordCredentials
    from openhound_jamf.models.tenant import Tenant
    from openhound_jamf.source import source

    monkeypatch.setenv("DLT_DATA_DIR", str(tmp_path / "dlt"))
    mock_jamf_api.app.state.group_details_override = {"group": group()}
    mock_jamf_api.app.state.cloud_idp_pages = [
        {
            "totalCount": 1,
            "results": [provider(kind="GOOGLE" if outcome == "google" else "AZURE")],
        }
    ]
    results = [] if outcome == "empty" else [result()]
    if outcome == "multiple":
        results.append(result(OTHER_ID, "Other Group"))
    mock_jamf_api.app.state.cloud_group_response = {
        "totalCount": len(results),
        "results": results,
    }
    if outcome == "error":
        mock_jamf_api.app.state.cloud_group_status = 403
    credentials = JamfPasswordCredentials(
        host="https://jamf.test", username="test", password="test"
    )

    def selected_source():
        """Select group details, provider summaries, and tenant data for the pipeline test."""
        return source(credentials=credentials).with_resources(
            "account_group_details", "cloud_integrations", "tenant"
        )

    collected = tmp_path / "collected"
    assert (
        not Collector(name="jamf", output_path=collected)
        .run(selected_source())
        .has_failed_jobs
    )
    if outcome != "google":
        assert mock_jamf_api.app.state.last_cloud_group_request == (
            "201",
            {"groupname": GROUP_NAME},
        )
    lookup_file = tmp_path / "lookup.duckdb"
    info = PreProcessor(
        name="jamf",
        input_path=collected / "jamf",
        output_file=lookup_file,
        transformer=cloud_ldap_group_matches,
    ).run(
        resources={
            "account_group_details": "account_group_details",
            "cloud_integrations": "cloud_integrations",
            "tenant": "tenant",
        }
    )
    assert not info.has_failed_jobs
    calls_before = list(mock_jamf_api.app.state.calls)
    output = tmp_path / "output"
    output.mkdir()
    with duckdb.connect(str(lookup_file)) as con:
        tests = json.loads(
            con.execute(
                "SELECT cloud_idp_group_tests FROM jamf.account_group_details"
            ).fetchone()[0]
        )
        assert tests[0]["status"] == (
            "error"
            if outcome == "error"
            else "unsupported"
            if outcome == "google"
            else "success"
        )
        info = Converter(
            name="jamf",
            input_path=collected / "jamf",
            lookup=JamfLookup(con),
            output_path=output,
            source_kind="jamf",
        ).run(selected_source(), [Group, Tenant], {})
        assert not info.has_failed_jobs
    graphs = [json.loads(path.read_text())["graph"] for path in output.glob("*.json")]
    nodes = [node for graph in graphs for node in graph["nodes"]]
    assert any("jamf_Group" in node["kinds"] for node in nodes)
    edges = [
        edge
        for graph in graphs
        for edge in graph["edges"]
        if edge["kind"] == "jamf_LDAPMatch"
    ]
    assert len(edges) == (1 if outcome in ("single", "multiple") else 0)
    if edges:
        assert edges[0]["start"]["kind"] == "AZGroup"
        assert edges[0]["start"]["property_matchers"][0]["value"] == GROUP_ID.upper()
        assert edges[0]["end"]["value"] == next(
            node["id"] for node in nodes if "jamf_Group" in node["kinds"]
        )
    assert mock_jamf_api.app.state.calls == calls_before
