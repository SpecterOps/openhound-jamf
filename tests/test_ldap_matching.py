import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from unittest.mock import MagicMock

import duckdb
import pytest
from pydantic import ValidationError
from requests import HTTPError

from openhound_jamf.lookup import JamfLookup
from openhound_jamf.models.account import Account
from openhound_jamf.models.cloudintegration import CloudIntegrationSnapshot
from openhound_jamf.models.cloudldap import (
    CloudUserResponse,
    CloudUserTest,
    matched_cloud_users,
)
from openhound_jamf.source import SourceContext
from openhound_jamf.transforms import cloud_ldap_matches

USER_ID = "11111111-1111-4111-8111-111111111111"
OTHER_ID = "22222222-2222-4222-8222-222222222222"


def provider(id="1002", enabled=True, kind="AZURE"):
    """Build a synthetic provider summary with configurable identity, state, and kind."""
    return dict(
        id=id,
        displayName="Directory",
        enabled=enabled,
        providerName=kind,
        providerDescription="Directory",
    )


def result(uuid=USER_ID, email="user@example.com", server="1002"):
    """Build a synthetic user search result with email and provider-bound UUIDs."""
    return dict(
        id=uuid,
        uuid=uuid,
        serverId=server,
        attributes={"emailAddress": email, "buildingName": None},
    )


def account(**overrides):
    """Build Jamf directory account details with synthetic identity and LDAP association."""
    return dict(
        id=45,
        name="testu",
        full_name="Test User",
        email="user@example.com",
        enabled="Enabled",
        access_level="Full Access",
        privilege_set="Custom",
        directory_user=True,
        ldap_server={"id": 1002, "name": "Directory"},
        **overrides,
    )


def context(providers=None, results=None):
    """Build a source context whose provider and user-search responses are mocked."""
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
    """Build validated user search evidence with optional field overrides."""
    values = dict(
        provider_id="1002",
        provider_name="AZURE",
        requested_username=account()["name"],
        status="success",
        total_count=len(results),
        results=results,
    )
    values.update(overrides)
    return CloudUserTest.model_validate(values)


@pytest.mark.parametrize("association", [None, {}, [], [{"id": 1002}], {"id": 1002}])
def test_account_association_normalization(association):
    """Verify missing, single, and list LDAP associations normalize for account validation."""
    values = account()
    values["ldap_server"] = association
    parsed = Account.model_validate(values)
    assert len(parsed.ldap_server) == (1 if association else 0)


def test_plural_association_alias_and_missing_key():
    """Verify absent associations default empty and the plural LDAP alias accepts lists."""
    values = account()
    del values["ldap_server"]
    assert Account.model_validate(values).ldap_server == []
    values["ldap_servers"] = [{"id": 1002}, {"id": 1003}]
    assert [server.id for server in Account.model_validate(values).ldap_server] == [
        "1002",
        "1003",
    ]


def test_azure_search_body_and_shared_snapshot():
    """Verify user searches send the username and parallel resources share one snapshot."""
    ctx = context()
    tests = ctx.account_cloud_tests(account())
    assert tests[0]["status"] == "success"
    ctx.client.post.assert_called_once_with(
        "/api/v1/cloud-idp/1002/test-user", json={"username": account()["name"]}
    )
    with ThreadPoolExecutor(max_workers=4) as pool:
        snapshots = list(pool.map(lambda _: ctx.cloud_snapshot(), range(8)))
    assert all(snapshot is snapshots[0] for snapshot in snapshots)
    assert ctx.client.get.call_count == 1


@pytest.mark.parametrize(
    "change,providers",
    [
        ({"directory_user": False}, [provider()]),
        ({"ldap_server": []}, [provider()]),
        ({}, [provider(enabled=False)]),
        ({}, [provider(id="9999")]),
        ({}, []),
    ],
)
def test_ineligible_accounts_do_not_post(change, providers):
    """Verify local accounts and missing, disabled, or unrelated providers skip searches."""
    ctx = context(providers)
    values = account()
    values.update(change)
    assert ctx.account_cloud_tests(values) == []
    ctx.client.post.assert_not_called()


def test_google_logs_once_and_never_posts(caplog):
    """Verify Google lookups emit one unsupported warning and no search POSTs."""
    ctx = context([provider(kind="GOOGLE")])
    for _ in range(2):
        assert ctx.account_cloud_tests(account())[0]["status"] == "unsupported"
    ctx.client.post.assert_not_called()
    assert caplog.text.count("Google cloud integrations are unsupported.") == 1


def test_each_associated_azure_provider_is_queried():
    """Verify each associated Azure provider is queried with provider-bound responses."""
    ctx = context([provider(), provider(id="1003")])
    # Separate responses preserve the provider binding on each returned identity.
    first, second = MagicMock(), MagicMock()
    first.json.return_value = {"totalCount": 1, "results": [result()]}
    second.json.return_value = {"totalCount": 1, "results": [result(server="1003")]}
    ctx.client.post.side_effect = [first, second]
    values = account()
    values["ldap_server"] = [{"id": 1002}, {"id": 1003}]
    assert [test["status"] for test in ctx.account_cloud_tests(values)] == [
        "success",
        "success",
    ]
    assert ctx.client.post.call_count == 2


@pytest.mark.parametrize("failure", ["http", "uuid", "provider", "count", "identity"])
def test_invalid_or_failed_search_is_error_evidence(failure):
    """Verify HTTP errors and invalid user responses produce unusable error evidence."""
    ctx = context()
    payload = {"totalCount": 1, "results": [result()]}
    if failure == "http":
        ctx.client.post.return_value.raise_for_status.side_effect = HTTPError("403")
    elif failure == "uuid":
        payload["results"][0]["uuid"] = "invalid"
    elif failure == "provider":
        payload["results"][0]["serverId"] = "other"
    elif failure == "count":
        payload["totalCount"] = 2
    else:
        payload["results"][0]["id"] = OTHER_ID
    ctx.client.post.return_value.json.return_value = payload
    test = CloudUserTest.model_validate(ctx.account_cloud_tests(account())[0])
    assert test.status == "error"
    assert matched_cloud_users(test, "user@example.com") == []


@pytest.mark.parametrize(
    "results,email,expected",
    [
        ([], "user@example.com", []),
        ([result()], "different@example.com", [(USER_ID.upper(), "single_result")]),
        (
            [result(), result(OTHER_ID, "other@example.com")],
            " USER@EXAMPLE.COM ",
            [(USER_ID.upper(), "email")],
        ),
        ([result(), result(OTHER_ID)], "", []),
        ([result(), result(OTHER_ID)], "absent@example.com", []),
        (
            [result(), result(OTHER_ID)],
            "user@example.com",
            [(USER_ID.upper(), "email"), (OTHER_ID.upper(), "email")],
        ),
        ([result(), result()], "user@example.com", [(USER_ID.upper(), "email")]),
    ],
)
def test_resolution_rules(results, email, expected):
    """Verify single-result, email-based, empty, and duplicate user resolution rules."""
    assert matched_cloud_users(evidence(results), email) == expected


def test_zero_search_result_is_success():
    """Verify an empty directory search is valid evidence rather than an API failure."""
    assert context(results=[]).account_cloud_tests(account())[0]["status"] == "success"


@pytest.mark.parametrize(
    "change",
    [
        "local",
        "disabled",
        "unassociated",
        "provider_disabled",
        "wrong_username",
        "error",
    ],
)
def test_preprocessing_rejects_ineligible_evidence(change):
    """Verify preprocessing excludes local, disabled, unassociated, or invalid user evidence."""
    values = account()
    test = evidence([result()]).model_dump(mode="json")
    providers = [provider()]
    if change == "local":
        values["directory_user"] = False
    if change == "disabled":
        values["enabled"] = "Disabled"
    if change == "unassociated":
        values["ldap_server"] = [{"id": 9999}]
    if change == "provider_disabled":
        providers = [provider(enabled=False)]
    if change == "wrong_username":
        test["requested_username"] = "other"
    if change == "error":
        test["status"] = "error"
    with lookup_db(values, [test], providers) as con:
        cloud_ldap_matches(con)
        assert JamfLookup(con).ldap_match_user_ids(45) == []


def lookup_db(values, tests, providers=None):
    """Create an in-memory lookup database containing synthetic account and search evidence."""
    con = duckdb.connect()
    con.execute("CREATE SCHEMA jamf")
    con.execute(
        "CREATE TABLE jamf.account_details (id BIGINT, name VARCHAR, email VARCHAR, directory_user BOOLEAN, enabled VARCHAR, ldap_server JSON, cloud_idp_user_tests JSON)"
    )
    con.execute(
        "INSERT INTO jamf.account_details VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
            values["id"],
            values["name"],
            values["email"],
            values["directory_user"],
            values["enabled"],
            json.dumps(values["ldap_server"]),
            json.dumps(tests),
        ],
    )
    providers = [provider()] if providers is None else providers
    snapshot = CloudIntegrationSnapshot(
        total_count=len(providers),
        results=providers,
        cloudintegrationenabled=any(p["enabled"] for p in providers),
    )
    con.execute(
        "CREATE TABLE jamf.cloud_integrations (total_count BIGINT, results JSON, cloudintegrationenabled BOOLEAN)"
    )
    con.execute(
        "INSERT INTO jamf.cloud_integrations VALUES (?, ?, ?)",
        [
            snapshot.total_count,
            json.dumps(snapshot.model_dump(mode="json")["results"]),
            snapshot.cloudintegrationenabled,
        ],
    )
    con.execute("CREATE TABLE jamf.tenant AS SELECT 'jamf.test' AS id")
    return con


def test_preprocessing_and_edge_identity_deduplicate_matches():
    """Verify duplicate evidence produces one traversable Azure-to-Jamf account edge."""
    values = account()
    test = evidence([result()]).model_dump(mode="json")
    with lookup_db(values, [test, test]) as con:
        cloud_ldap_matches(con)
        parsed = Account.model_validate(values)
        parsed._lookup = JamfLookup(con)
        edges = list(parsed._ldap_match_edges)
        assert len(edges) == 1
        edge = asdict(edges[0])
        assert edge["kind"] == "jamf_LDAPMatch"
        assert edge["start"] == {
            "kind": "AZUser",
            "match_by": "property",
            "property_matchers": [
                {"key": "objectid", "value": USER_ID.upper(), "operator": "equals"},
            ],
        }
        assert edge["end"] == {"match_by": "id", "value": parsed.as_node.id}
        assert edge["properties"]["traversable"] is True


def test_search_requires_complete_response():
    """Verify a user response with a mismatched result count fails validation."""
    with pytest.raises(ValidationError):
        CloudUserResponse.model_validate({"totalCount": 2, "results": [result()]})


@pytest.mark.usefixtures("mock_dlt_requests")
@pytest.mark.parametrize("outcome", ["single", "multiple", "empty", "error", "google"])
def test_collect_preprocess_convert_offline(
    tmp_path, monkeypatch, mock_jamf_api, outcome
):
    """Verify the mocked account pipeline emits matching edges without conversion API calls."""
    from openhound.core.collect import Collector
    from openhound.core.convert import Converter
    from openhound.core.preproc import PreProcessor

    from openhound_jamf.auth import JamfPasswordCredentials
    from openhound_jamf.models.tenant import Tenant
    from openhound_jamf.source import source

    monkeypatch.setenv("DLT_DATA_DIR", str(tmp_path / "dlt"))
    mock_jamf_api.app.state.cloud_idp_pages = [
        {
            "totalCount": 1,
            "results": [
                provider(id="1", kind="GOOGLE" if outcome == "google" else "AZURE")
            ],
        }
    ]
    results = (
        []
        if outcome == "empty"
        else [result(server="1", email="john.smith@company.com")]
    )
    if outcome == "multiple":
        results.append(result(OTHER_ID, email="other@example.com", server="1"))
    mock_jamf_api.app.state.cloud_user_response = {
        "totalCount": len(results),
        "results": results,
    }
    if outcome == "error":
        mock_jamf_api.app.state.cloud_user_status = 403
    credentials = JamfPasswordCredentials(
        host="https://jamf.test", username="test", password="test"
    )

    def selected_source():
        """Select account details, tenant, and provider summaries for the pipeline test."""
        return source(credentials=credentials).with_resources(
            "account_details", "tenant", "cloud_integrations"
        )

    collected = tmp_path / "collected"
    info = Collector(name="jamf", output_path=collected).run(selected_source())
    assert not info.has_failed_jobs
    if outcome != "google":
        assert mock_jamf_api.app.state.last_cloud_user_request == (
            "1",
            {"username": "John Smith"},
        )
    lookup_file = tmp_path / "lookup.duckdb"
    info = PreProcessor(
        name="jamf",
        input_path=collected / "jamf",
        output_file=lookup_file,
        transformer=cloud_ldap_matches,
    ).run(
        resources={
            "account_details": "account_details",
            "tenant": "tenant",
            "cloud_integrations": "cloud_integrations",
        }
    )
    assert not info.has_failed_jobs
    calls_before_convert = list(mock_jamf_api.app.state.calls)
    output = tmp_path / "output"
    output.mkdir()
    with duckdb.connect(str(lookup_file)) as con:
        raw_tests = json.loads(
            con.execute(
                "SELECT cloud_idp_user_tests FROM jamf.account_details"
            ).fetchone()[0]
        )
        assert raw_tests[0]["status"] == (
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
        ).run(selected_source(), [Account, Tenant], {})
        assert not info.has_failed_jobs
    graphs = [json.loads(path.read_text())["graph"] for path in output.glob("*.json")]
    nodes = [node for graph in graphs for node in graph["nodes"]]
    edges = [
        edge
        for graph in graphs
        for edge in graph["edges"]
        if edge["kind"] == "jamf_LDAPMatch"
    ]
    assert any("jamf_Account" in node["kinds"] for node in nodes)
    assert len(edges) == (1 if outcome in ("single", "multiple") else 0)
    if edges:
        assert edges[0]["start"]["property_matchers"][0]["value"] == USER_ID.upper()
        assert edges[0]["properties"]["traversable"] is True
    assert mock_jamf_api.app.state.calls == calls_before_convert
