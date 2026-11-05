import json

import duckdb
import pytest

from openhound_jamf.lookup import JamfLookup
from openhound_jamf.models.tenant import Tenant
from openhound_jamf.transforms import cloud_ldap_group_matches, cloud_ldap_matches

OBJECT_ID = "11111111-1111-4111-8111-111111111111"


@pytest.fixture
def database():
    with duckdb.connect() as con:
        con.execute("CREATE SCHEMA custom")
        con.execute(
            "CREATE TABLE custom.account_details (id BIGINT, name VARCHAR, email VARCHAR, directory_user BOOLEAN, enabled VARCHAR, ldap_server JSON, cloud_idp_user_tests JSON)"
        )
        con.execute(
            "CREATE TABLE custom.account_group_details (id BIGINT, name VARCHAR, ldap_server JSON, cloud_idp_group_tests JSON)"
        )
        common = {
            "provider_id": "1",
            "provider_name": "AZURE",
            "status": "success",
            "total_count": 1,
        }
        result = {"uuid": OBJECT_ID, "serverId": "1", "name": "example"}
        user_test = common | {"requested_username": "example", "results": [result]}
        group_test = common | {"requested_groupname": "example", "results": [result]}
        server = json.dumps({"id": 1})
        con.execute(
            "INSERT INTO custom.account_details VALUES (1, 'example', '', true, 'Enabled', ?, ?)",
            [server, json.dumps([user_test])],
        )
        con.execute(
            "INSERT INTO custom.account_group_details VALUES (1, 'example', ?, ?)",
            [server, json.dumps([group_test])],
        )
        yield con


def create_snapshot_table(con):
    con.execute(
        "CREATE TABLE custom.cloud_integrations (total_count BIGINT, results JSON, cloudintegrationenabled BOOLEAN)"
    )


@pytest.mark.parametrize("snapshot", ["missing", "empty_table", "empty_results"])
def test_no_snapshot_produces_empty_matches_and_disabled_tenant(database, snapshot):
    if snapshot != "missing":
        create_snapshot_table(database)
    if snapshot == "empty_results":
        database.execute(
            "INSERT INTO custom.cloud_integrations VALUES (0, '[]', false)"
        )
    # Existing matches from an earlier preprocessing run must not survive.
    database.execute("CREATE TABLE custom.cloud_ldap_matches (stale INTEGER)")
    database.execute("INSERT INTO custom.cloud_ldap_matches VALUES (1)")
    database.execute("CREATE TABLE custom.cloud_ldap_group_matches (stale INTEGER)")
    database.execute("INSERT INTO custom.cloud_ldap_group_matches VALUES (1)")

    cloud_ldap_matches(database, "custom")
    cloud_ldap_group_matches(database, "custom")
    lookup = JamfLookup(database, "custom")
    assert lookup.ldap_match_user_ids(1) == []
    assert lookup.ldap_match_group_ids(1) == []
    assert lookup.cloud_integration_enabled() is False
    database.execute("CREATE TABLE custom.tenant AS SELECT 'jamf.test' AS id")
    tenant = Tenant(id="jamf.test", name="jamf.test")
    tenant._lookup = lookup
    assert tenant.as_node.properties.cloudintegrationenabled is False


def test_snapshot_enables_matching_evidence(database):
    create_snapshot_table(database)
    provider = {
        "id": "1",
        "displayName": "example",
        "enabled": True,
        "providerName": "AZURE",
        "providerDescription": "example",
    }
    database.execute(
        "INSERT INTO custom.cloud_integrations VALUES (1, ?, true)",
        [json.dumps([provider])],
    )
    cloud_ldap_matches(database, "custom")
    cloud_ldap_group_matches(database, "custom")
    lookup = JamfLookup(database, "custom")
    assert lookup.ldap_match_user_ids(1) == [OBJECT_ID.upper()]
    assert lookup.ldap_match_group_ids(1) == [OBJECT_ID.upper()]
    assert lookup.cloud_integration_enabled() is True


def test_multiple_snapshots_still_fail(database):
    create_snapshot_table(database)
    database.execute(
        "INSERT INTO custom.cloud_integrations VALUES (0, '[]', false), (0, '[]', false)"
    )
    with pytest.raises(ValueError, match="one Cloud Identity Provider snapshot"):
        cloud_ldap_matches(database, "custom")
    with pytest.raises(ValueError, match="one Cloud Identity Provider snapshot"):
        cloud_ldap_group_matches(database, "custom")
    with pytest.raises(RuntimeError, match="one Cloud Identity Provider snapshot"):
        JamfLookup(database, "custom").cloud_integration_enabled()


@pytest.mark.parametrize("failure", ["missing_column", "broken_view"])
@pytest.mark.parametrize("operation", ["users", "groups", "lookup"])
def test_unrelated_query_errors_propagate(database, failure, operation):
    if failure == "missing_column":
        database.execute("CREATE TABLE custom.cloud_integrations (other BOOLEAN)")
        error = duckdb.BinderException
    else:
        create_snapshot_table(database)
        database.execute("ALTER TABLE custom.cloud_integrations RENAME TO backing")
        database.execute(
            "CREATE VIEW custom.cloud_integrations AS SELECT * FROM custom.backing"
        )
        database.execute("DROP TABLE custom.backing")
        error = duckdb.CatalogException
    with pytest.raises(error):
        if operation == "users":
            cloud_ldap_matches(database, "custom")
        elif operation == "groups":
            cloud_ldap_group_matches(database, "custom")
        else:
            JamfLookup(database, "custom").cloud_integration_enabled()
