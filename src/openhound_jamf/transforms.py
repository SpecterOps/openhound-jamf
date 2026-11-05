import json
import logging

import duckdb
from pydantic import ValidationError

from openhound_jamf.cloud_snapshot import cloud_snapshot_rows

logger = logging.getLogger(__name__)


def cloud_ldap_matches(con, schema: str = "jamf") -> None:
    """Resolve only collected, enabled, account-associated Azure provider evidence."""
    # Imported lazily: main.py imports this module before constructing app.
    from openhound_jamf.models.cloudintegration import CloudIntegrationSnapshot
    from openhound_jamf.models.cloudldap import (
        CloudUserTest,
        LDAPServer,
        matched_cloud_users,
        normalize_ldap_servers,
    )

    con.execute(f"""
        CREATE OR REPLACE TABLE {schema}.cloud_ldap_matches (
            account_id BIGINT, provider_id VARCHAR, azure_object_id VARCHAR,
            match_method VARCHAR
        )
    """)
    columns = {
        row[0] for row in con.execute(f"DESCRIBE {schema}.account_details").fetchall()
    }
    required = {"cloud_idp_user_tests", "ldap_server"}
    if not required.issubset(columns):
        logger.warning(
            "LDAP matching evidence is missing; recollect account details to generate jamf_LDAPMatch edges"
        )
        return

    def decode(value):
        return json.loads(value) if isinstance(value, str) else value

    snapshots = cloud_snapshot_rows(
        con, schema, "total_count, results, cloudintegrationenabled"
    )
    if not snapshots:
        return
    if len(snapshots) > 1:
        raise ValueError(
            "Expected one Cloud Identity Provider snapshot for LDAP matching"
        )
    count, results, enabled = snapshots[0]
    snapshot = CloudIntegrationSnapshot.model_validate(
        {
            "total_count": count,
            "results": decode(results),
            "cloudintegrationenabled": enabled,
        }
    )
    providers = {
        provider.id: provider
        for provider in snapshot.results
        if provider.enabled and provider.provider_name == "AZURE"
    }
    matches = set()
    accounts = con.execute(f"""
        SELECT id, name, email, directory_user, enabled, ldap_server, cloud_idp_user_tests
        FROM {schema}.account_details
    """).fetchall()
    for account_id, name, email, directory_user, enabled, servers, tests in accounts:
        if not directory_user or enabled != "Enabled":
            continue
        try:
            associated = {
                LDAPServer.model_validate(server).id
                for server in normalize_ldap_servers(decode(servers))
            }
            for raw_test in decode(tests) or []:
                test = CloudUserTest.model_validate(raw_test)
                if (
                    test.provider_id not in associated
                    or test.provider_id not in providers
                ):
                    continue
                if test.requested_username != name:
                    continue
                resolved = matched_cloud_users(test, email or "")
                if len(resolved) > 1:
                    logger.warning(
                        "Multiple directory identities match account %s, provider %s",
                        account_id,
                        test.provider_id,
                    )
                for object_id, method in resolved:
                    matches.add((account_id, test.provider_id, object_id, method))
        except (ValidationError, ValueError, TypeError) as error:
            logger.warning(
                "Invalid LDAP evidence for account %s: %s",
                account_id,
                type(error).__name__,
            )
    if matches:
        con.executemany(
            f"INSERT INTO {schema}.cloud_ldap_matches VALUES (?, ?, ?, ?)",
            sorted(matches),
        )


def cloud_ldap_group_matches(con, schema: str = "jamf") -> None:
    """Resolve group search evidence against the group's own enabled Azure providers."""
    # Keep imports local because main.py imports transforms before constructing app.
    from openhound_jamf.models.cloudintegration import CloudIntegrationSnapshot
    from openhound_jamf.models.cloudldap import (
        CloudGroupTest,
        LDAPServer,
        matched_cloud_groups,
        normalize_ldap_servers,
    )

    con.execute(f"""
        CREATE OR REPLACE TABLE {schema}.cloud_ldap_group_matches (
            group_id BIGINT, provider_id VARCHAR, azure_object_id VARCHAR,
            match_method VARCHAR
        )
    """)
    columns = {
        row[0]
        for row in con.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_schema = ? AND table_name = ?",
            [schema, "account_group_details"],
        ).fetchall()
    }
    if not {"cloud_idp_group_tests", "ldap_server"}.issubset(columns):
        logger.warning(
            "Group LDAP matching evidence is missing; recollect group details to generate jamf_LDAPMatch edges"
        )
        return

    def decode(value):
        return json.loads(value) if isinstance(value, str) else value

    snapshots = cloud_snapshot_rows(
        con, schema, "total_count, results, cloudintegrationenabled"
    )
    if not snapshots:
        return
    if len(snapshots) > 1:
        raise ValueError(
            "Expected one Cloud Identity Provider snapshot for group LDAP matching"
        )
    count, results, enabled = snapshots[0]
    snapshot = CloudIntegrationSnapshot.model_validate(
        {
            "total_count": count,
            "results": decode(results),
            "cloudintegrationenabled": enabled,
        }
    )
    if not snapshot.cloudintegrationenabled:
        return
    providers = {
        provider.id
        for provider in snapshot.results
        if provider.enabled and provider.provider_name == "AZURE"
    }
    groups = con.execute(f"""
        SELECT id, name, ldap_server, cloud_idp_group_tests
        FROM {schema}.account_group_details
    """).fetchall()
    matches = set()
    for group_id, name, servers, tests in groups:
        try:
            associated = {
                LDAPServer.model_validate(server).id
                for server in normalize_ldap_servers(decode(servers))
            }
            if not associated:
                continue
            for raw_test in decode(tests) or []:
                test = CloudGroupTest.model_validate(raw_test)
                if (
                    test.provider_id not in associated
                    or test.provider_id not in providers
                ):
                    continue
                if test.requested_groupname != name:
                    continue
                resolved = matched_cloud_groups(test, name)
                if len(resolved) > 1:
                    logger.warning(
                        "Multiple directory groups match group %s, provider %s",
                        group_id,
                        test.provider_id,
                    )
                for object_id, method in resolved:
                    matches.add((group_id, test.provider_id, object_id, method))
        except (ValidationError, ValueError, TypeError) as error:
            logger.warning(
                "Invalid LDAP evidence for group %s: %s", group_id, type(error).__name__
            )
    if matches:
        con.executemany(
            f"INSERT INTO {schema}.cloud_ldap_group_matches VALUES (?, ?, ?, ?)",
            sorted(matches),
        )


def account_privileges(con, schema: str = "jamf") -> None:
    """Unnested privileges for accounts"""
    con.execute(f"""
        CREATE OR REPLACE TABLE {schema}.account_privileges AS
        SELECT
            a.id,
            a.name,
            a.access_level,
            a.privilege_set,
            a.enabled,
            site->>'$.id' AS site_id,
            p.unnested AS privilege
        FROM {schema}.account_details a,
        LATERAL unnest(
            from_json(privileges->'$.jss_objects', '["VARCHAR"]')
        ) AS p(unnested)
        WHERE a.privileges IS NOT NULL
          AND json_extract(a.privileges, '$.jss_objects') IS NOT NULL;
    """)


def group_privileges(con, schema: str = "jamf") -> None:
    """Unnested privileges for groups"""
    con.execute(f"""
        CREATE OR REPLACE TABLE {schema}.group_privileges AS
        SELECT
            a.id,
            a.name,
            a.access_level,
            a.privilege_set,
            site->>'$.id' AS site_id,
            p.unnested AS privilege
        FROM {schema}.account_group_details a,
        LATERAL unnest(
            from_json(privileges->'$.jss_objects', '["VARCHAR"]')
        ) AS p(unnested)
        WHERE a.privileges IS NOT NULL
          AND json_extract(a.privileges, '$.jss_objects') IS NOT NULL;
    """)


def api_privileges(con, schema: str = "jamf") -> None:
    """Unnested privileges for api integrations"""
    con.execute(f"""
        CREATE OR REPLACE TABLE {schema}.api_client_resolved_privileges AS
        SELECT
            c.id AS client_id,
            c.display_name AS client_name,
            c.enabled,
            r.display_name AS role_name,
            p.unnested AS privilege
        FROM {schema}.api_integrations c,
        LATERAL unnest(
            from_json(c.authorization_scopes, '["VARCHAR"]')
        ) AS s(scope),
        {schema}.api_roles r,
        LATERAL unnest(
            from_json(r.privileges, '["VARCHAR"]')
        ) AS p(unnested)
        WHERE r.display_name = s.scope;
    """)


def recurring_script_policies(con, schema: str = "jamf") -> None:
    """Table with recurring script policies"""
    con.execute(f"""
        CREATE OR REPLACE TABLE {schema}.recurring_script_policies AS
        SELECT
            p.id        AS policy_id,
            from_json(p.scope, '{{"all_computers": "BOOLEAN"}}').all_computers AS all_computers,
            from_json(p.scope, '{{"computers": [{{"id":"INTEGER"}}]}}').computers AS scope_computers,
            from_json(p.scope, '{{"exclusions": {{"computers": [{{"udid":"VARCHAR"}}]}}}}').exclusions.computers AS exclusion_computers,
            p.scripts            AS scripts
        FROM {schema}.policy_details p
        WHERE p.enabled = true
          AND p.frequency NOT LIKE '%per user%'
          AND p.frequency NOT LIKE '%per computer%'
          AND json_array_length(p.scripts) > 0
    """)


def policy_target_computers(con, schema: str = "jamf") -> None:
    """Table containing policies target computers"""
    con.execute(f"""
        CREATE OR REPLACE TABLE {schema}.recurring_policy_target_computers AS
        -- Step 1: policies targeting all computers
        SELECT
            rsp.policy_id,
            c.id AS computer_id
        FROM {schema}.recurring_script_policies rsp
        CROSS JOIN {schema}.computers c
        WHERE rsp.all_computers = true
            AND c.udid NOT IN (
              SELECT unnest(rsp.exclusion_computers).udid as cudid
            )
        UNION ALL
        -- Step 2: policies targeting specific computers
        SELECT
            rsp.policy_id,
            sc.value->>'id' AS computer_id
        FROM {schema}.recurring_script_policies rsp,
             LATERAL unnest(from_json(rsp.scope_computers, '["JSON"]')) AS sc(value)
        WHERE rsp.all_computers = false
    """)


def transforms(con: duckdb.DuckDBPyConnection, schema: str = "jamf") -> None:
    cloud_ldap_matches(con, schema)
    cloud_ldap_group_matches(con, schema)
    account_privileges(con, schema)
    group_privileges(con, schema)
    api_privileges(con, schema)
    recurring_script_policies(con, schema)
    policy_target_computers(con, schema)
