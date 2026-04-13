import duckdb


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
            p.name      AS policy_name,
            from_json(p.scope, '{{"all_computers": "BOOLEAN"}}').all_computers AS all_computers,
            from_json(p.scope, '{{"computers": [{{"id":"INTEGER","name":"VARCHAR","udid":"VARCHAR"}}]}}').computers AS scope_computers,
            from_json(p.scope, '{{"exclusions": {{"computers": [{{"id":"INTEGER","name":"VARCHAR","udid":"VARCHAR"}}]}}}}').exclusions.computers AS exclusion_computers,
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
    account_privileges(con, schema)
    group_privileges(con, schema)
    api_privileges(con, schema)
    recurring_script_policies(con, schema)
    policy_target_computers(con, schema)
