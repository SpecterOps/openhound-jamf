import duckdb


def cloud_snapshot_rows(con, schema: str, columns: str):
    """Read snapshot rows, treating only a missing snapshot table as empty."""
    try:
        return con.execute(
            f"SELECT {columns} FROM {schema}.cloud_integrations"
        ).fetchall()
    except duckdb.CatalogException:
        schema_exists, table_exists = con.execute(
            """
            SELECT
                EXISTS (SELECT 1 FROM information_schema.schemata
                        WHERE catalog_name = current_database() AND lower(schema_name) = lower(?)),
                EXISTS (SELECT 1 FROM information_schema.tables
                        WHERE table_catalog = current_database() AND lower(table_schema) = lower(?)
                          AND lower(table_name) = 'cloud_integrations')
            """,
            [schema, schema],
        ).fetchone()
        if schema_exists and not table_exists:
            return []
        raise
