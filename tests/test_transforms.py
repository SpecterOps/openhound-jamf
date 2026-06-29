"""Tests for openhound_jamf models and transforms.

Covers model-level site validation, edge-generation correctness, and
DuckDB transform behaviour with the site JSON column.
"""

from __future__ import annotations

import json

import duckdb
import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_lookup(tenant: str = "test-tenant"):
    from unittest.mock import MagicMock

    lookup = MagicMock()
    lookup.tenant_id.return_value = tenant
    return lookup


def _make_account(extra: dict | None = None, lookup=None):
    from openhound_jamf.models.account import Account

    base = dict(
        id=1,
        name="alice",
        full_name="Alice Smith",
        email="alice@example.com",
        enabled="Enabled",
        access_level="Site Access",
        privilege_set="Administrator",
        directory_user=False,
    )
    if extra:
        base.update(extra)
    account = Account(**base)
    account._lookup = lookup or _make_lookup()
    return account


def _make_group(extra: dict | None = None, lookup=None):
    from openhound_jamf.models.group import Group

    base = dict(
        id=10,
        name="admins",
        access_level="Site Access",
        privilege_set="Administrator",
    )
    if extra:
        base.update(extra)
    group = Group(**base)
    group._lookup = lookup or _make_lookup()
    return group


# ---------------------------------------------------------------------------
# Model-level site coercion — Account
# ---------------------------------------------------------------------------

class TestAccountSiteCoercion:
    def test_missing_site_defaults_to_sentinel(self):
        account = _make_account()
        assert account.site.id == -1

    def test_explicit_none_site_becomes_sentinel(self):
        account = _make_account({"site": None})
        assert account.site.id == -1

    def test_sentinel_dict_stays_sentinel(self):
        account = _make_account({"site": {"id": -1}})
        assert account.site.id == -1

    def test_real_site_id_is_preserved(self):
        account = _make_account({"site": {"id": 42}})
        assert account.site.id == 42


# ---------------------------------------------------------------------------
# Model-level site coercion — Group
# ---------------------------------------------------------------------------

class TestGroupSiteCoercion:
    def test_missing_site_defaults_to_sentinel(self):
        group = _make_group()
        assert group.site.id == -1

    def test_explicit_none_site_becomes_sentinel(self):
        group = _make_group({"site": None})
        assert group.site.id == -1

    def test_sentinel_dict_stays_sentinel(self):
        group = _make_group({"site": {"id": -1}})
        assert group.site.id == -1

    def test_real_site_id_is_preserved(self):
        group = _make_group({"site": {"id": 42}})
        assert group.site.id == 42


# ---------------------------------------------------------------------------
# Edge tests — _admin_to_site_edges
# ---------------------------------------------------------------------------

class TestAdminToSiteEdges:
    def test_account_with_sentinel_site_emits_no_admin_to_site_edges(self):
        account = _make_account()  # site.id == -1
        edges = list(account._admin_to_site_edges)
        assert edges == []

    def test_account_with_real_site_emits_admin_to_site_edge(self):
        account = _make_account({"site": {"id": 42}})
        edges = list(account._admin_to_site_edges)
        from openhound_jamf.kinds import edges as ek
        assert len(edges) == 1
        assert edges[0].kind == ek.ADMIN_TO_SITE

    def test_group_with_sentinel_site_emits_no_admin_to_site_edges(self):
        group = _make_group()  # site.id == -1
        edges = list(group._admin_to_site_edges)
        assert edges == []

    def test_group_with_real_site_emits_admin_to_site_edge(self):
        group = _make_group({"site": {"id": 42}})
        edges = list(group._admin_to_site_edges)
        from openhound_jamf.kinds import edges as ek
        assert len(edges) == 1
        assert edges[0].kind == ek.ADMIN_TO_SITE


# ---------------------------------------------------------------------------
# DuckDB transform tests — site column with JSON sentinel
# ---------------------------------------------------------------------------

PRIVILEGES_JSON = json.dumps({"jss_objects": ["Read Computers"], "jss_settings": [], "jss_actions": []})
SENTINEL_SITE_JSON = json.dumps({"id": -1})


@pytest.fixture
def con():
    """In-memory DuckDB connection with the jamf schema."""
    c = duckdb.connect()
    c.execute("CREATE SCHEMA jamf")
    yield c
    c.close()


class TestDuckDBTransforms:
    def test_account_privileges_with_sentinel_site_does_not_raise(self, con):
        from openhound_jamf.transforms import account_privileges

        con.execute("""
            CREATE TABLE jamf.account_details (
                id INTEGER,
                name VARCHAR,
                access_level VARCHAR,
                privilege_set VARCHAR,
                enabled VARCHAR,
                site JSON,
                privileges JSON
            )
        """)
        con.execute(
            "INSERT INTO jamf.account_details VALUES (1, 'Alice', 'Full Access', 'Custom', 'Enabled', ?, ?)",
            [SENTINEL_SITE_JSON, PRIVILEGES_JSON],
        )

        account_privileges(con)

        rows = con.execute("SELECT id, site_id, privilege FROM jamf.account_privileges").fetchall()
        assert len(rows) == 1
        assert rows[0][1] == "-1"

    def test_group_privileges_with_sentinel_site_does_not_raise(self, con):
        from openhound_jamf.transforms import group_privileges

        con.execute("""
            CREATE TABLE jamf.account_group_details (
                id INTEGER,
                name VARCHAR,
                access_level VARCHAR,
                privilege_set VARCHAR,
                site JSON,
                privileges JSON
            )
        """)
        con.execute(
            "INSERT INTO jamf.account_group_details VALUES (10, 'Admins', 'Full Access', 'Custom', ?, ?)",
            [SENTINEL_SITE_JSON, PRIVILEGES_JSON],
        )

        group_privileges(con)

        rows = con.execute("SELECT id, site_id, privilege FROM jamf.group_privileges").fetchall()
        assert len(rows) == 1
        assert rows[0][1] == "-1"
