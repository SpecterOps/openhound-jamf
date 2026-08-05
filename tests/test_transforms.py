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


class TestAccountDirectoryBacking:
    def test_directory_user_is_not_emitted_as_local_account(self):
        account = _make_account({"directory_user": True})
        assert account.as_node.properties.local_account is False

    def test_non_directory_user_is_emitted_as_local_account(self):
        account = _make_account({"directory_user": False})
        assert account.as_node.properties.local_account is True


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
# SAML normalized output
# ---------------------------------------------------------------------------

def _make_saml_sso(model_cls, extra: dict | None = None, lookup=None):
    base = dict(
        configurationType="SAML",
        samlSettings={
            "userMapping": "EMAIL",
            "groupAttributeName": "http://schemas.xmlsoap.org/claims/Group",
            "groupRdnKey": " ",
            "idpProviderType": "OKTA",
            "idpUrl": "https://example.idp.com/app/id/sso/saml/metadata",
            "entityId": "https://jamf.test/saml/metadata",
            "metadataSource": "URL",
        },
        samlMetadata={
            "sp": {
                "entityId": "https://jamf.test/saml/metadata",
                "acsUrl": "https://jamf.test/saml/SSO",
                "acsBinding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                "assertionConsumerServices": [
                    {
                        "acsUrl": "https://jamf.test/saml/SSO",
                        "acsBinding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                        "index": "0",
                        "isDefault": True,
                    }
                ],
                "nameIdFormats": [
                    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
                ],
            },
            "idp": {
                "entityId": "http://www.okta.com/example-jamf-app",
                "ssoUrl": "https://example.idp.com/app/id/sso/saml",
                "ssoBinding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                "nameIdFormats": [
                    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
                ],
            },
            "errors": [],
        },
        ssoEnabled=True,
    )
    if extra:
        base.update(extra)
    asset = model_cls(**base)
    asset._lookup = lookup or _make_lookup()
    return asset


class TestSAMLNormalizedOutput:
    def test_service_provider_emits_route_and_account_edges(self):
        from openhound_jamf.kinds import edges as ek
        from openhound_jamf.kinds import nodes as nk
        from openhound_jamf.models.sso import SAMLServiceProvider

        lookup = _make_lookup()
        lookup.all_account_saml_bindings.return_value = [
            {
                "id": 1,
                "name": "alice",
                "full_name": "Alice Example",
                "email": "alice@example.com",
                "email_address": "alice@example.com",
                "enabled": "Enabled",
            },
            {
                "id": 2,
                "name": "bob",
                "full_name": "Bob Example",
                "email": "bob@example.com",
                "email_address": "bob@example.com",
                "enabled": "Disabled",
            },
        ]

        service_provider = _make_saml_sso(SAMLServiceProvider, lookup=lookup)

        node = service_provider.as_node
        assert node.kinds == [nk.SAML_SERVICE_PROVIDER]
        assert node.properties.enabled is True
        assert node.properties.sp_entity_id == "https://jamf.test/saml/metadata"
        assert node.properties.schema_contract_version == "opengraph-saml-v0.3.0"

        emitted_edges = list(service_provider.edges)
        assert [edge.kind for edge in emitted_edges].count(ek.SAML_IMPLEMENTS) == 1
        assert [edge.kind for edge in emitted_edges].count(ek.SAML_TRUSTS_ISSUER) == 1
        assert (
            [edge.kind for edge in emitted_edges].count(
                ek.SAML_HAS_ASSERTION_CONSUMER_SERVICE
            )
            == 1
        )

        account_edges = [
            edge for edge in emitted_edges if edge.kind == ek.SAML_HAS_ACCOUNT
        ]
        assert len(account_edges) == 2
        assert account_edges[0].properties.match_values == ["alice@example.com"]
        assert account_edges[0].properties.email_match_values == [
            "alice@example.com"
        ]
        assert account_edges[0].properties.account_state == "enabled"
        assert account_edges[1].properties.match_values == ["bob@example.com"]
        assert account_edges[1].properties.account_state == "disabled"
        assert all(
            edge.properties.schema_contract_version == "opengraph-saml-v0.3.0"
            for edge in emitted_edges
        )

        rule_edge = next(
            edge
            for edge in emitted_edges
            if edge.kind == ek.SAML_HAS_ACCOUNT_RESOLUTION_RULE
        )
        assert rule_edge.start.value == service_provider.as_node.id

    def test_email_mapping_emits_readable_v0_3_resolution_rule(self):
        from openhound_jamf.models.sso import SAMLAccountResolutionRule

        rule = _make_saml_sso(SAMLAccountResolutionRule)

        assert rule.as_node.properties.expression_language == "cel"
        assert (
            rule.as_node.properties.expression_profile
            == "saml_account_resolution_v1"
        )
        assert rule.as_node.properties.expression == (
            "assertion.email_match_values.exists(value, value in "
            "account.email_match_values)"
        )
        assert rule.as_node.properties.summary == (
            "Any assertion email value exactly matches an account email value"
        )

    def test_username_mapping_uses_explicit_account_field_values(self):
        from openhound_jamf.kinds import edges as ek
        from openhound_jamf.models.sso import (
            SAMLAccountResolutionField,
            SAMLAccountResolutionRule,
            SAMLServiceProvider,
        )

        lookup = _make_lookup()
        lookup.all_account_saml_bindings.return_value = [
            {"id": 1, "name": "alice", "enabled": "Enabled"}
        ]
        settings = {
            "userMapping": "USERNAME",
            "groupAttributeName": "group",
            "groupRdnKey": " ",
            "idpProviderType": "OKTA",
            "idpUrl": "https://example.idp.test/metadata",
            "entityId": "https://jamf.test/saml/metadata",
            "metadataSource": "URL",
        }
        extra = {"samlSettings": settings}
        service_provider = _make_saml_sso(
            SAMLServiceProvider, extra=extra, lookup=lookup
        )
        rule = _make_saml_sso(SAMLAccountResolutionRule, extra=extra)
        account_field = _make_saml_sso(SAMLAccountResolutionField, extra=extra)

        assert account_field.as_node.properties.name == "username"
        assert rule.as_node.properties.expression == (
            'account.fields.exists(field, field.name == "username" && '
            "assertion.scoped_exact_match_values.exists(value, value in "
            "field.match_values))"
        )
        emitted_edges = list(service_provider.edges)
        value_edge = next(
            edge
            for edge in emitted_edges
            if edge.kind == ek.SAML_HAS_ACCOUNT_RESOLUTION_VALUE
        )
        assert value_edge.properties.match_values == ["alice"]
        assert value_edge.properties.canonical_match_values == ["alice"]

    def test_issuer_node_preserves_exact_trusted_entity_id(self):
        from openhound_jamf.kinds import nodes as nk
        from openhound_jamf.models.sso import SAMLIssuer

        issuer = _make_saml_sso(SAMLIssuer)

        node = issuer.as_node
        assert node.kinds == [nk.SAML_ISSUER]
        assert node.properties.entity_id == "http://www.okta.com/example-jamf-app"
        assert node.properties.comparison_mode == "exact_trimmed"

    def test_acs_node_preserves_exact_route_key(self):
        from openhound_jamf.kinds import nodes as nk
        from openhound_jamf.models.sso import SAMLAssertionConsumerService

        acs = _make_saml_sso(SAMLAssertionConsumerService)

        node = acs.as_node
        assert node.kinds == [nk.SAML_ASSERTION_CONSUMER_SERVICE]
        assert node.properties.acs_url == "https://jamf.test/saml/SSO"
        assert node.properties.sp_entity_id == "https://jamf.test/saml/metadata"
        assert node.properties.route_key == "acs_url + sp_entity_id"

    def test_normalized_saml_node_avoids_reserved_objectid_property(self):
        from dataclasses import asdict

        from openhound_jamf.models.sso import SAMLServiceProvider

        node = _make_saml_sso(SAMLServiceProvider).as_node
        properties = asdict(node.properties)

        assert "objectid" not in properties
        assert properties["source_object_id"].startswith("jamf:")

    def test_unknown_account_state_is_not_treated_as_disabled(self):
        from openhound_jamf.kinds import edges as ek
        from openhound_jamf.models.sso import SAMLServiceProvider

        lookup = _make_lookup()
        lookup.all_account_saml_bindings.return_value = [
            {
                "id": 1,
                "name": "alice",
                "full_name": "Alice Example",
                "email": "alice@example.com",
                "email_address": "alice@example.com",
                "enabled": None,
            }
        ]

        service_provider = _make_saml_sso(SAMLServiceProvider, lookup=lookup)
        edge = next(
            edge for edge in service_provider.edges if edge.kind == ek.SAML_HAS_ACCOUNT
        )

        assert edge.properties.account_state == "unknown"

    def test_disabled_sso_keeps_structural_evidence(self):
        from openhound_jamf.kinds import edges as ek
        from openhound_jamf.models.sso import SAMLServiceProvider

        service_provider = _make_saml_sso(
            SAMLServiceProvider,
            extra={"ssoEnabled": False},
        )

        assert service_provider.as_node.properties.enabled is False
        edge_kinds = {edge.kind for edge in service_provider.edges}
        assert ek.SAML_IMPLEMENTS in edge_kinds
        assert ek.SAML_TRUSTS_ISSUER in edge_kinds
        assert ek.SAML_HAS_ASSERTION_CONSUMER_SERVICE in edge_kinds

    def test_missing_acs_withholds_acs_route_evidence(self):
        from openhound_jamf.kinds import edges as ek
        from openhound_jamf.models.sso import (
            SAMLAssertionConsumerService,
            SAMLServiceProvider,
        )

        metadata = {
            "sp": {"entityId": "https://jamf.test/saml/metadata"},
            "idp": {"entityId": "http://www.okta.com/example-jamf-app"},
            "errors": ["sp: metadata omits AssertionConsumerService"],
        }
        service_provider = _make_saml_sso(
            SAMLServiceProvider,
            extra={"samlMetadata": metadata},
        )
        acs = _make_saml_sso(
            SAMLAssertionConsumerService,
            extra={"samlMetadata": metadata},
        )

        assert acs.as_node is None
        assert all(
            edge.kind != ek.SAML_HAS_ASSERTION_CONSUMER_SERVICE
            for edge in service_provider.edges
        )
        assert service_provider.as_node.properties.metadata_errors == metadata["errors"]

    def test_unsupported_mapping_withholds_account_edges(self):
        from openhound_jamf.kinds import edges as ek
        from openhound_jamf.models.sso import SAMLServiceProvider

        settings = {
            "userMapping": "CUSTOM_ATTRIBUTE",
            "groupAttributeName": "http://schemas.xmlsoap.org/claims/Group",
            "groupRdnKey": " ",
            "idpProviderType": "OKTA",
            "idpUrl": "https://example.idp.com/app/id/sso/saml/metadata",
            "entityId": "https://jamf.test/saml/metadata",
            "metadataSource": "URL",
        }
        service_provider = _make_saml_sso(
            SAMLServiceProvider,
            extra={"samlSettings": settings},
        )

        edge_kinds = {edge.kind for edge in service_provider.edges}
        assert ek.SAML_TRUSTS_ISSUER in edge_kinds
        assert ek.SAML_HAS_ASSERTION_CONSUMER_SERVICE in edge_kinds
        assert ek.SAML_HAS_ACCOUNT not in edge_kinds

    def test_service_provider_emits_all_metadata_acs_routes(self):
        from openhound_jamf.kinds import edges as ek
        from openhound_jamf.models.sso import SAMLServiceProvider

        metadata = {
            "sp": {
                "entityId": "https://jamf.test/saml/metadata",
                "assertionConsumerServices": [
                    {"acsUrl": "https://jamf.test/saml/SSO", "index": "0", "isDefault": True},
                    {"acsUrl": "https://jamf.test/saml/alternate", "index": "1", "isDefault": False},
                ],
            },
            "idp": {"entityId": "http://www.okta.com/example-jamf-app"},
            "errors": [],
        }
        service_provider = _make_saml_sso(
            SAMLServiceProvider,
            extra={"samlMetadata": metadata},
        )

        acs_edges = [
            edge
            for edge in service_provider.edges
            if edge.kind == ek.SAML_HAS_ASSERTION_CONSUMER_SERVICE
        ]
        assert len(acs_edges) == 2


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
