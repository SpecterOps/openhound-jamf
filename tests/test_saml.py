"""Jamf SAML facts: library-built nodes and edges, and the converted graph."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import duckdb
import pytest
from openhound_saml_producer.testing.conformance import assert_conformant

from openhound_jamf.models import (
    SAMLAccountResolutionField,
    SAMLAccountResolutionRule,
    SAMLAssertionConsumerService,
    SAMLIssuer,
    SAMLServiceProvider,
)
from openhound_jamf.models.saml import SAML

TENANT = "jamf.test"
ACS = {
    "acsUrl": "https://jamf.test/saml/SSO",
    "acsBinding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
    "index": 0,
    "isDefault": True,
}


def _record(mapping: str = "EMAIL", *, idp: bool = True, acs=(ACS,)) -> dict[str, Any]:
    return {
        "configurationType": "SAML",
        "ssoEnabled": True,
        "samlSettings": {
            "groupAttributeName": "",
            "groupRdnKey": "",
            "userMapping": mapping,
            "entityId": "saml/metadata",
        },
        "samlMetadata": {
            "sp": {
                "entityId": "https://jamf.test/saml/metadata",
                "assertionConsumerServices": list(acs),
            },
            "idp": {"entityId": "http://idp.example/app"} if idp else None,
            "errors": [],
        },
    }


def _asset(cls, record: dict[str, Any], accounts: list[dict[str, Any]]):
    asset = cls(**record)
    asset._lookup = SimpleNamespace(
        tenant_id=lambda: TENANT,
        all_account_saml_bindings=lambda: accounts,
    )
    return asset


def _account(id_: int, name: str | None, email: str | None, enabled: str | None):
    return {"id": id_, "name": name, "email": email, "enabled": enabled}


ALL_ASSETS = (
    SAMLServiceProvider,
    SAMLAccountResolutionRule,
    SAMLAccountResolutionField,
    SAMLIssuer,
    SAMLAssertionConsumerService,
)


def test_without_entity_id_no_saml_fact_is_written():
    # SP fetch failed and the settings hold a relative path, not an entity ID.
    record = {**_record(), "samlMetadata": {**_record()["samlMetadata"], "sp": None}}
    record = {**record, "samlAcs": ACS}
    accounts = [_account(1, "jsmith", "j@example.com", "Enabled")]
    for cls in ALL_ASSETS:
        asset = _asset(cls, record, accounts)
        assert asset.as_node is None
        assert list(asset.edges) == []


def test_without_issuer_the_sp_facts_have_no_issuer_trust():
    record = {**_record(idp=False), "samlAcs": ACS}
    accounts = [_account(1, "jsmith", "j@example.com", "Enabled")]
    assert _asset(SAMLIssuer, record, accounts).as_node is None
    assert _asset(SAMLAssertionConsumerService, record, accounts).as_node is not None
    sp = _asset(SAMLServiceProvider, record, accounts)
    assert sp.as_node is not None
    kinds = {e.kind for e in sp.edges}
    assert "SAML_TrustsIssuer" not in kinds
    assert {"SAML_HasAssertionConsumerService", "SAML_HasAccount"} <= kinds


def test_service_provider_edges_follow_account_evidence():
    accounts = [
        _account(1, "a", "A@Example.com ", "Enabled"),
        _account(2, "b", "b@example.com", "Disabled"),
        _account(3, "c", "c@example.com", "Locked"),
        _account(4, "d", " ", "Enabled"),  # no usable email: no edge
    ]
    sp = _asset(
        SAMLServiceProvider, _record(acs=(ACS, {**ACS, "acsUrl": "x"})), accounts
    )
    edges = list(sp.edges)
    has_account = [e for e in edges if e.kind == "SAML_HasAccount"]

    assert [e.properties.account_state for e in has_account] == [
        "enabled",
        "disabled",
        "unknown",
    ]
    # The source value stays exact. The typed email value is folded.
    assert has_account[0].properties.match_values == ["A@Example.com "]
    assert has_account[0].properties.email_match_values == ["a@example.com"]
    assert len([e for e in edges if e.kind == "SAML_HasAssertionConsumerService"]) == 2
    assert {e.kind for e in edges} >= {"SAML_Implements", "SAML_TrustsIssuer"}


def test_username_rule_exists_only_when_an_account_gives_the_field():
    record = _record("USERNAME")
    nameless = [_account(1, None, "a@example.com", "Enabled")]
    assert _asset(SAMLAccountResolutionRule, record, nameless).as_node is None
    assert _asset(SAMLAccountResolutionField, record, nameless).as_node is None
    sp = _asset(SAMLServiceProvider, record, nameless)
    assert sp.as_node.properties.rule_count == 0
    assert not [e for e in sp.edges if "Rule" in e.kind or "Field" in e.kind]

    named = [_account(1, "jsmith", None, "Enabled")]
    field = _asset(SAMLAccountResolutionField, record, named).as_node
    rule = _asset(SAMLAccountResolutionRule, record, named).as_node
    assert field.properties.account_field_name == "username"
    assert 'field.name == "username"' in rule.properties.expression
    kinds = {e.kind for e in _asset(SAMLServiceProvider, record, named).edges}
    assert {
        "SAML_UsesAccountResolutionField",
        "SAML_HasAccountResolutionValue",
    } <= kinds


@pytest.mark.usefixtures("mock_dlt_requests")
@pytest.mark.parametrize(
    ("mapping", "idp_allowed"),
    [("EMAIL", True), ("USERNAME", True), ("EMAIL", False)],
    ids=["email", "username", "idp-origin-not-allowed"],
)
def test_converted_graph_is_conformant(
    tmp_path, monkeypatch, mock_jamf_api, mapping, idp_allowed
):
    from openhound.core.collect import Collector
    from openhound.core.convert import Converter
    from openhound.core.preproc import PreProcessor
    from openhound.core.progress import Progress

    from openhound_jamf.auth import JamfPasswordCredentials
    from openhound_jamf.lookup import JamfLookup
    from openhound_jamf.main import app
    from openhound_jamf.source import source
    from openhound_jamf.transforms import transforms

    monkeypatch.setenv("DLT_DATA_DIR", str(tmp_path / "dlt"))
    mock_jamf_api.app.state.sso_user_mapping = mapping
    credentials = JamfPasswordCredentials(
        host="https://jamf.test", username="u", password="p"
    )

    def make_source():
        return source(
            credentials=credentials,
            saml_metadata_allowed_origins="https://example.idp.com"
            if idp_allowed
            else "",
        )

    collected = tmp_path / "collected" / "jamf"
    Collector(name="jamf", output_path=tmp_path / "collected").run(make_source())
    lookup_file = tmp_path / "lookup.duckdb"
    tables = {path.name: path.name for path in collected.iterdir() if path.is_dir()}
    PreProcessor(
        name="jamf",
        input_path=collected,
        output_file=lookup_file,
        transformer=transforms,
        progress=Progress.log,
    ).run(tables)
    with duckdb.connect(str(lookup_file), read_only=True) as con:
        Converter(
            name="jamf",
            input_path=collected,
            lookup=JamfLookup(con),
            output_path=tmp_path / "graph",
            source_kind=app.source_kind,
            progress=Progress.log,
        ).run(make_source(), app.assets, {})

    nodes, edges = [], []
    for path in (tmp_path / "graph").glob("*.json"):
        graph = json.loads(path.read_text())["graph"]
        nodes += graph["nodes"]
        edges += graph["edges"]

    assert (
        assert_conformant({"graph": {"nodes": nodes, "edges": edges}}, producer=SAML)
        == []
    )
    # Only the library's kinds are on SAML nodes, and every native node keeps `jamf`.
    saml = [n for n in nodes if n["kinds"][0].startswith("SAML_")]
    assert all(n["kinds"] == [n["kinds"][0], "SAML"] for n in saml)
    assert all(n["kinds"][-1] == "jamf" for n in nodes if n not in saml)
    edge_kinds = {e["kind"] for e in edges}
    assert "SAML_Implements" in edge_kinds
    assert ("SAML_TrustsIssuer" in edge_kinds) == idp_allowed
    has_field = "SAML_AccountResolutionField" in {n["kinds"][0] for n in saml}
    assert has_field == (mapping == "USERNAME")
    assert ("SAML_HasAccountResolutionValue" in edge_kinds) == (mapping == "USERNAME")
