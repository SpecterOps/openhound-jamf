"""Origin policy and parsing of the SAML metadata fetch."""

from __future__ import annotations

import pytest

from openhound_jamf import saml_metadata
from openhound_jamf.saml_metadata import enrich_sso_metadata, parse_allowed_origins

BASE = "https://jamf.test"
IDP_ORIGIN = ("https", "idp.example", 443)
SP_XML = b"""<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="sp">
<md:SPSSODescriptor><md:AssertionConsumerService Location="https://jamf.test/acs" Binding="b" index="0001" isDefault="true"/>
</md:SPSSODescriptor></md:EntityDescriptor>"""
IDP_XML = b'<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="idp"/>'
# A byte search for "<!DOCTYPE" misses this body, but a parser expands the entity.
UTF16_ENTITY_XML = (
    '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE a [<!ENTITY x "idp">]>'
    '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="&x;"/>'
)
# An ACS index outside xs:unsignedShort (here, over 4300 digits) is invalid metadata.
OVERSIZED_INDEX_XML = (
    b'<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="idp">'
    b'<md:SPSSODescriptor><md:AssertionConsumerService Location="https://x/acs" Binding="b" index="'
    + b"9" * 4400
    + b'"/></md:SPSSODescriptor></md:EntityDescriptor>'
)
RECORD = {
    "configurationType": "SAML",
    "samlSettings": {
        "entityId": "/saml/metadata",
        "idpUrl": "https://idp.example/metadata",
    },
}


class FakeResponse:
    def __init__(
        self, status: int = 200, body: bytes = b"", location: str | None = None
    ):
        self.status_code = status
        self.headers = {"Location": location} if location else {}
        self._body = body

    def iter_content(self, chunk_size: int):
        yield self._body

    def raise_for_status(self) -> None: ...

    def close(self) -> None: ...


def _serve(monkeypatch, routes: dict[str, FakeResponse]) -> list[str]:
    requested: list[str] = []

    def get(url: str, **_: object) -> FakeResponse:
        requested.append(url)
        return routes[url]

    monkeypatch.setattr(saml_metadata.requests, "get", get)
    return requested


def test_allowlist_accepts_only_https_origins():
    assert parse_allowed_origins("https://idp.example") == {IDP_ORIGIN}
    for bad in ("http://idp.example", "https://idp.example/path", "idp.example"):
        with pytest.raises(ValueError):
            parse_allowed_origins(bad)


def test_metadata_gives_entity_ids_and_every_acs_endpoint(monkeypatch):
    _serve(
        monkeypatch,
        {
            "https://jamf.test/saml/metadata": FakeResponse(body=SP_XML),
            "https://idp.example/metadata": FakeResponse(body=IDP_XML),
        },
    )
    metadata = enrich_sso_metadata(RECORD, BASE, frozenset({IDP_ORIGIN}))[
        "samlMetadata"
    ]
    assert metadata["idp"]["entityId"] == "idp"
    assert metadata["sp"]["entityId"] == "sp"
    assert metadata["sp"]["assertionConsumerServices"] == [
        {
            "acsUrl": "https://jamf.test/acs",
            "acsBinding": "b",
            "index": 1,
            "isDefault": True,
        }
    ]
    assert metadata["errors"] == []


@pytest.mark.parametrize(
    ("allowed", "routes", "error"),
    [
        (
            frozenset(),
            {},
            "idp: metadata URL is not allowed; permit its HTTPS origin with saml_metadata_allowed_origins",
        ),
        (
            frozenset({IDP_ORIGIN}),
            {
                "https://idp.example/metadata": FakeResponse(
                    302, location="https://evil.example/x"
                )
            },
            "idp: metadata redirect is not allowed",
        ),
        (
            frozenset({IDP_ORIGIN}),
            {
                "https://idp.example/metadata": FakeResponse(
                    body=b"<!DOCTYPE x>" + IDP_XML
                )
            },
            "idp: invalid metadata XML",
        ),
        (
            frozenset({IDP_ORIGIN}),
            {
                "https://idp.example/metadata": FakeResponse(
                    body=UTF16_ENTITY_XML.encode("utf-16")
                )
            },
            "idp: invalid metadata XML",
        ),
        (
            frozenset({IDP_ORIGIN}),
            {"https://idp.example/metadata": FakeResponse(body=OVERSIZED_INDEX_XML)},
            "idp: invalid metadata XML",
        ),
    ],
)
def test_unsafe_idp_metadata_is_skipped_without_blocking_sp_metadata(
    monkeypatch, allowed, routes, error
):
    requested = _serve(
        monkeypatch,
        {"https://jamf.test/saml/metadata": FakeResponse(body=SP_XML), **routes},
    )
    metadata = enrich_sso_metadata(RECORD, BASE, allowed)["samlMetadata"]
    assert metadata["errors"] == [error]
    assert metadata["idp"] is None
    assert metadata["sp"]["entityId"] == "sp"
    assert "https://evil.example/x" not in requested
