from __future__ import annotations

from unittest.mock import Mock

import pytest
from requests import Response


def _response(body: bytes, status_code: int = 200) -> Response:
    response = Response()
    response.status_code = status_code
    response._content = body
    response._content_consumed = True
    response.headers["Content-Type"] = "application/xml"
    response.close = Mock()
    return response


def test_parse_saml_metadata_preserves_every_acs_endpoint():
    from openhound_jamf.source import _parse_saml_metadata

    metadata = _parse_saml_metadata(
        """<?xml version="1.0"?>
        <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://jamf.test/saml/metadata">
          <md:SPSSODescriptor>
            <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://jamf.test/saml/SSO" index="0" isDefault="true"/>
            <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://jamf.test/saml/alternate" index="1"/>
          </md:SPSSODescriptor>
        </md:EntityDescriptor>"""
    )

    assert metadata["acsUrl"] == "https://jamf.test/saml/SSO"
    assert metadata["assertionConsumerServices"] == [
        {
            "acsUrl": "https://jamf.test/saml/SSO",
            "acsBinding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            "index": "0",
            "isDefault": True,
        },
        {
            "acsUrl": "https://jamf.test/saml/alternate",
            "acsBinding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            "index": "1",
            "isDefault": False,
        },
    ]


def test_saml_acs_entries_supports_legacy_and_multi_endpoint_metadata():
    from openhound_jamf.source import _saml_acs_entries

    assert _saml_acs_entries(
        {"samlMetadata": {"sp": {"acsUrl": "https://jamf.test/saml/SSO"}}}
    ) == [
        {
            "acsUrl": "https://jamf.test/saml/SSO",
            "acsBinding": None,
            "index": None,
            "isDefault": True,
        }
    ]

    assert _saml_acs_entries(
        {
            "samlMetadata": {
                "sp": {
                    "assertionConsumerServices": [
                        {"acsUrl": "https://jamf.test/saml/SSO"},
                        {"acsUrl": "https://jamf.test/saml/alternate"},
                    ]
                }
            }
        }
    ) == [
        {"acsUrl": "https://jamf.test/saml/SSO"},
        {"acsUrl": "https://jamf.test/saml/alternate"},
    ]


def test_enrich_sso_metadata_keeps_fetch_errors(monkeypatch):
    import openhound_jamf.source as source_module

    def fetch(url, allowed_origins):
        del allowed_origins
        if "jamf.test" in url:
            return None, "SP metadata request failed"
        return {"entityId": "http://www.okta.com/example"}, None

    monkeypatch.setattr(source_module, "_fetch_saml_metadata", fetch)
    enriched = source_module._enrich_sso_metadata(
        {
            "configurationType": "SAML",
            "samlSettings": {
                "entityId": "https://jamf.test/saml/metadata",
                "idpUrl": "https://idp.test/metadata",
            },
        },
        "https://jamf.test",
        source_module._parse_allowed_idp_origins("https://idp.test"),
    )

    assert enriched["samlMetadata"]["idp"] == {
        "entityId": "http://www.okta.com/example"
    }
    assert enriched["samlMetadata"]["errors"] == ["sp: SP metadata request failed"]


@pytest.mark.parametrize(
    "entity_id",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://[invalid",
        "https://jamf.test:444/saml/metadata",
        "https://jamf.test:0/saml/metadata",
        "https://user:password@jamf.test/saml/metadata",
    ],
)
def test_unapproved_metadata_destination_is_not_requested_or_persisted(
    monkeypatch, entity_id: str
):
    import openhound_jamf.source as source_module

    get = Mock(side_effect=AssertionError("metadata request must be blocked"))
    monkeypatch.setattr(source_module.requests, "get", get)

    enriched = source_module._enrich_sso_metadata(
        {
            "configurationType": "SAML",
            "samlSettings": {
                "entityId": entity_id,
                "idpUrl": "https://idp.test/metadata?sig=SENTINEL",
            },
        },
        "https://jamf.test",
    )

    get.assert_not_called()
    assert enriched["samlMetadata"]["errors"] == [
        "sp: metadata URL is not allowed",
        "idp: metadata URL is not allowed",
    ]
    assert "SENTINEL" not in str(enriched["samlMetadata"])


@pytest.mark.parametrize(
    "allowlist",
    ["http://idp.test", "https://idp.test/metadata", "https://[invalid"],
)
def test_idp_allowlist_requires_https_origins(allowlist: str):
    from openhound_jamf.source import _parse_allowed_idp_origins

    with pytest.raises(ValueError, match="HTTPS origins"):
        _parse_allowed_idp_origins(allowlist)


def test_metadata_redirect_to_unapproved_origin_is_blocked(monkeypatch):
    import openhound_jamf.source as source_module

    redirect = _response(b"", status_code=302)
    redirect.headers["Location"] = "http://169.254.169.254/latest/meta-data/"
    get = Mock(return_value=redirect)
    monkeypatch.setattr(source_module.requests, "get", get)

    enriched = source_module._enrich_sso_metadata(
        {
            "configurationType": "SAML",
            "samlSettings": {"entityId": "saml/metadata", "idpUrl": ""},
        },
        "https://jamf.test",
    )

    assert get.call_count == 1
    assert get.call_args.kwargs["allow_redirects"] is False
    assert get.call_args.kwargs["stream"] is True
    assert (
        enriched["samlMetadata"]["errors"][0] == "sp: metadata redirect is not allowed"
    )
    assert "169.254" not in str(enriched["samlMetadata"])
    redirect.close.assert_called_once()


def test_same_origin_metadata_redirect_is_followed(monkeypatch):
    import openhound_jamf.source as source_module

    redirect = _response(b"", status_code=301)
    redirect.headers["Location"] = "/saml/metadata/"
    metadata = _response(
        b'<EntityDescriptor entityID="https://jamf.test/saml/metadata"/>'
    )
    get = Mock(side_effect=[redirect, metadata])
    monkeypatch.setattr(source_module.requests, "get", get)

    enriched = source_module._enrich_sso_metadata(
        {
            "configurationType": "SAML",
            "samlSettings": {"entityId": "saml/metadata", "idpUrl": ""},
        },
        "https://jamf.test",
    )

    assert enriched["samlMetadata"]["sp"]["entityId"] == (
        "https://jamf.test/saml/metadata"
    )
    assert [call.args[0] for call in get.call_args_list] == [
        "https://jamf.test/saml/metadata",
        "https://jamf.test/saml/metadata/",
    ]
    assert all(call.kwargs["allow_redirects"] is False for call in get.call_args_list)
    redirect.close.assert_called_once()
    metadata.close.assert_called_once()


def test_idp_redirect_requires_both_origins_in_allowlist(monkeypatch):
    import openhound_jamf.source as source_module

    redirect = _response(b"", status_code=302)
    redirect.headers["Location"] = "https://cdn.idp.test/metadata"
    metadata = _response(b'<EntityDescriptor entityID="https://idp.test/issuer"/>')
    get = Mock(side_effect=[redirect, redirect, metadata])
    monkeypatch.setattr(source_module.requests, "get", get)
    settings = {
        "configurationType": "SAML",
        "samlSettings": {
            "entityId": "",
            "idpUrl": "https://idp.test/metadata",
        },
    }

    blocked = source_module._enrich_sso_metadata(
        settings,
        "https://jamf.test",
        source_module._parse_allowed_idp_origins("https://idp.test"),
    )
    assert blocked["samlMetadata"]["errors"][-1] == (
        "idp: metadata redirect is not allowed"
    )
    assert get.call_count == 1

    allowed = source_module._enrich_sso_metadata(
        settings,
        "https://jamf.test",
        source_module._parse_allowed_idp_origins(
            "https://idp.test,https://cdn.idp.test"
        ),
    )
    assert allowed["samlMetadata"]["idp"]["entityId"] == "https://idp.test/issuer"
    assert get.call_count == 3


def test_metadata_redirect_chain_is_bounded(monkeypatch):
    import openhound_jamf.source as source_module

    redirects = [_response(b"", status_code=302) for _ in range(4)]
    for response in redirects:
        response.headers["Location"] = "/saml/metadata"
    get = Mock(side_effect=redirects)
    monkeypatch.setattr(source_module.requests, "get", get)

    enriched = source_module._enrich_sso_metadata(
        {
            "configurationType": "SAML",
            "samlSettings": {"entityId": "saml/metadata", "idpUrl": ""},
        },
        "https://jamf.test",
    )

    assert enriched["samlMetadata"]["errors"][0] == (
        "sp: metadata redirect limit exceeded"
    )
    assert get.call_count == 4
    for response in redirects:
        response.close.assert_called_once()


def test_metadata_fetch_caps_streamed_response_and_closes_it(monkeypatch):
    import openhound_jamf.source as source_module

    response = _response(b"x" * (source_module.MAX_SAML_METADATA_BYTES + 1))
    get = Mock(return_value=response)
    monkeypatch.setattr(source_module.requests, "get", get)

    enriched = source_module._enrich_sso_metadata(
        {
            "configurationType": "SAML",
            "samlSettings": {"entityId": "saml/metadata", "idpUrl": ""},
        },
        "https://jamf.test",
    )

    assert enriched["samlMetadata"]["errors"][0] == "sp: metadata exceeds size limit"
    response.close.assert_called_once()


def test_metadata_fetch_rejects_xml_entities(monkeypatch):
    import openhound_jamf.source as source_module

    response = _response(
        b'<!DOCTYPE foo [<!ENTITY x "expanded">]><EntityDescriptor entityID="&x;"/>'
    )
    monkeypatch.setattr(source_module.requests, "get", Mock(return_value=response))

    enriched = source_module._enrich_sso_metadata(
        {
            "configurationType": "SAML",
            "samlSettings": {"entityId": "saml/metadata", "idpUrl": ""},
        },
        "https://jamf.test",
    )

    assert enriched["samlMetadata"]["errors"][0] == "sp: invalid metadata XML"
    response.close.assert_called_once()


def test_allowed_idp_origin_fetches_without_exposing_url_on_failure(monkeypatch):
    import openhound_jamf.source as source_module

    get = Mock(side_effect=RuntimeError("https://idp.test/metadata?sig=SENTINEL"))
    monkeypatch.setattr(source_module.requests, "get", get)

    enriched = source_module._enrich_sso_metadata(
        {
            "configurationType": "SAML",
            "samlSettings": {
                "entityId": "",
                "idpUrl": "https://idp.test/metadata?sig=SENTINEL",
            },
        },
        "https://jamf.test",
        source_module._parse_allowed_idp_origins("https://idp.test"),
    )

    assert get.call_count == 1
    assert "SENTINEL" not in str(enriched["samlMetadata"])
    assert enriched["samlMetadata"]["errors"][-1] == "idp: metadata request failed"
