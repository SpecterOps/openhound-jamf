from __future__ import annotations


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

    def fetch(url):
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
    )

    assert enriched["samlMetadata"]["idp"] == {
        "entityId": "http://www.okta.com/example"
    }
    assert enriched["samlMetadata"]["errors"] == [
        "sp: SP metadata request failed"
    ]
