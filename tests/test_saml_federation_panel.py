"""The SAML Federation panel item that the library writes for jamf_SSOIntegration."""

import json
from pathlib import Path

from openhound_saml_producer import FederationSide
from openhound_saml_producer.testing.saml_federation import (
    assert_saml_federation_item_current,
)

from openhound_jamf.kinds import nodes as nk

SCHEMA = Path(__file__).parents[1] / "extension" / "schema.json"


def test_schema_holds_the_current_saml_federation_item():
    """The SSO integration starts a SAML_Implements edge to SAML_ServiceProvider."""
    assert_saml_federation_item_current(
        json.loads(SCHEMA.read_text()),
        nk.SSO_INTEGRATION,
        FederationSide.SERVICE_PROVIDER,
        position=1,
    )
