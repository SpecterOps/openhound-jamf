from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi import Request
from httpx import ASGITransport, AsyncClient
from requests import PreparedRequest, Response
from requests.hooks import dispatch_hook
from requests.structures import CaseInsensitiveDict
from starlette.responses import Response as StarletteResponse

TEST_DATA_DIR = Path(__file__).parent / "test_data"

JAMF_SP_METADATA = """<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://jamf.test/saml/metadata">
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://jamf.test/saml/SSO" index="0" isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>
"""

OKTA_IDP_METADATA = """<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://www.okta.com/example-jamf-app">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://example.idp.com/app/id/sso/saml"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
"""


def _load_json(relative_path: str):
    with (TEST_DATA_DIR / relative_path).open(encoding="utf-8") as handle:
        return json.load(handle)


def _page_payload(relative_path: str, page: int | None):
    payload = _load_json(relative_path)
    if not page:
        return payload
    if isinstance(payload, dict) and "results" in payload:
        return {**payload, "results": []}
    return payload


@pytest.fixture
def mock_jamf_api() -> Any:
    from fastapi import FastAPI

    app = FastAPI()
    app.state.calls = []

    @app.post("/api/v1/auth/token")
    async def auth_token():
        app.state.calls.append("auth_token")
        return {"token": "test-token"}

    @app.post("/api/v1/oauth/token")
    async def oauth_token(request: Request):
        form_data = parse_qs((await request.body()).decode())

        assert form_data == {
            "grant_type": ["client_credentials"],
            "client_id": ["jamf-client-id"],
            "client_secret": ["jamf-client-secret"],
        }

        app.state.calls.append("oauth_token")
        return {"access_token": "test-client-token"}

    @app.get("/JSSResource/users")
    async def users():
        app.state.calls.append("users")
        return _load_json("jss_resource/users.json")

    @app.get("/JSSResource/users/id/{user_id}")
    async def user_details(user_id: int):
        app.state.calls.append("user_details")
        return _load_json("jss_resource/user-details.json")

    @app.get("/JSSResource/accounts")
    async def accounts():
        app.state.calls.append("accounts")
        return _load_json("jss_resource/accounts.json")

    @app.get("/JSSResource/accounts/userid/{account_id}")
    async def account_details(account_id: int):
        app.state.calls.append("account_details")
        return _load_json("jss_resource/accounts-by-id.json")

    @app.get("/JSSResource/accounts/groupid/{group_id}")
    async def account_group_details(group_id: int):
        app.state.calls.append("account_group_details")
        return _load_json("jss_resource/group-by-id.json")

    @app.get("/JSSResource/policies")
    async def policies():
        app.state.calls.append("policies")
        return _load_json("jss_resource/policies.json")

    @app.get("/JSSResource/policies/id/{policy_id}")
    async def policy_details(policy_id: int):
        app.state.calls.append("policy_details")
        return _load_json("jss_resource/policy-by-id.json")

    @app.get("/JSSResource/scripts")
    async def scripts():
        app.state.calls.append("scripts")
        return _load_json("jss_resource/scripts.json")

    @app.get("/JSSResource/scripts/id/{script_id}")
    async def script_details(script_id: int):
        app.state.calls.append("script_details")
        return _load_json("jss_resource/script-by-id.json")

    @app.get("/JSSResource/computerextensionattributes")
    async def computerextensionattributes():
        app.state.calls.append("computerextensionattributes")
        return _load_json("jss_resource/computerextensionattributes.json")

    @app.get("/JSSResource/sites")
    async def sites():
        app.state.calls.append("sites")
        return _load_json("jss_resource/sites.json")

    @app.get("/api/v3/sso")
    async def sso():
        app.state.calls.append("sso")
        return _load_json("v3/sso.json")

    @app.get("/saml/metadata")
    async def jamf_sp_metadata():
        app.state.calls.append("jamf_sp_metadata")
        return StarletteResponse(JAMF_SP_METADATA, media_type="application/xml")

    @app.get("/app/id/sso/saml/metadata")
    async def okta_idp_metadata():
        app.state.calls.append("okta_idp_metadata")
        return StarletteResponse(OKTA_IDP_METADATA, media_type="application/xml")

    @app.get("/api/v1/computers-inventory")
    async def computers_inventory(
        page: int | None = None, section: list[str] | None = None
    ):
        del section
        app.state.calls.append("computers")
        return _page_payload("v1/computers-inventory.json", page)

    @app.get("/api/v1/api-integrations")
    async def api_integrations(page: int | None = None):
        app.state.calls.append("api_integrations")
        return _page_payload("v1/api-integrations.json", page)

    @app.get("/api/v1/api-roles")
    async def api_roles(page: int | None = None):
        app.state.calls.append("api_roles")
        return _page_payload("v1/api-roles.json", page)

    return SimpleNamespace(app=app)


@pytest.fixture
def mock_dlt_requests(monkeypatch, mock_jamf_api):
    from dlt.sources.helpers import requests as dlt_requests
    from dlt.sources.helpers.requests.session import Session as DltSession

    def mock_send(self, request: PreparedRequest, **kwargs: Any) -> Response:
        parsed = urlsplit(request.url or "")
        path = parsed.path
        if parsed.query:
            path = f"{path}?{parsed.query}"

        async def send_to_app():
            transport = ASGITransport(app=mock_jamf_api.app)
            async with AsyncClient(
                transport=transport,
                base_url="https://jamf.test",
            ) as client:
                return await client.request(
                    method=request.method,
                    url=path,
                    headers=dict(request.headers),
                    content=request.body,
                )

        response = asyncio.run(send_to_app())
        requests_response = Response()
        requests_response.status_code = response.status_code
        requests_response._content = response.content
        requests_response.headers = CaseInsensitiveDict(response.headers)
        requests_response.encoding = response.encoding or "utf-8"
        requests_response.reason = response.reason_phrase
        requests_response.url = request.url or ""
        requests_response.request = request
        return dispatch_hook("response", request.hooks, requests_response, **kwargs)

    dlt_requests.client._local.__dict__.pop("session", None)
    monkeypatch.setattr(DltSession, "send", mock_send)
