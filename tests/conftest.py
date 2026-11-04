from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi import Request
from requests import PreparedRequest, Response
from requests.hooks import dispatch_hook
from requests.structures import CaseInsensitiveDict

TEST_DATA_DIR = Path(__file__).parent / "test_data"


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
    from fastapi.testclient import TestClient

    app = FastAPI()
    app.state.calls = []
    app.state.cloud_idp_pages = [
        {
            "totalCount": 2,
            "results": [
                {
                    "id": "1001",
                    "displayName": "Entra ID",
                    "enabled": True,
                    "providerName": "AZURE",
                    "providerDescription": "Entra ID",
                },
                {
                    "id": "1002",
                    "displayName": "Test",
                    "enabled": True,
                    "providerName": "AZURE",
                    "providerDescription": "Entra ID",
                },
            ],
        }
    ]

    app.state.cloud_user_response = {"totalCount": 0, "results": []}
    app.state.cloud_user_status = 200

    @app.post("/api/v1/cloud-idp/{provider_id}/test-user")
    async def cloud_user_test(provider_id: str, request: Request):
        from fastapi.responses import JSONResponse

        payload = await request.json()
        app.state.calls.append("cloud_user_test")
        app.state.last_cloud_user_request = (provider_id, payload)
        return JSONResponse(
            app.state.cloud_user_response, status_code=app.state.cloud_user_status
        )

    app.state.group_details_override = None
    app.state.cloud_group_response = {"totalCount": 0, "results": []}
    app.state.cloud_group_status = 200

    @app.post("/api/v1/cloud-idp/{provider_id}/test-group")
    async def cloud_group_test(provider_id: str, request: Request):
        from fastapi.responses import JSONResponse

        payload = await request.json()
        app.state.calls.append("cloud_group_test")
        app.state.last_cloud_group_request = (provider_id, payload)
        return JSONResponse(
            app.state.cloud_group_response, status_code=app.state.cloud_group_status
        )

    app.state.cloud_azure_overrides = {}
    app.state.cloud_azure_status = {}

    @app.get("/api/v1/cloud-azure/{provider_id}")
    async def cloud_azure_details(provider_id: str):
        from fastapi.responses import JSONResponse

        app.state.calls.append("cloud_azure_details")
        payload = _load_json("v1/cloud-azure.json")
        payload["cloudIdPCommon"]["id"] = provider_id
        payload["server"]["id"] = provider_id
        for page in app.state.cloud_idp_pages:
            for provider in page["results"]:
                if provider["id"] == provider_id:
                    payload["cloudIdPCommon"]["displayName"] = provider["displayName"]
                    payload["server"]["enabled"] = provider["enabled"]
        return JSONResponse(
            app.state.cloud_azure_overrides.get(provider_id, payload),
            status_code=app.state.cloud_azure_status.get(provider_id, 200),
        )

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
        if app.state.group_details_override is not None:
            return app.state.group_details_override
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

    @app.get("/api/v1/cloud-idp")
    async def cloud_idp(page: int = 0):
        app.state.calls.append("cloud_integrations")
        return app.state.cloud_idp_pages[page]

    @app.get("/api/v1/api-roles")
    async def api_roles(page: int | None = None):
        app.state.calls.append("api_roles")
        return _page_payload("v1/api-roles.json", page)

    return TestClient(app)


@pytest.fixture
def mock_dlt_requests(monkeypatch, mock_jamf_api):
    from dlt.sources.helpers import requests as dlt_requests
    from dlt.sources.helpers.requests.session import Session as DltSession

    def mock_send(self, request: PreparedRequest, **kwargs: Any) -> Response:
        parsed = urlsplit(request.url)
        path = parsed.path
        if parsed.query:
            path = f"{path}?{parsed.query}"

        response = mock_jamf_api.request(
            method=request.method,
            url=path,
            headers=dict(request.headers),
            content=request.body,
        )
        requests_response = Response()
        requests_response.status_code = response.status_code
        requests_response._content = response.content
        requests_response.headers = CaseInsensitiveDict(response.headers)
        requests_response.encoding = response.encoding or "utf-8"
        requests_response.reason = response.reason_phrase
        requests_response.url = request.url
        requests_response.request = request
        return dispatch_hook("response", request.hooks, requests_response, **kwargs)

    dlt_requests.client._local.__dict__.pop("session", None)
    monkeypatch.setattr(DltSession, "send", mock_send)
