from dataclasses import dataclass
from typing import NotRequired, TypedDict, Union
from xml.etree import ElementTree
from urllib.parse import urljoin, urlsplit

import dlt
from dlt.sources.helpers import requests
from dlt.sources.helpers.rest_client.client import RESTClient
from dlt.sources.helpers.rest_client.paginators import (
    PageNumberPaginator,
    SinglePagePaginator,
)

from .auth import JamfAuth, JamfClientCredentials, JamfPasswordCredentials
from .main import app
from .models import (
    SSO,
    Account,
    ApiIntegration,
    ApiRole,
    BaseAccount,
    BaseGroup,
    BasePolicy,
    BaseScript,
    BaseUser,
    Computer,
    ComputerextensionAttribute,
    Group,
    InventoryAssignedUser,
    Policy,
    SAMLAccountResolutionField,
    SAMLAccountResolutionRule,
    SAMLAssertionConsumerService,
    SAMLIssuer,
    SAMLServiceProvider,
    Script,
    Site,
    Tenant,
    User,
)


@dataclass
class SourceContext:
    client: RESTClient
    base_url: str
    allowed_idp_origins: frozenset[tuple[str, str, int]]


SAML_METADATA_NS = {"md": "urn:oasis:names:tc:SAML:2.0:metadata"}
MAX_SAML_METADATA_BYTES = 2 * 1024 * 1024
MAX_SAML_METADATA_REDIRECTS = 3
MetadataOrigin = tuple[str, str, int]


class SAMLACSEntry(TypedDict):
    acsUrl: str
    acsBinding: str | None
    index: str | None
    isDefault: bool


class SAMLMetadata(TypedDict):
    entityId: str | None
    acsUrl: NotRequired[str | None]
    acsBinding: NotRequired[str | None]
    assertionConsumerServices: NotRequired[list[SAMLACSEntry]]
    nameIdFormats: NotRequired[list[str]]
    ssoUrl: NotRequired[str | None]
    ssoBinding: NotRequired[str | None]


class EnrichedSAMLMetadata(TypedDict):
    errors: list[str]
    sp: NotRequired[SAMLMetadata]
    idp: NotRequired[SAMLMetadata]


def _metadata_origin(url: str) -> MetadataOrigin | None:
    if any(char.isspace() or ord(char) < 32 or char == "\\" for char in url):
        return None
    try:
        parsed = urlsplit(url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            return None
        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme == "https" else 80
        if port == 0:
            return None
    except ValueError:
        return None
    return parsed.scheme, parsed.hostname, port


def _parse_allowed_idp_origins(value: str | None) -> frozenset[MetadataOrigin]:
    if not value:
        return frozenset()
    origins: set[MetadataOrigin] = set()
    for item in value.split(","):
        candidate = item.strip()
        try:
            parsed = urlsplit(candidate)
        except ValueError as exc:
            raise ValueError(
                "SAML metadata allowlist entries must be HTTPS origins"
            ) from exc
        origin = _metadata_origin(candidate)
        if (
            origin is None
            or origin[0] != "https"
            or parsed.path not in {"", "/"}
            or parsed.query
        ):
            raise ValueError("SAML metadata allowlist entries must be HTTPS origins")
        origins.add(origin)
    return frozenset(origins)


def _resolve_url(base_url: str, value: str | None) -> str | None:
    if not value or not value.strip():
        return None
    try:
        parsed = urlsplit(value)
    except ValueError:
        return value
    if parsed.scheme and parsed.netloc:
        return value

    base = urlsplit(base_url)
    path = value if value.startswith("/") else f"/{value}"
    return f"{base.scheme}://{base.netloc}{path}"


def _text_values(element: ElementTree.Element, path: str) -> list[str]:
    return [
        child.text.strip()
        for child in element.findall(path, SAML_METADATA_NS)
        if child.text and child.text.strip()
    ]


def _parse_saml_metadata(xml_text: str | bytes) -> SAMLMetadata:
    root = ElementTree.fromstring(xml_text)
    entity_id = root.attrib.get("entityID")
    metadata: SAMLMetadata = {"entityId": entity_id}

    sp_descriptor = root.find("md:SPSSODescriptor", SAML_METADATA_NS)
    if sp_descriptor is not None:
        services = sp_descriptor.findall(
            "md:AssertionConsumerService", SAML_METADATA_NS
        )
        default_service = next(
            (
                service
                for service in services
                if service.attrib.get("isDefault") == "true"
            ),
            services[0] if services else None,
        )
        assertion_consumer_services: list[SAMLACSEntry] = [
            {
                "acsUrl": service.attrib["Location"],
                "acsBinding": service.attrib.get("Binding"),
                "index": service.attrib.get("index"),
                "isDefault": service.attrib.get("isDefault") == "true",
            }
            for service in services
            if service.attrib.get("Location")
        ]
        # Keep the preferred endpoint for backwards-compatible raw output.
        metadata["acsUrl"] = (
            default_service.attrib.get("Location")
            if default_service is not None
            else None
        )
        metadata["acsBinding"] = (
            default_service.attrib.get("Binding")
            if default_service is not None
            else None
        )
        metadata["assertionConsumerServices"] = assertion_consumer_services
        metadata["nameIdFormats"] = _text_values(sp_descriptor, "md:NameIDFormat")

    idp_descriptor = root.find("md:IDPSSODescriptor", SAML_METADATA_NS)
    if idp_descriptor is not None:
        services = idp_descriptor.findall("md:SingleSignOnService", SAML_METADATA_NS)
        post_service = next(
            (
                service
                for service in services
                if service.attrib.get("Binding", "").endswith(":HTTP-POST")
            ),
            services[0] if services else None,
        )
        metadata["ssoUrl"] = (
            post_service.attrib.get("Location") if post_service is not None else None
        )
        metadata["ssoBinding"] = (
            post_service.attrib.get("Binding") if post_service is not None else None
        )
        metadata["nameIdFormats"] = _text_values(idp_descriptor, "md:NameIDFormat")

    return metadata


def _fetch_saml_metadata(
    url: str | None, allowed_origins: frozenset[MetadataOrigin]
) -> tuple[SAMLMetadata | None, str | None]:
    if not url:
        return None, "metadata URL is empty"
    current_url = url
    # Validate every hop before requesting it; an access gateway may redirect
    # metadata requests to a different origin.
    for redirect_count in range(MAX_SAML_METADATA_REDIRECTS + 1):
        if _metadata_origin(current_url) not in allowed_origins:
            return None, (
                "metadata URL is not allowed"
                if redirect_count == 0
                else "metadata redirect is not allowed"
            )
        try:
            response = requests.get(
                current_url, timeout=(5, 30), stream=True, allow_redirects=False
            )
            try:
                if 300 <= response.status_code < 400:
                    location = response.headers.get("Location")
                    if (
                        response.status_code not in {301, 302, 303, 307, 308}
                        or not location
                    ):
                        return None, "metadata request failed"
                    if redirect_count == MAX_SAML_METADATA_REDIRECTS:
                        return None, "metadata redirect limit exceeded"
                    next_url = urljoin(current_url, location)
                    if _metadata_origin(next_url) not in allowed_origins:
                        return None, "metadata redirect is not allowed"
                    current_url = next_url
                    continue
                response.raise_for_status()
                declared_size = response.headers.get("Content-Length")
                if declared_size and declared_size.isdecimal():
                    if int(declared_size) > MAX_SAML_METADATA_BYTES:
                        return None, "metadata exceeds size limit"
                body = bytearray()
                for chunk in response.iter_content(chunk_size=64 * 1024):
                    body.extend(chunk)
                    if len(body) > MAX_SAML_METADATA_BYTES:
                        return None, "metadata exceeds size limit"
                xml_bytes = bytes(body)
                if (
                    b"<!DOCTYPE" in xml_bytes.upper()
                    or b"<!ENTITY" in xml_bytes.upper()
                ):
                    return None, "invalid metadata XML"
                return _parse_saml_metadata(xml_bytes), None
            finally:
                response.close()
        except ElementTree.ParseError:
            return None, "invalid metadata XML"
        except Exception:
            # Request exceptions may include a credential-bearing query.
            return None, "metadata request failed"
    return None, "metadata redirect limit exceeded"


def _enrich_sso_metadata(
    response: dict,
    base_url: str,
    allowed_idp_origins: frozenset[MetadataOrigin] = frozenset(),
) -> dict:
    saml_settings = response.get("samlSettings") or {}
    if response.get("configurationType") != "SAML" or not saml_settings:
        return response

    metadata: EnrichedSAMLMetadata = {"errors": []}
    sp_url = _resolve_url(base_url, saml_settings.get("entityId"))
    idp_url = _resolve_url(base_url, saml_settings.get("idpUrl"))
    jamf_origin = _metadata_origin(base_url)
    jamf_origins = frozenset({jamf_origin}) if jamf_origin is not None else frozenset()

    sp_metadata, sp_error = _fetch_saml_metadata(sp_url, jamf_origins)
    if sp_metadata:
        metadata["sp"] = sp_metadata
    if sp_error:
        metadata["errors"].append(f"sp: {sp_error}")

    idp_metadata, idp_error = _fetch_saml_metadata(
        idp_url, jamf_origins | allowed_idp_origins
    )
    if idp_metadata:
        metadata["idp"] = idp_metadata
    if idp_error:
        metadata["errors"].append(f"idp: {idp_error}")

    return {**response, "samlMetadata": metadata}


def _saml_acs_entries(sso_config: dict) -> list[dict]:
    """Return every usable ACS endpoint from enriched Jamf SAML metadata."""
    sp_metadata = (sso_config.get("samlMetadata") or {}).get("sp") or {}
    endpoints = [
        endpoint
        for endpoint in sp_metadata.get("assertionConsumerServices", [])
        if endpoint.get("acsUrl")
    ]
    if endpoints:
        return endpoints

    # Existing collected fixtures may only contain the pre-multi-endpoint shape.
    if sp_metadata.get("acsUrl"):
        return [
            {
                "acsUrl": sp_metadata["acsUrl"],
                "acsBinding": sp_metadata.get("acsBinding"),
                "index": None,
                "isDefault": True,
            }
        ]
    return []


@app.resource(name="users", parallelized=True, columns=BaseUser)
def users(ctx: SourceContext):
    """DLT resource, fetches JAMF users via the /JSSResource/use¬rs endpoint.

    Yields:
        dict: The JAMF user with user ID, excluding user details.
    """
    response = ctx.client.get("/JSSResource/users").json()
    for user in response["users"]:
        yield user


@app.transformer(name="user_details", data_from=users, parallelized=True, columns=User)
def user_details(user, ctx: SourceContext):
    """DLT transformer, fetches JAMF user details via the /JSSResource/users/id/<id> endpoint.

    Args:
        user (dict): The previously collected JAMF user with the user ID.
    Yields:
        user (User): The JAMF user including user details, parsed by the Pydantic User model.
    """
    response = ctx.client.get(f"/JSSResource/users/id/{user['id']}").json()
    yield response["user"]


@app.resource(name="accounts", parallelized=True, columns=BaseAccount)
def accounts(ctx: SourceContext):
    """DLT resource, fetches JAMF accounts via the /JSSResource/accounts endpoint.

    Yields:
        dict: The JAMF account with account ID, excluding account details.
    """
    response = ctx.client.get("/JSSResource/accounts").json()
    for account in response["accounts"]["users"]:
        yield account


@app.transformer(
    name="account_details", data_from=accounts, parallelized=True, columns=Account
)
def account_details(user, ctx: SourceContext):
    """DLT transformer, fetches JAMF account user details via the /JSSResource/accounts/userid/<id> endpoint.

    Args:
        user (dict): The previously collected JAMF account with the account ID.

    Yields:
        account (Account): The JAMF account including account details, parsed by the Pydantic Account model.
    """
    response = ctx.client.get(f"/JSSResource/accounts/userid/{user['id']}").json()
    yield response["account"]


@app.resource(name="account_groups", parallelized=True, columns=BaseGroup)
def account_groups(ctx: SourceContext):
    """DLT resource, fetches JAMF account groups via the /JSSResource/accounts endpoint.

    Yields:
        dict: The JAMF account group with group ID, excluding group details.
    """
    response = ctx.client.get("/JSSResource/accounts").json()
    for account in response["accounts"]["groups"]:
        yield account


@app.transformer(
    name="account_group_details",
    data_from=account_groups,
    parallelized=True,
    columns=Group,
)
def account_group_details(group, ctx: SourceContext):
    """DLT transformer, fetches JAMF account group details via the /JSSResource/accounts/groupid/<id> endpoint.

    Args:
        group (dict): The previously collected JAMF account group with the group ID.

    Yields:
        group (Group): The JAMF account group including group details, parsed by the Pydantic Group model.
    """
    response = ctx.client.get(f"/JSSResource/accounts/groupid/{group['id']}").json()
    yield response["group"]


@app.resource(name="policies", parallelized=True, columns=BasePolicy)
def policies(ctx: SourceContext):
    """DLT resource, fetches JAMF policies via the /JSSResource/policies endpoint.

    Yields:
        dict: The JAMF policy with policy ID, excluding policy details.
    """
    response = ctx.client.get("/JSSResource/policies").json()
    for policy in response["policies"]:
        yield policy


@app.transformer(
    name="policy_details", data_from=policies, parallelized=True, columns=Policy
)
def policy_details(policy, ctx: SourceContext):
    """DLT transformer, fetches JAMF policy details via the /JSSResource/policies/id/<id> endpoint.

    Args:
        policy (dict): The previously collected JAMF policy with the policy ID.

    Yields:
        policy (Policy): The JAMF policy including policy details, parsed by the Pydantic Policy model.
    """
    response = ctx.client.get(f"/JSSResource/policies/id/{policy['id']}").json()
    policy = response["policy"]
    general = policy.pop("general")
    yield {**general, **policy}


@app.resource(name="scripts", parallelized=True, columns=BaseScript)
def scripts(ctx: SourceContext):
    """DLT resource, fetches JAMF scripts via the /JSSResource/scripts endpoint.

    Yields:
        dict: The JAMF script with script ID, excluding script details.
    """
    response = ctx.client.get("/JSSResource/scripts").json()
    for script in response["scripts"]:
        yield script


@app.transformer(
    name="script_details", data_from=scripts, parallelized=True, columns=Script
)
def script_details(script, ctx: SourceContext):
    """DLT transformer, fetches JAMF script details via the /JSSResource/scripts/id/<id> endpoint.

    Args:
        script (dict): The previously collected JAMF script with the script ID.

    Yields:
        script (Script): The JAMF script including script details, parsed by the Pydantic Script model.
    """
    response = ctx.client.get(f"/JSSResource/scripts/id/{script['id']}").json()
    yield response["script"]


@app.resource(
    name="computerextensionattributes",
    parallelized=True,
    columns=ComputerextensionAttribute,
)
def computerextensionattributes(ctx: SourceContext):
    """DLT resource, fetches JAMF computer extension attributes via the /JSSResource/computerextensionattributes endpoint.

    Yields:
        dict: The JAMF computer extension attribute definition.
    """
    response = ctx.client.get("/JSSResource/computerextensionattributes").json()
    for assoc in response["computer_extension_attributes"]:
        yield assoc


@app.resource(name="sites", parallelized=True, columns=Site)
def sites(ctx: SourceContext):
    """DLT resource, fetches JAMF sites via the /JSSResource/sites endpoint.

    Yields:
        site (Site): The JAMF site, parsed by the Pydantic Site model.
    """
    response = ctx.client.get("/JSSResource/sites").json()
    for site in response["sites"]:
        yield site


@app.resource(name="sso", parallelized=True, columns=SSO)
def sso(ctx: SourceContext):
    """DLT resource, fetches JAMF SSO settings via the /api/v3/sso endpoint.

    Yields:
        dict: The JAMF SSO settings.
    """
    response = ctx.client.get("/api/v3/sso").json()
    response = _enrich_sso_metadata(response, ctx.base_url, ctx.allowed_idp_origins)
    yield response


@app.transformer(
    name="saml_service_provider",
    data_from=sso,
    parallelized=True,
    columns=SAMLServiceProvider,
)
def saml_service_provider(sso_config):
    yield sso_config


@app.transformer(
    name="saml_account_resolution_rule",
    data_from=sso,
    parallelized=True,
    columns=SAMLAccountResolutionRule,
)
def saml_account_resolution_rule(sso_config):
    yield sso_config


@app.transformer(
    name="saml_account_resolution_field",
    data_from=sso,
    parallelized=True,
    columns=SAMLAccountResolutionField,
)
def saml_account_resolution_field(sso_config):
    yield sso_config


@app.transformer(
    name="saml_issuer", data_from=sso, parallelized=True, columns=SAMLIssuer
)
def saml_issuer(sso_config):
    yield sso_config


@app.transformer(
    name="saml_assertion_consumer_service",
    data_from=sso,
    parallelized=True,
    columns=SAMLAssertionConsumerService,
)
def saml_assertion_consumer_service(sso_config):
    for acs in _saml_acs_entries(sso_config):
        yield {**sso_config, "samlAcs": acs}


@app.resource(name="computers", parallelized=True, columns=Computer)
def computers(ctx: SourceContext):
    """DLT resource, fetches JAMF computers via the /api/v1/computers-inventory endpoint.

    Yields:
        computer (Computer): The JAMF computer, parsed by the Pydantic Computer model.
    """
    paginator = PageNumberPaginator(page_param="page", total_path="totalCount")
    for page in ctx.client.paginate(
        "/api/v1/computers-inventory?section=GENERAL&section=HARDWARE&section=USER_AND_LOCATION&section=CONFIGURATION_PROFILES&section=LOCAL_USER_ACCOUNTS&section=SECURITY&section=OPERATING_SYSTEM&section=GROUP_MEMBERSHIPS",
        paginator=paginator,
    ):
        for computer in page:
            general = computer.pop("general")
            yield {
                **computer,
                **general,
            }


@app.transformer(
    name="computer_inventory_users",
    data_from=computers,
    parallelized=True,
    columns=InventoryAssignedUser,
)
def computer_inventory_users(computer):
    """Yield legacy-compatible assigned-user evidence from computer inventory."""

    user = computer.get("userAndLocation") or {}
    if not any(
        isinstance(value, str) and value.strip()
        for field in ("username", "email", "realname")
        if (value := user.get(field)) is not None
    ):
        return
    yield {
        "computer_id": str(computer["id"]),
        "username": user.get("username"),
        "realname": user.get("realname"),
        "email": user.get("email"),
        "phone": user.get("phone"),
    }


@app.resource(name="api_integrations", parallelized=True, columns=ApiIntegration)
def api_integrations(ctx: SourceContext):
    """DLT resource, fetches JAMF API integrations via the /api/v1/api-integrations endpoint.

    Yields:
        integration (ApiIntegration): The JAMF API integration, parsed by the Pydantic ApiIntegration model.
    """
    paginator = PageNumberPaginator(page_param="page", total_path="totalCount")
    for integration in ctx.client.paginate(
        "/api/v1/api-integrations", paginator=paginator
    ):
        yield integration


@app.resource(name="api_roles", parallelized=True, columns=ApiRole)
def api_roles(ctx: SourceContext):
    """DLT resource, fetches JAMF API roles via the /api/v1/api-roles endpoint.

    Yields:
        apirole (ApiRole): The JAMF API role, parsed by the Pydantic ApiRole model.
    """
    paginator = PageNumberPaginator(page_param="page", total_path="totalCount")
    for role in ctx.client.paginate("/api/v1/api-roles", paginator=paginator):
        yield role


@app.resource(name="tenant", parallelized=True, columns=Tenant)
def tenant(host: str):
    parse_host = urlsplit(host)
    yield {"id": parse_host.hostname, "name": parse_host.hostname}


@dlt.source(name="jamf", max_table_nesting=0)
def source(
    credentials: Union[
        JamfPasswordCredentials, JamfClientCredentials
    ] = dlt.secrets.value,
    saml_metadata_allowed_origins: str | None = dlt.config.value,
):
    """DLT source, defines JAMF collection resources and transformers.

    Args:
        credentials (JamfPasswordCredentials | JamfClientCredentials): The JAMF credentials configuration.
        saml_metadata_allowed_origins (str | None): Comma-separated HTTPS origins
            authorized for external IdP metadata fetches. Configure with
            SOURCES__JAMF__SAML_METADATA_ALLOWED_ORIGINS. Without it, only the
            configured Jamf origin may serve metadata; redirects must remain
            within the origins authorized for that request.

    Returns:
        (tuple[users, user_details, sites, scripts, script_details, policy_details, policies, computers, computerextensionattributes, api_roles, api_integrations, accounts, account_details, account_groups, account_group_details]): A tuple of DLT resources/transformers registered for the JAMF source.

    """

    ctx = SourceContext(
        client=RESTClient(
            base_url=credentials.host,
            headers={"accept": "application/json"},
            auth=JamfAuth(credentials=credentials),
            paginator=SinglePagePaginator(),
        ),
        base_url=credentials.host,
        allowed_idp_origins=_parse_allowed_idp_origins(saml_metadata_allowed_origins),
    )

    users_resource = users(ctx)
    policies_resource = policies(ctx)
    scripts_resource = scripts(ctx)
    accounts_resource = accounts(ctx)
    groups_resource = account_groups(ctx)
    computers_resource = computers(ctx)

    sso_resource = sso(ctx)

    return (
        users_resource | user_details(ctx),
        policies_resource | policy_details(ctx),
        scripts_resource | script_details(ctx),
        accounts_resource | account_details(ctx),
        groups_resource | account_group_details(ctx),
        computers_resource,
        computers_resource | computer_inventory_users(),
        computerextensionattributes(ctx),
        sites(ctx),
        api_integrations(ctx),
        api_roles(ctx),
        sso_resource,
        sso_resource | saml_service_provider(),
        sso_resource | saml_account_resolution_rule(),
        sso_resource | saml_account_resolution_field(),
        sso_resource | saml_issuer(),
        sso_resource | saml_assertion_consumer_service(),
        tenant(credentials.host),
    )
