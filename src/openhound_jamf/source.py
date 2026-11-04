import logging
from dataclasses import dataclass, field
from threading import Lock
from typing import Union
from urllib.parse import urlsplit

import dlt
from dlt.sources.helpers.rest_client.client import RESTClient
from dlt.sources.helpers.rest_client.paginators import (
    PageNumberPaginator,
    SinglePagePaginator,
)

from .auth import JamfAuth, JamfClientCredentials, JamfPasswordCredentials
from .main import app
from .graph import JAMFNode
from .kinds import nodes as nk
from .models.cloudldap import (
    CloudGroupResponse,
    CloudGroupTest,
    CloudUserResponse,
    CloudUserTest,
    LDAPServer,
    normalize_ldap_servers,
)
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
    AzureCloudConfiguration,
    CloudIntegration,
    CloudIntegrationAsset,
    CloudIntegrationResponse,
    CloudIntegrationSnapshot,
    Computer,
    ComputerextensionAttribute,
    Group,
    Policy,
    Script,
    Site,
    Tenant,
    User,
)


logger = logging.getLogger(__name__)


@dataclass
class SourceContext:
    client: RESTClient
    tenant_id: str | None = None
    _cloud_snapshot: CloudIntegrationSnapshot | None = field(default=None, init=False)
    _cloud_error: Exception | None = field(default=None, init=False)
    _cloud_lock: Lock = field(default_factory=Lock, init=False, repr=False)
    _unsupported_logged: set[str] = field(default_factory=set, init=False)

    def cloud_snapshot(self) -> CloudIntegrationSnapshot:
        # Resources run in parallel: share one complete provider snapshot per run.
        with self._cloud_lock:
            if self._cloud_error is not None:
                raise self._cloud_error
            if self._cloud_snapshot is None:
                try:
                    self._cloud_snapshot = fetch_cloud_integrations(self.client)
                except Exception as error:
                    self._cloud_error = error
                    raise
            return self._cloud_snapshot

    def account_cloud_tests(self, account: dict) -> list[dict]:
        if not account.get("directory_user"):
            return []
        associations = [
            LDAPServer.model_validate(item)
            for item in normalize_ldap_servers(
                account.get("ldap_server", account.get("ldap_servers"))
            )
        ]
        if not associations:
            return []
        provider_ids = {server.id for server in associations}
        tests = []
        for provider in self.cloud_snapshot().results:
            if provider.id not in provider_ids or not provider.enabled:
                continue
            evidence = dict(
                provider_id=provider.id,
                provider_name=provider.provider_name,
                requested_username=account["name"],
            )
            if provider.provider_name != "AZURE":
                self.log_unsupported_provider(provider)
                test = CloudUserTest(**evidence, status="unsupported")
            else:
                try:
                    response = self.client.post(
                        f"/api/v1/cloud-idp/{provider.id}/test-user",
                        json={"username": account["name"]},
                    )
                    response.raise_for_status()
                    result = CloudUserResponse.model_validate(response.json())
                    if any(user.server_id != provider.id for user in result.results):
                        raise ValueError(
                            "Cloud directory response belongs to another provider"
                        )
                    test = CloudUserTest(
                        **evidence,
                        status="success",
                        total_count=result.total_count,
                        results=result.results,
                    )
                except Exception as error:
                    # Keep the principal even when its optional directory lookup fails.
                    logger.warning(
                        "Cloud directory lookup failed for account %s, provider %s: %s",
                        account["id"],
                        provider.id,
                        type(error).__name__,
                    )
                    test = CloudUserTest(
                        **evidence, status="error", error=type(error).__name__
                    )
            tests.append(test.model_dump(mode="json"))
        return tests

    def log_unsupported_provider(self, provider: CloudIntegration) -> None:
        with self._cloud_lock:
            if provider.id not in self._unsupported_logged:
                message = (
                    "Google cloud integrations are unsupported."
                    if provider.provider_name == "GOOGLE"
                    else "Cloud Integration provider not currently supported"
                )
                logger.warning(message, extra={"provider_id": provider.id})
                self._unsupported_logged.add(provider.id)

    def group_cloud_tests(self, group: dict) -> list[dict]:
        associations = [
            LDAPServer.model_validate(item)
            for item in normalize_ldap_servers(
                group.get("ldap_server", group.get("ldap_servers"))
            )
        ]
        if not associations:
            return []
        snapshot = self.cloud_snapshot()
        if not snapshot.cloudintegrationenabled:
            return []
        provider_ids = {server.id for server in associations}
        tests = []
        for provider in snapshot.results:
            if provider.id not in provider_ids or not provider.enabled:
                continue
            evidence = dict(
                provider_id=provider.id,
                provider_name=provider.provider_name,
                requested_groupname=group["name"],
            )
            if provider.provider_name != "AZURE":
                self.log_unsupported_provider(provider)
                test = CloudGroupTest(**evidence, status="unsupported")
            else:
                try:
                    response = self.client.post(
                        f"/api/v1/cloud-idp/{provider.id}/test-group",
                        json={"groupname": group["name"]},
                    )
                    response.raise_for_status()
                    result = CloudGroupResponse.model_validate(response.json())
                    if any(item.server_id != provider.id for item in result.results):
                        raise ValueError(
                            "Cloud directory group response belongs to another provider"
                        )
                    test = CloudGroupTest(
                        **evidence,
                        status="success",
                        total_count=result.total_count,
                        results=result.results,
                    )
                except Exception as error:
                    logger.warning(
                        "Cloud directory lookup failed for group %s, provider %s: %s",
                        group["id"],
                        provider.id,
                        type(error).__name__,
                    )
                    test = CloudGroupTest(
                        **evidence, status="error", error=type(error).__name__
                    )
            tests.append(test.model_dump(mode="json"))
        return tests


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
    account = response["account"]
    try:
        account["cloud_idp_user_tests"] = ctx.account_cloud_tests(account)
    except Exception as error:
        logger.warning(
            "Cloud directory enrichment failed for account %s: %s",
            account["id"],
            type(error).__name__,
        )
        account["cloud_idp_user_tests"] = []
    yield account


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
    details = response["group"]
    try:
        details["cloud_idp_group_tests"] = ctx.group_cloud_tests(details)
    except Exception as error:
        logger.warning(
            "Cloud directory enrichment failed for group %s: %s",
            details["id"],
            type(error).__name__,
        )
        details["cloud_idp_group_tests"] = []
    yield details


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
    yield response


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


def fetch_cloud_integrations(client: RESTClient) -> CloudIntegrationSnapshot:
    """Fetch a complete provider snapshot for all resources in this source run."""
    integrations: list[CloudIntegration] = []
    expected_total: int | None = None
    page_number = 0

    while True:
        response = client.get(
            "/api/v1/cloud-idp",
            params={"page": page_number, "page-size": 100},
        )
        response.raise_for_status()
        page = CloudIntegrationResponse.model_validate(response.json())

        if expected_total is None:
            expected_total = page.total_count
        elif page.total_count != expected_total:
            raise RuntimeError(
                "Cloud Identity Provider count changed during collection; retry."
            )

        integrations.extend(page.results)
        if len(integrations) == expected_total:
            break
        if not page.results or len(integrations) > expected_total:
            raise RuntimeError(
                "Cloud Identity Provider pagination returned an incomplete "
                "or inconsistent collection."
            )
        page_number += 1

    snapshot = CloudIntegrationSnapshot(
        total_count=len(integrations),
        results=integrations,
        cloudintegrationenabled=any(item.enabled for item in integrations),
    )
    return snapshot


@app.resource(
    name="cloud_integrations",
    parallelized=True,
    columns=CloudIntegrationSnapshot,
)
def cloud_integrations(ctx: SourceContext):
    """Persist the same provider snapshot used for account directory searches."""
    yield ctx.cloud_snapshot().model_dump(mode="json")


@app.resource(
    name="cloud_integration_details",
    parallelized=True,
    columns=CloudIntegrationAsset,
)
def cloud_integration_details(ctx: SourceContext):
    """Collect one Azure graph asset per discovered provider, including disabled ones."""
    if not ctx.tenant_id:
        raise ValueError(
            "A Jamf tenant hostname is required for cloud integration identity"
        )
    for provider in ctx.cloud_snapshot().results:
        if provider.provider_name != "AZURE":
            ctx.log_unsupported_provider(provider)
            continue
        identity = dict(
            summary=provider,
            graph_id=JAMFNode.guid(provider.id, nk.CLOUD_INTEGRATION, ctx.tenant_id),
            tenant=ctx.tenant_id,
        )
        try:
            response = ctx.client.get(f"/api/v1/cloud-azure/{provider.id}")
            response.raise_for_status()
            details = AzureCloudConfiguration.model_validate(response.json())
            asset = CloudIntegrationAsset(**identity, details=details)
            if provider.enabled != details.server.enabled:
                logger.warning(
                    "Cloud integration %s enabled status differs between summary and details",
                    provider.id,
                )
        except Exception as error:
            logger.warning(
                "Cloud integration detail collection failed for provider %s: %s",
                provider.id,
                type(error).__name__,
            )
            asset = CloudIntegrationAsset(
                **identity, details_error=type(error).__name__
            )
        yield asset.model_dump(mode="json")


@app.resource(name="tenant", parallelized=True, columns=Tenant)
def tenant(host: str):
    parse_host = urlsplit(host)
    yield {"id": parse_host.hostname, "name": parse_host.hostname}


@dlt.source(name="jamf", max_table_nesting=0)
def source(
    credentials: Union[
        JamfPasswordCredentials, JamfClientCredentials
    ] = dlt.secrets.value,
):
    """DLT source, defines JAMF collection resources and transformers.

    Args:
        credentials (JamfPasswordCredentials | JamfClientCredentials): The JAMF credentials configuration

    Returns:
        (tuple[users, user_details, sites, scripts, script_details, policy_details, policies, computers, computerextensionattributes, api_roles, api_integrations, accounts, account_details, account_groups, account_group_details]): A tuple of DLT resources/transformers registered for the JAMF source.

    """

    ctx = SourceContext(
        tenant_id=urlsplit(credentials.host).hostname,
        client=RESTClient(
            base_url=credentials.host,
            headers={"accept": "application/json"},
            auth=JamfAuth(credentials=credentials),
            paginator=SinglePagePaginator(),
        ),
    )

    users_resource = users(ctx)
    policies_resource = policies(ctx)
    scripts_resource = scripts(ctx)
    accounts_resource = accounts(ctx)
    groups_resource = account_groups(ctx)

    return (
        users_resource | user_details(ctx),
        policies_resource | policy_details(ctx),
        scripts_resource | script_details(ctx),
        accounts_resource | account_details(ctx),
        groups_resource | account_group_details(ctx),
        computers(ctx),
        computerextensionattributes(ctx),
        sites(ctx),
        api_integrations(ctx),
        api_roles(ctx),
        cloud_integrations(ctx),
        cloud_integration_details(ctx),
        sso(ctx),
        tenant(credentials.host),
    )
