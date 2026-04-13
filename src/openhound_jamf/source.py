from dataclasses import dataclass
from functools import cache
from urllib.parse import urlsplit

import dlt
from dlt.common.configuration import configspec
from dlt.sources.helpers import requests
from dlt.sources.helpers.rest_client.auth import AuthConfigBase
from dlt.sources.helpers.rest_client.client import RESTClient
from dlt.sources.helpers.rest_client.paginators import (
    PageNumberPaginator,
    SinglePagePaginator,
)

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
    Policy,
    Script,
    Site,
    Tenant,
    User,
)


@dataclass
class SourceContext:
    client: RESTClient


@configspec
class CustomAuth(AuthConfigBase):
    def __init__(self, host: str, username: str, password: str):
        self.host = host
        self.username = username
        self.password = password

    @staticmethod
    @cache
    def token(host, username, password) -> str:
        """Calls the JAMF authentication API to generate an API token based on a username/password.

        Args:
            host (str): The base JAMF URL used for API calls.
            user (str): The JAMF username used for authentication, read from environment or dlt config file.
            passw (str): The JAMF password used for authentication, read from environment or dlt config file.

        Returns:
            dict: A (cached) JAMF API token used for API calls.
        """
        response = requests.post(f"{host}/api/v1/auth/token", auth=(username, password))
        return response.json()["token"]

    def __call__(self, request):
        request.headers["Authorization"] = (
            f"Bearer {self.token(self.host, self.username, self.password)}"
        )
        return request


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


@app.resource(name="tenant", parallelized=True, columns=Tenant)
def tenant(host: str):
    parse_host = urlsplit(host)
    yield {"id": parse_host.hostname, "name": parse_host.hostname}


@dlt.source(name="jamf", max_table_nesting=0)
def source(
    username=dlt.secrets.value, password=dlt.secrets.value, host=dlt.secrets.value
):
    """DLT source, defines JAMF collection resources and transformers.

    Args:
        username (str): The JAMF username used for authentication.
        password (str): The JAMF password used for authentication.
        host (str): The base JAMF URL used for API calls.

    Returns:
        (tuple[users, user_details, sites, scripts, script_details, policy_details, policies, computers, computerextensionattributes, api_roles, api_integrations, accounts, account_details, account_groups, account_group_details]): A tuple of DLT resources/transformers registered for the JAMF source.

    """

    ctx = SourceContext(
        client=RESTClient(
            base_url=host,
            headers={"accept": "application/json"},
            auth=CustomAuth(host=host, username=username, password=password),
            paginator=SinglePagePaginator(),
        )
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
        sso(ctx),
        tenant(host),
    )
