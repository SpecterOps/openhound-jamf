from dataclasses import dataclass

from openhound.core.asset import EdgeDef, NodeDef
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties
from pydantic import ConfigDict, Field

from openhound_jamf.graph import JAMFAsset, JAMFNode, JAMFNodeProperties
from openhound_jamf.kinds import edges as ek
from openhound_jamf.kinds import nodes as nk
from openhound_jamf.main import app


@dataclass
class ApiIntegrationProperties(JAMFNodeProperties):
    """JAMF API Integration (API Client) node properties"""

    enabled: bool
    client_id: str
    app_type: str
    privileges: list[str]
    collected: bool = True


@app.asset(
    description="Jamf API Client asset. Returns a node representing a Jamf API Client with edges to its tenant.",
    node=NodeDef(
        kind=nk.API_CLIENT,
        description="Jamf API Client node",
        icon="plug",
        properties=ApiIntegrationProperties,
    ),
    edges=[
        EdgeDef(
            start=nk.TENANT,
            end=nk.API_CLIENT,
            kind=ek.CONTAINS,
            description="The tenant contains this API client.",
        ),
        EdgeDef(
            start=nk.API_CLIENT,
            end=nk.TENANT,
            kind=ek.CREATE_ACCOUNTS,
            description="The API client can create accounts on the target tenant.",
            traversable=True,
        ),
        EdgeDef(
            start=nk.API_CLIENT,
            end=nk.TENANT,
            kind=ek.UPDATE_ACCOUNTS,
            description="The API client can update accounts on the target tenant.",
            traversable=True,
        ),
        EdgeDef(
            start=nk.API_CLIENT,
            end=nk.COMPUTER,
            kind=ek.CREATE_POLICIES,
            description="The API client can create policies on the target computer.",
            traversable=True,
        ),
        EdgeDef(
            start=nk.API_CLIENT,
            end=nk.COMPUTER,
            kind=ek.UPDATE_POLICIES,
            description="The API client can update policies on the target computer.",
            traversable=True,
        ),
        EdgeDef(
            start=nk.API_CLIENT,
            end=nk.COMPUTER,
            kind=ek.CREATE_COMPUTER_EXTENSIONS,
            description="The API client can create computer extensions on the target computer.",
            traversable=True,
        ),
        EdgeDef(
            start=nk.API_CLIENT,
            end=nk.COMPUTER,
            kind=ek.UPDATE_COMPUTER_EXTENSIONS,
            description="The API client can update computer extensions on the target computer.",
            traversable=True,
        ),
        EdgeDef(
            start=nk.API_CLIENT,
            end=nk.TENANT,
            kind=ek.SCRIPTS_NON_TRAVERSABLE,
            description="The API Client can create or update scripts on the target tenant.",
            traversable=False,
        ),
        EdgeDef(
            start=nk.API_CLIENT,
            end=nk.COMPUTER,
            kind=ek.UPDATE_RECURRING_SCRIPTS,
            description="The API Client can update recurring scripts on the target tenant.",
            traversable=True,
        ),
        EdgeDef(
            start=nk.API_CLIENT,
            end=nk.TENANT,
            kind=ek.CREATE_API_ROLES,
            description="The API Client can create roles on the target tenant.",
            traversable=False,
        ),
        EdgeDef(
            start=nk.API_CLIENT,
            end=nk.TENANT,
            kind=ek.UPDATE_ROLES_ASSIGNED_TO_SELF,
            description="The API Client can update roles assigned to itself on the target tenant.",
            traversable=True,
        ),
        EdgeDef(
            start=nk.API_CLIENT,
            end=nk.TENANT,
            kind=ek.CREATE_API_CLIENT_AND_CREATE_ROLE,
            description="The API Client can create and assign roles on the target tenant.",
            traversable=True,
        ),
        EdgeDef(
            start=nk.API_CLIENT,
            end=nk.TENANT,
            kind=ek.CREATE_API_CLIENT_AND_UPDATE_ROLE,
            description="The API Client can create and update roles on the target tenant.",
            traversable=True,
        ),
        EdgeDef(
            start=nk.API_CLIENT,
            end=nk.TENANT,
            kind=ek.CREATE_API_CLIENT_AND_ASSIGN_ROLE,
            description="The API Client can create and assign roles on the target tenant.",
            traversable=True,
        ),
        EdgeDef(
            start=nk.API_CLIENT,
            end=nk.TENANT,
            kind=ek.UPDATE_SELF_AND_UPDATE_ROLES,
            description="The API Client can update roles on the target tenant.",
            traversable=True,
        ),
        EdgeDef(
            start=nk.API_CLIENT,
            end=nk.TENANT,
            kind=ek.UPDATE_SELF_AND_CREATE_ROLES,
            description="The API Client can create roles on the target tenant.",
            traversable=True,
        ),
        EdgeDef(
            start=nk.API_CLIENT,
            end=nk.TENANT,
            kind=ek.UPDATE_SELF_AND_ASSIGN_ROLES,
            description="The API Client can assign roles on the target tenant.",
            traversable=True,
        ),
        EdgeDef(
            start=nk.API_CLIENT,
            end=nk.SSO_INTEGRATION,
            kind=ek.UPDATE_SSO_SETTINGS,
            description="The API Client can update SSO settings on the target tenant.",
            traversable=True,
        ),
    ],
)
class ApiIntegration(JAMFAsset):
    """JAMF API integration resource parsed into a Pydantic model.

    Parses the raw JAMF API integration payload and exposes OpenGraph Node and Edges via
    the `as_node` and `edges` properties.

    Args:
        BaseAsset (BaseAsset): Base class providing OpenGraph node/edge exports.
    """

    model_config = ConfigDict(populate_by_name=True)

    id: int
    display_name: str = Field(alias="displayName")
    authorization_scopes: list[str] = Field(alias="authorizationScopes")
    access_token_lifetime_seconds: int = Field(alias="accessTokenLifetimeSeconds")
    enabled: bool
    app_type: str = Field(alias="appType")
    client_id: str = Field(alias="clientId")

    @property
    def as_node(self) -> JAMFNode:

        all_privileges = []
        for (privilege,) in self._lookup.client_permissions(self.id):
            all_privileges.append(privilege)

        properties = ApiIntegrationProperties(
            name=self.display_name,
            displayname=self.display_name,
            id=self.id,
            tenant=self.tenant_id,
            tier=1,
            enabled=self.enabled,
            client_id=self.client_id,
            privileges=all_privileges,
            app_type=self.app_type,
            environmentid=self.tenant_node_id,
        )
        return JAMFNode(kinds=[nk.API_CLIENT], properties=properties)

    @property
    def _node_id(self) -> str:
        return self.as_node.id

    def _has_privilege(self, privilege: str) -> str | None:
        return self._lookup.client_has_permission(self.id, privilege)

    @property
    def _contains_edge(self):
        yield Edge(
            kind=ek.CONTAINS,
            start=EdgePath(match_by="id", value=self.tenant_node_id),
            end=EdgePath(match_by="id", value=self._node_id),
            properties=EdgeProperties(traversable=True),
        )

    @property
    def _create_accounts_edge(self):
        if self._has_privilege("Create Accounts"):
            yield Edge(
                kind=ek.CREATE_ACCOUNTS,
                start=EdgePath(match_by="id", value=self._node_id),
                end=EdgePath(match_by="id", value=self.tenant_node_id),
                properties=EdgeProperties(traversable=True),
            )

    @property
    def _update_accounts_edge(self):
        if self._has_privilege("Update Accounts"):
            yield Edge(
                kind=ek.UPDATE_ACCOUNTS,
                start=EdgePath(match_by="id", value=self._node_id),
                end=EdgePath(match_by="id", value=self.tenant_node_id),
                properties=EdgeProperties(traversable=True),
            )

    @property
    def _create_policies_edges(self):
        if self._has_privilege("Create Policies"):
            for (computer_id,) in self._lookup.all_computers():
                computer_node_id = JAMFNode.guid(
                    computer_id, nk.COMPUTER, self.tenant_id
                )
                yield Edge(
                    kind=ek.CREATE_POLICIES,
                    start=EdgePath(match_by="id", value=self._node_id),
                    end=EdgePath(match_by="id", value=computer_node_id),
                    properties=EdgeProperties(traversable=True),
                )

    @property
    def _update_policies_edges(self):
        if self._has_privilege("Update Policies") and self._lookup.policies_exist():
            for (computer_id,) in self._lookup.all_computers():
                computer_node_id = JAMFNode.guid(
                    computer_id, nk.COMPUTER, self.tenant_id
                )
                yield Edge(
                    kind=ek.UPDATE_POLICIES,
                    start=EdgePath(match_by="id", value=self._node_id),
                    end=EdgePath(match_by="id", value=computer_node_id),
                    properties=EdgeProperties(traversable=True),
                )

    @property
    def _create_computer_extensions_edges(self):
        if self._has_privilege("Create Computer Extension Attributes"):
            for (computer_id,) in self._lookup.all_computers():
                computer_node_id = JAMFNode.guid(
                    computer_id, nk.COMPUTER, self.tenant_id
                )
                yield Edge(
                    kind=ek.CREATE_COMPUTER_EXTENSIONS,
                    start=EdgePath(match_by="id", value=self._node_id),
                    end=EdgePath(match_by="id", value=computer_node_id),
                    properties=EdgeProperties(traversable=True),
                )

    @property
    def _update_computer_extensions_edges(self):
        if (
            self._has_privilege("Update Computer Extension Attributes")
            and self._lookup.extension_attrs_exist()
        ):
            for (computer_id,) in self._lookup.all_computers():
                computer_node_id = JAMFNode.guid(
                    computer_id, nk.COMPUTER, self.tenant_id
                )
                yield Edge(
                    kind=ek.UPDATE_COMPUTER_EXTENSIONS,
                    start=EdgePath(match_by="id", value=self._node_id),
                    end=EdgePath(match_by="id", value=computer_node_id),
                    properties=EdgeProperties(traversable=True),
                )

    @property
    def _scripts_non_traversable_edge(self):
        if self._has_privilege("Create Scripts") or self._has_privilege(
            "Update Scripts"
        ):
            yield Edge(
                kind=ek.SCRIPTS_NON_TRAVERSABLE,
                start=EdgePath(match_by="id", value=self._node_id),
                end=EdgePath(match_by="id", value=self.tenant_node_id),
                properties=EdgeProperties(traversable=False),
            )

    @property
    def _update_recurring_scripts_edges(self):
        if self._has_privilege("Update Scripts"):
            for (computer_id,) in self._lookup.recurring_policy_computers():
                computer_node_id = JAMFNode.guid(
                    str(computer_id), nk.COMPUTER, self.tenant_id
                )
                yield Edge(
                    kind=ek.UPDATE_RECURRING_SCRIPTS,
                    start=EdgePath(match_by="id", value=self._node_id),
                    end=EdgePath(match_by="id", value=computer_node_id),
                    properties=EdgeProperties(traversable=True),
                )

    @property
    def _create_api_roles_edge(self):
        if self._has_privilege("Create API Roles"):
            yield Edge(
                kind=ek.CREATE_API_ROLES,
                start=EdgePath(match_by="id", value=self._node_id),
                end=EdgePath(match_by="id", value=self.tenant_node_id),
                properties=EdgeProperties(traversable=False),
            )

    @property
    def _update_roles_assigned_to_self_edge(self):
        if self._has_privilege("Update API Roles"):
            yield Edge(
                kind=ek.UPDATE_ROLES_ASSIGNED_TO_SELF,
                start=EdgePath(match_by="id", value=self._node_id),
                end=EdgePath(match_by="id", value=self.tenant_node_id),
                properties=EdgeProperties(traversable=True),
            )

    @property
    def _create_api_client_and_create_role_edge(self):
        if self._has_privilege("Create API Integrations") and self._has_privilege(
            "Create API Roles"
        ):
            yield Edge(
                kind=ek.CREATE_API_CLIENT_AND_CREATE_ROLE,
                start=EdgePath(match_by="id", value=self._node_id),
                end=EdgePath(match_by="id", value=self.tenant_node_id),
                properties=EdgeProperties(traversable=True),
            )

    @property
    def _create_api_client_and_update_role_edge(self):
        if (
            self._has_privilege("Create API Integrations")
            and self._has_privilege("Update API Roles")
            and self._lookup.roles_exist()
        ):
            yield Edge(
                kind=ek.CREATE_API_CLIENT_AND_UPDATE_ROLE,
                start=EdgePath(match_by="id", value=self._node_id),
                end=EdgePath(match_by="id", value=self.tenant_node_id),
                properties=EdgeProperties(traversable=True),
            )

    @property
    def _create_api_client_and_assign_role_edge(self):
        if (
            self._has_privilege("Create API Integrations")
            and self._lookup.roles_exist()
        ):
            yield Edge(
                kind=ek.CREATE_API_CLIENT_AND_ASSIGN_ROLE,
                start=EdgePath(match_by="id", value=self._node_id),
                end=EdgePath(match_by="id", value=self.tenant_node_id),
                properties=EdgeProperties(traversable=True),
            )

    @property
    def _update_self_and_update_roles_edge(self):
        if (
            self._has_privilege("Update API Integrations")
            and self._has_privilege("Update API Roles")
            and self._lookup.roles_exist()
        ):
            yield Edge(
                kind=ek.UPDATE_SELF_AND_UPDATE_ROLES,
                start=EdgePath(match_by="id", value=self._node_id),
                end=EdgePath(match_by="id", value=self.tenant_node_id),
                properties=EdgeProperties(traversable=True),
            )

    @property
    def _update_self_and_create_roles_edge(self):
        if self._has_privilege("Update API Integrations") and self._has_privilege(
            "Create API Roles"
        ):
            yield Edge(
                kind=ek.UPDATE_SELF_AND_CREATE_ROLES,
                start=EdgePath(match_by="id", value=self._node_id),
                end=EdgePath(match_by="id", value=self.tenant_node_id),
                properties=EdgeProperties(traversable=True),
            )

    @property
    def _update_self_and_assign_roles_edge(self):
        if (
            self._has_privilege("Update API Integrations")
            and self._lookup.roles_exist()
        ):
            yield Edge(
                kind=ek.UPDATE_SELF_AND_ASSIGN_ROLES,
                start=EdgePath(match_by="id", value=self._node_id),
                end=EdgePath(match_by="id", value=self.tenant_node_id),
                properties=EdgeProperties(traversable=True),
            )

    @property
    def _update_sso_settings_edges(self):
        if self._has_privilege("Update SSO Settings"):
            sso_config_type = self._lookup.sso_config_type()
            if sso_config_type:
                sso_guid = JAMFNode.guid(
                    f"SSO-{sso_config_type}", nk.SSO_INTEGRATION, self.tenant_id
                )
                yield Edge(
                    kind=ek.UPDATE_SSO_SETTINGS,
                    start=EdgePath(match_by="id", value=self._node_id),
                    end=EdgePath(match_by="id", value=sso_guid),
                    properties=EdgeProperties(traversable=True),
                )
            else:
                for (account_id,) in self._lookup.all_accounts():
                    account_node_id = JAMFNode.guid(
                        str(account_id), nk.ACCOUNT, self.tenant_id
                    )
                    yield Edge(
                        kind=ek.UPDATE_SSO_SETTINGS,
                        start=EdgePath(match_by="id", value=self._node_id),
                        end=EdgePath(match_by="id", value=account_node_id),
                        properties=EdgeProperties(traversable=True),
                    )
                for (group_id,) in self._lookup.all_groups():
                    group_node_id = JAMFNode.guid(
                        str(group_id), nk.GROUP, self.tenant_id
                    )
                    yield Edge(
                        kind=ek.UPDATE_SSO_SETTINGS,
                        start=EdgePath(match_by="id", value=self._node_id),
                        end=EdgePath(match_by="id", value=group_node_id),
                        properties=EdgeProperties(traversable=True),
                    )

    @property
    def edges(self):
        yield from self._contains_edge
        yield from self._create_accounts_edge
        yield from self._update_accounts_edge
        yield from self._create_policies_edges
        yield from self._update_policies_edges
        yield from self._create_computer_extensions_edges
        yield from self._update_computer_extensions_edges
        yield from self._scripts_non_traversable_edge
        yield from self._update_recurring_scripts_edges
        yield from self._create_api_roles_edge
        yield from self._update_roles_assigned_to_self_edge
        yield from self._create_api_client_and_create_role_edge
        yield from self._create_api_client_and_update_role_edge
        yield from self._create_api_client_and_assign_role_edge
        yield from self._update_self_and_update_roles_edge
        yield from self._update_self_and_create_roles_edge
        yield from self._update_self_and_assign_roles_edge
        yield from self._update_sso_settings_edges
