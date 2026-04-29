from dataclasses import dataclass
from typing import Optional

from openhound.core.asset import EdgeDef, NodeDef
from openhound.core.models.entries_dataclass import (
    ConditionalEdgePath,
    Edge,
    EdgePath,
    EdgeProperties,
    PropertyMatch,
)
from pydantic import BaseModel, Field

from openhound_jamf.graph import JAMFAsset, JAMFNode, JAMFNodeProperties
from openhound_jamf.kinds import edges as ek
from openhound_jamf.kinds import nodes as nk
from openhound_jamf.main import app


@dataclass
class AccountProperties(JAMFNodeProperties):
    """JAMF Account node properties

    Attributes:
        full_name: Full name of the Jamf Account
        email: The email address of the Jamf Account
        enabled: Specifies if the account is enabled
        site_id: The Jamf Site ID
        access_level: The access level of the Jamf Account
        privilege_objects: The list of privilege objects
        privilege_actions: The list of privilege actions
        privilege_settings: The list of privilege settings
        privilege_set:
        local_account: Whether the account is local account
        collected: Indicates that the account is collected by OpenHound
    """

    full_name: str
    email: str
    site_id: str
    access_level: str
    enabled: bool
    privilege_objects: list[str]
    privilege_actions: list[str]
    privilege_settings: list[str]
    privilege_set: str
    local_account: bool
    collected: bool = True


class BaseAccount(BaseModel):
    name: str
    id: int


class Site(BaseModel):
    id: int
    name: str


class Privilege(BaseModel):
    jss_objects: list[str] = Field(default_factory=list)
    jss_settings: list[str] = Field(default_factory=list)
    jss_actions: list[str] = Field(default_factory=list)


@app.asset(
    description="Jamf Account asset. Returns a node representing a Jamf Account and its privilege edges.",
    node=NodeDef(
        kind=nk.ACCOUNT,
        description="Jamf Account node",
        icon="user-lock",
        properties=AccountProperties,
    ),
    edges=[
        EdgeDef(
            start=nk.TENANT,
            end=nk.ACCOUNT,
            kind=ek.CONTAINS,
            description="The tenant contains this account.",
        ),
        EdgeDef(
            start=nk.ACCOUNT,
            end=nk.TENANT,
            kind=ek.ADMIN_TO,
            description="The account has administrative permissions on the Jamf tenant.",
            traversable=True,
        ),
        EdgeDef(
            start=nk.ACCOUNT,
            end=nk.SITE,
            kind=ek.ADMIN_TO_SITE,
            description="The account has administrative permissions for the target site.",
            traversable=True,
        ),
        EdgeDef(
            start=nk.ACCOUNT,
            end=nk.TENANT,
            kind=ek.CREATE_ACCOUNTS,
            description="The account can create accounts on the target tenant.",
            traversable=True,
        ),
        EdgeDef(
            start=nk.ACCOUNT,
            end=nk.TENANT,
            kind=ek.UPDATE_ACCOUNTS,
            description="The account can update accounts on the target tenant.",
            traversable=True,
        ),
        EdgeDef(
            start=nk.ACCOUNT,
            end=nk.COMPUTER,
            kind=ek.CREATE_POLICIES,
            description="The account can create policies on the target tenant.",
            traversable=True,
        ),
        EdgeDef(
            start=nk.ACCOUNT,
            end=nk.COMPUTER,
            kind=ek.UPDATE_POLICIES,
            description="The account can update policies on the target computer.",
            traversable=True,
        ),
        EdgeDef(
            start=nk.ACCOUNT,
            end=nk.COMPUTER,
            kind=ek.CREATE_COMPUTER_EXTENSIONS,
            description="The account can create computer extensions on the target computer.",
            traversable=True,
        ),
        EdgeDef(
            start=nk.ACCOUNT,
            end=nk.COMPUTER,
            kind=ek.UPDATE_COMPUTER_EXTENSIONS,
            description="The account can update computer extensions on the target computer.",
            traversable=True,
        ),
        EdgeDef(
            start=nk.ACCOUNT,
            end=nk.TENANT,
            kind=ek.SCRIPTS_NON_TRAVERSABLE,
            description="The account can create or update scripts on the target.",
            traversable=False,
        ),
        EdgeDef(
            start=nk.ACCOUNT,
            end=nk.COMPUTER,
            kind=ek.UPDATE_RECURRING_SCRIPTS,
            description="The account can update recurring scripts on the target computer.",
            traversable=True,
        ),
        EdgeDef(
            start=nk.ACCOUNT,
            end=nk.TENANT,
            kind=ek.CREATE_API_ROLES,
            description="The target can create API Roles on the target tenant.",
            traversable=False,
        ),
        EdgeDef(
            start=nk.ACCOUNT,
            end=nk.TENANT,
            kind=ek.UPDATE_API_ROLES,
            description="The account can update API Roles on the target tenant.",
            traversable=False,
        ),
        EdgeDef(
            start=nk.ACCOUNT,
            end=nk.TENANT,
            kind=ek.CREATE_API_CLIENT_AND_CREATE_ROLE,
            description="The account can create API clients and roles on the target tenant.",
            traversable=True,
        ),
        EdgeDef(
            start=nk.ACCOUNT,
            end=nk.TENANT,
            kind=ek.CREATE_API_CLIENT_AND_UPDATE_ROLE,
            description="The account can create API clients and update roles on the target tenant.",
            traversable=True,
        ),
        EdgeDef(
            start=nk.ACCOUNT,
            end=nk.TENANT,
            kind=ek.CREATE_API_CLIENT_AND_ASSIGN_ROLE,
            description="The account can create API clients and assign roles on the target tenant.",
            traversable=True,
        ),
        EdgeDef(
            start=nk.ACCOUNT,
            end=nk.TENANT,
            kind=ek.UPDATE_API_CLIENT_AND_UPDATE_ROLES,
            description="The account can update API clients and assign roles on the target tenant.",
            traversable=False,
        ),
        EdgeDef(
            start=nk.ACCOUNT,
            end=nk.TENANT,
            kind=ek.UPDATE_API_CLIENT_AND_CREATE_ROLES,
            description="The account can update API clients and assign roles on the target tenant.",
            traversable=False,
        ),
        EdgeDef(
            start=nk.ACCOUNT,
            end=nk.TENANT,
            kind=ek.UPDATE_API_CLIENT_AND_ASSIGN_ROLE,
            description="The account can update API clients and assign roles on the target tenant.",
            traversable=False,
        ),
        EdgeDef(
            start=nk.ACCOUNT,
            end=nk.SSO_INTEGRATION,
            kind=ek.UPDATE_SSO_SETTINGS,
            description="The account can update SSO settings on the target tenant.",
            traversable=True,
        ),
    ],
)
class Account(JAMFAsset):
    """JAMF account resource parsed into a Pydantic model.

    Parses the raw JAMF account payload and exposes OpenGraph Node and Edges via
    the `as_node` and `edges` properties.

    Args:
        BaseAsset (BaseAsset): Base class providing OpenGraph node/edge exports.
    """

    id: int
    name: str
    full_name: str
    email: str
    email_address: str
    enabled: str
    force_password_change: bool
    access_level: str
    privilege_set: str
    site: Optional[Site] | None = None
    privileges: Privilege | None = None
    directory_user: bool

    @property
    def as_node(self):

        tier_eval = (
            self.privilege_set == "Administrator" and self.access_level == "Full Access"
        )
        properties = AccountProperties(
            name=self.name,
            displayname=self.name,
            id=self.id,
            tenant=self.tenant_id,
            tier=0 if tier_eval else 1,
            full_name=self.full_name,
            email=self.email,
            enabled=self.enabled == "Enabled",
            site_id=str(self.site.id) if self.site else "-1",
            access_level=self.access_level,
            privilege_objects=self.privileges.jss_objects if self.privileges else [],
            privilege_actions=self.privileges.jss_actions if self.privileges else [],
            privilege_settings=self.privileges.jss_settings if self.privileges else [],
            environmentid=self.tenant_node_id,
            privilege_set=self.privilege_set,
            local_account=self.directory_user,
        )
        return JAMFNode(kinds=[nk.ACCOUNT], properties=properties)

    @property
    def _node_id(self) -> str:
        return self.as_node.id

    def _has_privilege(self, privilege: str) -> bool:
        return self.privileges is not None and privilege in self.privileges.jss_objects

    def _has_setting_privilege(self, privilege: str) -> bool:
        return self.privileges is not None and privilege in self.privileges.jss_settings

    @property
    def _is_admin(self) -> bool:
        return self.privilege_set == "Administrator" and self.access_level in (
            "Full Access",
            "Site Access",
        )

    def _target_computers(self):
        if self.access_level == "Site Access" and self.site:
            return self._lookup.computers_by_site(str(self.site.id))
        return self._lookup.all_computers()

    @property
    def _admin_to_edge(self):
        if self.access_level == "Full Access" and self.privilege_set == "Administrator":
            yield Edge(
                kind=ek.ADMIN_TO,
                start=EdgePath(match_by="id", value=self._node_id),
                end=EdgePath(match_by="id", value=self.tenant_node_id),
                properties=EdgeProperties(traversable=True),
            )

    @property
    def _az_matched_email_edges(self):
        match_by = PropertyMatch(key="email", value=self.email_address)
        yield Edge(
            kind=ek.AZ_MATCHED_EMAIL,
            start=EdgePath(match_by="id", value=self._node_id),
            end=ConditionalEdgePath(kind="AZUser", property_matchers=[match_by]),
        )

    @property
    def _admin_to_site_edges(self):
        if (
            self.access_level == "Site Access"
            and self.privilege_set == "Administrator"
            and self.site
        ):
            site_node_id = JAMFNode.guid(str(self.site.id), nk.SITE, self.tenant_id)
            yield Edge(
                kind=ek.ADMIN_TO_SITE,
                start=EdgePath(match_by="id", value=self._node_id),
                end=EdgePath(match_by="id", value=site_node_id),
                properties=EdgeProperties(traversable=True),
            )

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
        if not self._is_admin and self._has_privilege("Create Accounts"):
            yield Edge(
                kind=ek.CREATE_ACCOUNTS,
                start=EdgePath(match_by="id", value=self._node_id),
                end=EdgePath(match_by="id", value=self.tenant_node_id),
                properties=EdgeProperties(traversable=True),
            )

    @property
    def _update_accounts_edge(self):
        if not self._is_admin and self._has_privilege("Update Accounts"):
            yield Edge(
                kind=ek.UPDATE_ACCOUNTS,
                start=EdgePath(match_by="id", value=self._node_id),
                end=EdgePath(match_by="id", value=self.tenant_node_id),
                properties=EdgeProperties(traversable=True),
            )

    @property
    def _create_policies_edges(self):
        if not self._is_admin and self._has_privilege("Create Policies"):
            for (computer_id,) in self._target_computers():
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
        if (
            not self._is_admin
            and self._has_privilege("Update Policies")
            and self._lookup.policies_exist()
        ):
            for (computer_id,) in self._target_computers():
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
        if not self._is_admin and self._has_privilege(
            "Create Computer Extension Attributes"
        ):
            for (computer_id,) in self._target_computers():
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
            not self._is_admin
            and self._has_privilege("Update Computer Extension Attributes")
            and self._lookup.extension_attrs_exist()
        ):
            for (computer_id,) in self._target_computers():
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
        if not self._is_admin and (
            self._has_privilege("Create Scripts")
            or self._has_privilege("Update Scripts")
        ):
            if self.access_level == "Site Access" and self.site:
                site_node_id = JAMFNode.guid(str(self.site.id), nk.SITE, self.tenant_id)
                yield Edge(
                    kind=ek.SCRIPTS_NON_TRAVERSABLE,
                    start=EdgePath(match_by="id", value=self._node_id),
                    end=EdgePath(match_by="id", value=site_node_id),
                    properties=EdgeProperties(traversable=False),
                )
            else:
                yield Edge(
                    kind=ek.SCRIPTS_NON_TRAVERSABLE,
                    start=EdgePath(match_by="id", value=self._node_id),
                    end=EdgePath(match_by="id", value=self.tenant_node_id),
                    properties=EdgeProperties(traversable=False),
                )

    @property
    def _update_recurring_scripts_edges(self):
        if not self._is_admin and self._has_privilege("Update Scripts"):
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
        if not self._is_admin and self._has_privilege("Create API Roles"):
            yield Edge(
                kind=ek.CREATE_API_ROLES,
                start=EdgePath(match_by="id", value=self._node_id),
                end=EdgePath(match_by="id", value=self.tenant_node_id),
                properties=EdgeProperties(traversable=False),
            )

    @property
    def _update_api_roles_edge(self):
        if not self._is_admin and self._has_privilege("Update API Roles"):
            yield Edge(
                kind=ek.UPDATE_API_ROLES,
                start=EdgePath(match_by="id", value=self._node_id),
                end=EdgePath(match_by="id", value=self.tenant_node_id),
                properties=EdgeProperties(traversable=False),
            )

    @property
    def _create_api_client_and_create_role_edge(self):
        if (
            not self._is_admin
            and self._has_privilege("Create API Integrations")
            and self._has_privilege("Create API Roles")
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
            not self._is_admin
            and self._has_privilege("Create API Integrations")
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
            not self._is_admin
            and self._has_privilege("Create API Integrations")
            and self._lookup.roles_exist()
        ):
            yield Edge(
                kind=ek.CREATE_API_CLIENT_AND_ASSIGN_ROLE,
                start=EdgePath(match_by="id", value=self._node_id),
                end=EdgePath(match_by="id", value=self.tenant_node_id),
                properties=EdgeProperties(traversable=True),
            )

    @property
    def _update_api_client_and_update_roles_edge(self):
        if (
            not self._is_admin
            and self._has_privilege("Update API Integrations")
            and self._has_privilege("Update API Roles")
            and self._lookup.roles_exist()
            and self._lookup.clients_exist()
        ):
            yield Edge(
                kind=ek.UPDATE_API_CLIENT_AND_UPDATE_ROLES,
                start=EdgePath(match_by="id", value=self._node_id),
                end=EdgePath(match_by="id", value=self.tenant_node_id),
                properties=EdgeProperties(traversable=False),
            )

    @property
    def _update_api_client_and_create_roles_edge(self):
        if (
            not self._is_admin
            and self._has_privilege("Update API Integrations")
            and self._has_privilege("Create API Roles")
            and self._lookup.clients_exist()
        ):
            yield Edge(
                kind=ek.UPDATE_API_CLIENT_AND_CREATE_ROLES,
                start=EdgePath(match_by="id", value=self._node_id),
                end=EdgePath(match_by="id", value=self.tenant_node_id),
                properties=EdgeProperties(traversable=False),
            )

    @property
    def _update_api_client_and_assign_role_edge(self):
        if (
            not self._is_admin
            and self._has_privilege("Update API Integrations")
            and self._lookup.roles_exist()
            and self._lookup.clients_exist()
        ):
            yield Edge(
                kind=ek.UPDATE_API_CLIENT_AND_ASSIGN_ROLE,
                start=EdgePath(match_by="id", value=self._node_id),
                end=EdgePath(match_by="id", value=self.tenant_node_id),
                properties=EdgeProperties(traversable=False),
            )

    @property
    def _update_sso_settings_edges(self):
        if not self._is_admin and self._has_setting_privilege("Update SSO Settings"):
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
        yield from self._admin_to_edge
        yield from self._admin_to_site_edges
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
        yield from self._update_api_roles_edge
        yield from self._create_api_client_and_create_role_edge
        yield from self._create_api_client_and_update_role_edge
        yield from self._create_api_client_and_assign_role_edge
        yield from self._update_api_client_and_update_roles_edge
        yield from self._update_api_client_and_create_roles_edge
        yield from self._update_api_client_and_assign_role_edge
        yield from self._update_sso_settings_edges
        yield from self._az_matched_email_edges
