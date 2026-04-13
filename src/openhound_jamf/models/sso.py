from dataclasses import dataclass

from openhound.core.asset import EdgeDef, NodeDef
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties
from pydantic import BaseModel, ConfigDict, Field

from openhound_jamf.graph import JAMFAsset, JAMFNode, JAMFNodeProperties
from openhound_jamf.kinds import edges as ek
from openhound_jamf.kinds import nodes as nk
from openhound_jamf.main import app


@dataclass
class SSOProperties(JAMFNodeProperties):
    """JAMF SSO node properties"""

    id: str
    type: str
    bypass_allowed: bool
    sso_enabled: bool


class SAMLSettings(BaseModel):
    token_expiration_disabled: bool = Field(alias="tokenExpirationDisabled")
    user_attribute_enabled: bool = Field(alias="userAttributeEnabled")
    user_attribute_name: str = Field(alias="userAttributeName")
    user_mapping: str = Field(alias="userMapping")
    group_attribute_name: str = Field(alias="groupAttributeName")
    group_rdn_key: str = Field(alias="groupRdnKey")
    idp_url: str = Field(alias="idpUrl")
    idp_provider_type: str = Field(alias="idpProviderType")
    entity_id: str = Field(alias="entityId")


class OIDCSettings(BaseModel):
    user_mapping: str = Field(alias="userMapping")
    username_attribute_claim_mapping: str = Field(alias="usernameAttributeClaimMapping")
    jamf_id_authentication_enabled: bool = Field(alias="jamfIdAuthenticationEnabled")


class EnrollmentConfig(BaseModel):
    hosts: list[str]


@app.asset(
    description="Jamf SSO asset. Returns a node representing the SSO configuration for JAMF.",
    node=NodeDef(
        kind=nk.SSO_INTEGRATION,
        description="Jamf SSO Integration node",
        icon="key",
        properties=SSOProperties,
    ),
    edges=[
        EdgeDef(
            start=nk.TENANT,
            end=nk.SSO_INTEGRATION,
            kind=ek.CONTAINS,
            description="The tenant contains this SSO integration.",
            traversable=True,
        ),
        EdgeDef(
            start=nk.SSO_INTEGRATION,
            end=nk.ACCOUNT,
            kind=ek.SSO_LOGIN,
            description="SSO sources can map attributes to authenticate and inherit the privileges of the target.",
            traversable=True,
        ),
        EdgeDef(
            start=nk.SSO_INTEGRATION,
            end=nk.GROUP,
            kind=ek.SSO_LOGIN,
            description="SSO sources can map group attributes to authenticate and inherit the privileges of the target group.",
            traversable=True,
        ),
    ],
)
class SSO(JAMFAsset):
    model_config = ConfigDict(populate_by_name=True)

    configuration_type: str = Field(alias="configurationType")
    sso_for_enrollment_enabled: bool = Field(alias="ssoForEnrollmentEnabled")
    saml_settings: SAMLSettings | None = Field(alias="samlSettings", default=None)
    oidc_settings: OIDCSettings | None = Field(alias="oidcSettings", default=None)
    sso_enabled: bool = Field(alias="ssoEnabled")
    sso_for_mac_os_self_service_enabled: bool = Field(
        alias="ssoForMacOsSelfServiceEnabled"
    )
    enrollment_sso_for_account_driven_enrollment_enabled: bool = Field(
        alias="enrollmentSsoForAccountDrivenEnrollmentEnabled"
    )
    enrollment_sso_config: EnrollmentConfig = Field(alias="enrollmentSsoConfig")
    group_enrollment_access_enabled: bool = Field(alias="groupEnrollmentAccessEnabled")
    group_enrollment_access_name: str = Field(alias="groupEnrollmentAccessName")

    @property
    def id(self):
        return f"SSO-{self.configuration_type}"

    @property
    def as_node(self):
        properties = SSOProperties(
            id=self.id,
            name=self.name,
            displayname=self.name,
            tenant=self.tenant_id,
            type=self.configuration_type,
            bypass_allowed=self.sso_for_enrollment_enabled,
            tier=1,
            sso_enabled=self.sso_enabled,
            environmentid=self.tenant_node_id,
        )
        return JAMFNode(kinds=[nk.SSO_INTEGRATION], properties=properties)

    @property
    def name(self):
        return f"JamfSSO {self.tenant_id}"

    @property
    def _node_id(self) -> str:
        return self.as_node.id

    @property
    def _sso_account_edges(self):
        for (account_id,) in self._lookup.all_accounts():
            account_node_id = JAMFNode.guid(account_id, nk.ACCOUNT, self.tenant_id)
            yield Edge(
                kind=ek.SSO_LOGIN,
                start=EdgePath(match_by="id", value=self._node_id),
                end=EdgePath(match_by="id", value=account_node_id),
                properties=EdgeProperties(traversable=True),
            )

    @property
    def _sso_group_edges(self):
        if self.saml_settings and (
            self.saml_settings.group_attribute_name != ""
            or self.saml_settings.group_rdn_key != ""
        ):
            for (group_id,) in self._lookup.all_groups():
                group_node_id = JAMFNode.guid(group_id, nk.GROUP, self.tenant_id)
                yield Edge(
                    kind=ek.SSO_LOGIN,
                    start=EdgePath(match_by="id", value=self._node_id),
                    end=EdgePath(match_by="id", value=group_node_id),
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
    def edges(self):
        yield from self._sso_account_edges
        yield from self._sso_group_edges
        yield from self._contains_edge
