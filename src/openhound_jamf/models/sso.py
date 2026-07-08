from dataclasses import dataclass, field

from openhound.core.asset import EdgeDef, NodeDef
from openhound.core.models.entries_dataclass import (
    Edge,
    EdgePath,
    EdgeProperties,
    Node as BaseNode,
    NodeProperties,
)
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


@dataclass
class SAMLNodeProperties(NodeProperties):
    """Normalized SAML node properties emitted from Jamf SSO evidence."""

    objectid: str
    source_kind: str
    schema_contract_version: str = "opengraph-saml-v0.2.2"
    enabled: bool | None = None
    native_object_id: str | None = None
    native_object_kind: str | None = None
    sp_entity_id: str | None = None
    entity_id: str | None = None
    issuer: str | None = None
    acs_url: str | None = None
    route_key: str | None = None
    comparison_mode: str | None = None


@dataclass
class SAMLNode(BaseNode):
    properties: SAMLNodeProperties
    id: str = field(init=False)

    def __post_init__(self):
        self.id = self.guid(self.properties.objectid, self.kinds[0])


@dataclass
class SAMLEdgeProperties(EdgeProperties):
    model_layer: str = "adapter input"
    route_evidence: str | None = None
    match_values: list[str] | None = None
    account_state: str | None = None
    mapping_attribute: str | None = None


class ParsedServiceProviderMetadata(BaseModel):
    entity_id: str | None = Field(alias="entityId", default=None)
    acs_url: str | None = Field(alias="acsUrl", default=None)
    acs_binding: str | None = Field(alias="acsBinding", default=None)
    name_id_formats: list[str] = Field(alias="nameIdFormats", default_factory=list)


class ParsedIdentityProviderMetadata(BaseModel):
    entity_id: str | None = Field(alias="entityId", default=None)
    sso_url: str | None = Field(alias="ssoUrl", default=None)
    sso_binding: str | None = Field(alias="ssoBinding", default=None)
    name_id_formats: list[str] = Field(alias="nameIdFormats", default_factory=list)


class ParsedSAMLMetadata(BaseModel):
    sp: ParsedServiceProviderMetadata | None = None
    idp: ParsedIdentityProviderMetadata | None = None
    errors: list[str] = Field(default_factory=list)


class SAMLSettings(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    group_attribute_name: str = Field(alias="groupAttributeName")
    group_rdn_key: str = Field(alias="groupRdnKey")
    user_mapping: str | None = Field(alias="userMapping", default=None)
    idp_provider_type: str | None = Field(alias="idpProviderType", default=None)
    idp_url: str | None = Field(alias="idpUrl", default=None)
    entity_id: str | None = Field(alias="entityId", default=None)
    metadata_source: str | None = Field(alias="metadataSource", default=None)


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
    sso_enabled: bool = Field(alias="ssoEnabled")

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
            tier=0,
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


class SAMLSSOBase(JAMFAsset):
    model_config = ConfigDict(populate_by_name=True)

    configuration_type: str = Field(alias="configurationType")
    saml_settings: SAMLSettings | None = Field(alias="samlSettings", default=None)
    saml_metadata: ParsedSAMLMetadata | None = Field(alias="samlMetadata", default=None)
    sso_enabled: bool = Field(alias="ssoEnabled")

    @property
    def native_sso_id(self):
        return f"SSO-{self.configuration_type}"

    @property
    def native_sso_node_id(self):
        return JAMFNode.guid(self.native_sso_id, nk.SSO_INTEGRATION, self.tenant_id)

    @property
    def is_saml(self) -> bool:
        return self.configuration_type.upper() == "SAML" and self.saml_settings is not None

    @property
    def sp_entity_id(self) -> str | None:
        if self.saml_metadata and self.saml_metadata.sp:
            return self.saml_metadata.sp.entity_id or self.saml_settings.entity_id
        if self.saml_settings:
            return self.saml_settings.entity_id
        return None

    @property
    def acs_url(self) -> str | None:
        if self.saml_metadata and self.saml_metadata.sp:
            return self.saml_metadata.sp.acs_url
        return None

    @property
    def issuer_entity_id(self) -> str | None:
        if self.saml_metadata and self.saml_metadata.idp:
            return self.saml_metadata.idp.entity_id
        return None

    @property
    def service_provider_objectid(self) -> str | None:
        if not self.is_saml or not self.sp_entity_id:
            return None
        return f"jamf:{self.tenant_id}:saml-sp:{self.sp_entity_id}"

    @property
    def service_provider_node_id(self) -> str | None:
        if not self.service_provider_objectid:
            return None
        return SAMLNode.guid(self.service_provider_objectid, nk.SAML_SERVICE_PROVIDER)

    @property
    def issuer_objectid(self) -> str | None:
        if not self.issuer_entity_id:
            return None
        return f"saml-issuer:{self.issuer_entity_id}"

    @property
    def issuer_node_id(self) -> str | None:
        if not self.issuer_objectid:
            return None
        return SAMLNode.guid(self.issuer_objectid, nk.SAML_ISSUER)

    @property
    def acs_objectid(self) -> str | None:
        if not self.acs_url or not self.sp_entity_id:
            return None
        return f"saml-acs:{self.acs_url}|{self.sp_entity_id}"

    @property
    def acs_node_id(self) -> str | None:
        if not self.acs_objectid:
            return None
        return SAMLNode.guid(self.acs_objectid, nk.SAML_ASSERTION_CONSUMER_SERVICE)

    @property
    def match_mapping_attribute(self) -> str | None:
        if not self.saml_settings or not self.saml_settings.user_mapping:
            return None
        mapping = self.saml_settings.user_mapping.upper()
        if mapping == "EMAIL":
            return "email"
        if mapping == "USERNAME":
            return "name"
        return None

    def account_match_values(self, account) -> list[str]:
        mapping = self.match_mapping_attribute
        if not mapping:
            return []
        value = account.get(mapping)
        if not value:
            return []
        return [str(value)]

    @property
    def as_node(self):
        return None

    @property
    def edges(self):
        return []


@app.asset(
    description="Normalized SAML Service Provider emitted from Jamf SSO settings.",
    node=NodeDef(
        kind=nk.SAML_SERVICE_PROVIDER,
        description="SAML Service Provider node",
        icon="plug",
        properties=SAMLNodeProperties,
    ),
    edges=[
        EdgeDef(
            start=nk.SSO_INTEGRATION,
            end=nk.SAML_SERVICE_PROVIDER,
            kind=ek.SAML_IMPLEMENTS,
            description="The native Jamf SSO integration implements a normalized SAML service provider.",
        ),
        EdgeDef(
            start=nk.SAML_SERVICE_PROVIDER,
            end=nk.SAML_ISSUER,
            kind=ek.SAML_TRUSTS_ISSUER,
            description="The Jamf service provider trusts the upstream SAML issuer.",
        ),
        EdgeDef(
            start=nk.SAML_SERVICE_PROVIDER,
            end=nk.SAML_ASSERTION_CONSUMER_SERVICE,
            kind=ek.SAML_HAS_ASSERTION_CONSUMER_SERVICE,
            description="The Jamf service provider owns this assertion consumer service route.",
        ),
        EdgeDef(
            start=nk.SAML_SERVICE_PROVIDER,
            end=nk.ACCOUNT,
            kind=ek.SAML_HAS_ACCOUNT,
            description="The Jamf service provider can map SAML assertions to this existing Jamf account.",
        ),
    ],
)
class SAMLServiceProvider(SAMLSSOBase):
    @property
    def as_node(self):
        if not self.service_provider_objectid:
            return None
        properties = SAMLNodeProperties(
            objectid=self.service_provider_objectid,
            name=f"Jamf SAML SP {self.tenant_id}",
            displayname=f"Jamf SAML SP {self.tenant_id}",
            environmentid=self.tenant_node_id,
            source_kind="jamf",
            enabled=self.sso_enabled,
            native_object_id=self.native_sso_id,
            native_object_kind=nk.SSO_INTEGRATION,
            sp_entity_id=self.sp_entity_id,
            entity_id=self.sp_entity_id,
        )
        return SAMLNode(kinds=[nk.SAML_SERVICE_PROVIDER], properties=properties)

    @property
    def _implements_edge(self):
        if self.service_provider_node_id:
            yield Edge(
                kind=ek.SAML_IMPLEMENTS,
                start=EdgePath(match_by="id", value=self.native_sso_node_id),
                end=EdgePath(match_by="id", value=self.service_provider_node_id),
                properties=SAMLEdgeProperties(),
            )

    @property
    def _trusts_issuer_edge(self):
        if self.service_provider_node_id and self.issuer_node_id:
            yield Edge(
                kind=ek.SAML_TRUSTS_ISSUER,
                start=EdgePath(match_by="id", value=self.service_provider_node_id),
                end=EdgePath(match_by="id", value=self.issuer_node_id),
                properties=SAMLEdgeProperties(route_evidence="issuer"),
            )

    @property
    def _has_acs_edge(self):
        if self.service_provider_node_id and self.acs_node_id:
            yield Edge(
                kind=ek.SAML_HAS_ASSERTION_CONSUMER_SERVICE,
                start=EdgePath(match_by="id", value=self.service_provider_node_id),
                end=EdgePath(match_by="id", value=self.acs_node_id),
                properties=SAMLEdgeProperties(route_evidence="acs_url + sp_entity_id"),
            )

    @property
    def _has_account_edges(self):
        if not self.service_provider_node_id or not self.match_mapping_attribute:
            return

        for account in self._lookup.all_account_saml_bindings():
            account_id = account["id"]
            match_values = self.account_match_values(account)
            if not match_values:
                continue

            account_node_id = JAMFNode.guid(account_id, nk.ACCOUNT, self.tenant_id)
            account_state = "enabled" if account.get("enabled") == "Enabled" else "disabled"
            yield Edge(
                kind=ek.SAML_HAS_ACCOUNT,
                start=EdgePath(match_by="id", value=self.service_provider_node_id),
                end=EdgePath(match_by="id", value=account_node_id),
                properties=SAMLEdgeProperties(
                    match_values=match_values,
                    account_state=account_state,
                    mapping_attribute=self.match_mapping_attribute,
                ),
            )

    @property
    def edges(self):
        yield from self._implements_edge
        yield from self._trusts_issuer_edge
        yield from self._has_acs_edge
        yield from self._has_account_edges


@app.asset(
    description="Normalized SAML trusted issuer emitted from Jamf SSO settings.",
    node=NodeDef(
        kind=nk.SAML_ISSUER,
        description="SAML Issuer node",
        icon="stamp",
        properties=SAMLNodeProperties,
    ),
)
class SAMLIssuer(SAMLSSOBase):
    @property
    def as_node(self):
        if not self.issuer_objectid or not self.issuer_entity_id:
            return None
        properties = SAMLNodeProperties(
            objectid=self.issuer_objectid,
            name=f"Trusted issuer {self.issuer_entity_id}",
            displayname=f"Trusted issuer {self.issuer_entity_id}",
            environmentid=self.tenant_node_id,
            source_kind="jamf",
            entity_id=self.issuer_entity_id,
            issuer=self.issuer_entity_id,
            comparison_mode="exact_trimmed",
        )
        return SAMLNode(kinds=[nk.SAML_ISSUER], properties=properties)

    @property
    def edges(self):
        return []


@app.asset(
    description="Normalized SAML Assertion Consumer Service emitted from Jamf SP metadata.",
    node=NodeDef(
        kind=nk.SAML_ASSERTION_CONSUMER_SERVICE,
        description="SAML Assertion Consumer Service node",
        icon="right-to-bracket",
        properties=SAMLNodeProperties,
    ),
)
class SAMLAssertionConsumerService(SAMLSSOBase):
    @property
    def as_node(self):
        if not self.acs_objectid or not self.acs_url or not self.sp_entity_id:
            return None
        properties = SAMLNodeProperties(
            objectid=self.acs_objectid,
            name=f"Jamf ACS {self.acs_url}",
            displayname=f"Jamf ACS {self.acs_url}",
            environmentid=self.tenant_node_id,
            source_kind="jamf",
            acs_url=self.acs_url,
            sp_entity_id=self.sp_entity_id,
            route_key="acs_url + sp_entity_id",
        )
        return SAMLNode(
            kinds=[nk.SAML_ASSERTION_CONSUMER_SERVICE], properties=properties
        )

    @property
    def edges(self):
        return []
