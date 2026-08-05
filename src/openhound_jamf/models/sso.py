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


SAML_CONTRACT_VERSION = "opengraph-saml-v0.3.0"
ACCOUNT_RESOLUTION_PROFILE = "saml_account_resolution_v1"


@dataclass
class SSOProperties(JAMFNodeProperties):
    """JAMF SSO node properties"""

    id: str
    type: str
    bypass_allowed: bool
    sso_enabled: bool


@dataclass
class SAMLNodeProperties(NodeProperties):
    """Normalized SAML node properties emitted from Jamf SSO evidence.

    Attributes:
        source_object_id: Stable source object identifier used to derive the OpenGraph ID.
        source_kind: Collector source that produced the SAML evidence.
        schema_contract_version: Normalized SAML contract version.
        enabled: Whether the Jamf SSO service provider is enabled.
        native_object_id: Identifier of the native Jamf SSO integration.
        native_object_kind: OpenGraph kind of the native Jamf SSO integration.
        sp_entity_id: Service-provider entity ID associated with this SAML route.
        entity_id: SAML entity ID for a service provider or trusted issuer.
        issuer: Trusted upstream SAML issuer entity ID.
        acs_url: Assertion consumer service endpoint URL.
        route_key: Description of the route fields used for correlation.
        comparison_mode: Matching behavior required for issuer correlation.
        metadata_errors: Metadata retrieval or parsing failures retained for diagnostics.
    """

    source_object_id: str
    source_kind: str
    schema_contract_version: str = SAML_CONTRACT_VERSION
    enabled: bool | None = None
    native_object_id: str | None = None
    native_object_kind: str | None = None
    sp_entity_id: str | None = None
    entity_id: str | None = None
    issuer: str | None = None
    acs_url: str | None = None
    route_key: str | None = None
    comparison_mode: str | None = None
    metadata_errors: list[str] = field(default_factory=list)
    expression_language: str | None = None
    expression_profile: str | None = None
    expression: str | None = None
    summary: str | None = None


@dataclass
class SAMLNode(BaseNode):
    properties: SAMLNodeProperties
    id: str = field(init=False)

    def __post_init__(self):
        self.id = self.guid(self.properties.source_object_id, self.kinds[0])


@dataclass
class SAMLEdgeProperties(EdgeProperties):
    """Properties attached to normalized Jamf SAML relationship evidence.

    Attributes:
        model_layer: SAML processing layer that emitted the relationship.
        route_evidence: Native evidence supporting an issuer or ACS route.
        match_values: Authoritative values used to match an IdP assertion to a Jamf account.
        account_state: Normalized lifecycle state of the Jamf account.
        mapping_attribute: Jamf attribute selected by the configured user mapping.
    """

    model_layer: str = "adapter input"
    route_evidence: str | None = None
    match_values: list[str] | None = None
    account_state: str | None = None
    mapping_attribute: str | None = None
    schema_contract_version: str = SAML_CONTRACT_VERSION
    email_match_values: list[str] | None = None
    scoped_exact_match_values: list[str] | None = None
    canonical_match_values: list[str] | None = None


class ParsedAssertionConsumerService(BaseModel):
    acs_url: str | None = Field(alias="acsUrl", default=None)
    acs_binding: str | None = Field(alias="acsBinding", default=None)
    index: str | None = None
    is_default: bool = Field(alias="isDefault", default=False)


class ParsedServiceProviderMetadata(BaseModel):
    entity_id: str | None = Field(alias="entityId", default=None)
    acs_url: str | None = Field(alias="acsUrl", default=None)
    acs_binding: str | None = Field(alias="acsBinding", default=None)
    name_id_formats: list[str] = Field(alias="nameIdFormats", default_factory=list)
    assertion_consumer_services: list[ParsedAssertionConsumerService] = Field(
        alias="assertionConsumerServices",
        default_factory=list,
    )


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
        acs = self.acs_services
        if acs:
            return acs[0].acs_url
        return None

    @property
    def acs_services(self) -> list[ParsedAssertionConsumerService]:
        if not self.saml_metadata or not self.saml_metadata.sp:
            return []
        services = [
            service
            for service in self.saml_metadata.sp.assertion_consumer_services
            if service.acs_url
        ]
        if services:
            return services
        if self.saml_metadata.sp.acs_url:
            return [
                ParsedAssertionConsumerService(
                    acsUrl=self.saml_metadata.sp.acs_url,
                    acsBinding=self.saml_metadata.sp.acs_binding,
                    isDefault=True,
                )
            ]
        return []

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

    def acs_objectid_for(self, acs_url: str | None) -> str | None:
        if not acs_url or not self.sp_entity_id:
            return None
        return f"saml-acs:{acs_url}|{self.sp_entity_id}"

    @property
    def acs_objectid(self) -> str | None:
        return self.acs_objectid_for(self.acs_url)

    def acs_node_id_for(self, acs_url: str | None) -> str | None:
        objectid = self.acs_objectid_for(acs_url)
        if not objectid:
            return None
        return SAMLNode.guid(objectid, nk.SAML_ASSERTION_CONSUMER_SERVICE)

    @property
    def acs_node_id(self) -> str | None:
        return self.acs_node_id_for(self.acs_url)

    @property
    def metadata_errors(self) -> list[str]:
        if not self.saml_metadata:
            return []
        return self.saml_metadata.errors

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
    def account_resolution_rule_objectid(self) -> str | None:
        mapping = self.match_mapping_attribute
        if not self.service_provider_objectid or mapping not in {"email", "name"}:
            return None
        return f"{self.service_provider_objectid}:account-resolution:{mapping}"

    @property
    def account_resolution_rule_node_id(self) -> str | None:
        if not self.account_resolution_rule_objectid:
            return None
        return SAMLNode.guid(
            self.account_resolution_rule_objectid,
            nk.SAML_ACCOUNT_RESOLUTION_RULE,
        )

    @property
    def account_resolution_field_objectid(self) -> str | None:
        if self.match_mapping_attribute != "name" or not self.service_provider_objectid:
            return None
        return f"{self.service_provider_objectid}:account-field:username"

    @property
    def account_resolution_field_node_id(self) -> str | None:
        if not self.account_resolution_field_objectid:
            return None
        return SAMLNode.guid(
            self.account_resolution_field_objectid,
            nk.SAML_ACCOUNT_RESOLUTION_FIELD,
        )

    @property
    def account_resolution_expression(self) -> str | None:
        if self.match_mapping_attribute == "email":
            return (
                "assertion.email_match_values.exists(value, value in "
                "account.email_match_values)"
            )
        if self.match_mapping_attribute == "name":
            return (
                'account.fields.exists(field, field.name == "username" && '
                "assertion.scoped_exact_match_values.exists(value, value in "
                "field.match_values))"
            )
        return None

    @property
    def account_resolution_summary(self) -> str | None:
        if self.match_mapping_attribute == "email":
            return (
                "Any assertion email value exactly matches an account email value"
            )
        if self.match_mapping_attribute == "name":
            return (
                'Any assertion route-scoped exact value exactly matches account '
                'field "username"'
            )
        return None

    @staticmethod
    def account_state(account) -> str:
        value = account.get("enabled")
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized == "enabled":
                return "enabled"
            if normalized == "disabled":
                return "disabled"
        return "unknown"

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
        EdgeDef(
            start=nk.SAML_SERVICE_PROVIDER,
            end=nk.SAML_ACCOUNT_RESOLUTION_RULE,
            kind=ek.SAML_HAS_ACCOUNT_RESOLUTION_RULE,
            description="The Jamf service provider uses this account-resolution rule.",
        ),
        EdgeDef(
            start=nk.ACCOUNT,
            end=nk.SAML_ACCOUNT_RESOLUTION_FIELD,
            kind=ek.SAML_HAS_ACCOUNT_RESOLUTION_VALUE,
            description="A Jamf account supplies an exceptional resolution value.",
        ),
    ],
)
class SAMLServiceProvider(SAMLSSOBase):
    @property
    def as_node(self):
        if not self.service_provider_objectid:
            return None
        properties = SAMLNodeProperties(
            source_object_id=self.service_provider_objectid,
            name=f"Jamf SAML SP {self.tenant_id}",
            displayname=f"Jamf SAML SP {self.tenant_id}",
            environmentid=self.tenant_node_id,
            source_kind="jamf",
            enabled=self.sso_enabled,
            native_object_id=self.native_sso_id,
            native_object_kind=nk.SSO_INTEGRATION,
            sp_entity_id=self.sp_entity_id,
            entity_id=self.sp_entity_id,
            metadata_errors=self.metadata_errors,
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
        if not self.service_provider_node_id:
            return
        for acs in self.acs_services:
            acs_node_id = self.acs_node_id_for(acs.acs_url)
            if not acs_node_id:
                continue
            yield Edge(
                kind=ek.SAML_HAS_ASSERTION_CONSUMER_SERVICE,
                start=EdgePath(match_by="id", value=self.service_provider_node_id),
                end=EdgePath(match_by="id", value=acs_node_id),
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
            email_match_values = (
                [value.casefold() for value in match_values]
                if self.match_mapping_attribute == "email"
                else None
            )
            yield Edge(
                kind=ek.SAML_HAS_ACCOUNT,
                start=EdgePath(match_by="id", value=self.service_provider_node_id),
                end=EdgePath(match_by="id", value=account_node_id),
                properties=SAMLEdgeProperties(
                    match_values=match_values,
                    account_state=self.account_state(account),
                    mapping_attribute=self.match_mapping_attribute,
                    email_match_values=email_match_values,
                ),
            )
            if self.account_resolution_field_node_id:
                yield Edge(
                    kind=ek.SAML_HAS_ACCOUNT_RESOLUTION_VALUE,
                    start=EdgePath(match_by="id", value=account_node_id),
                    end=EdgePath(
                        match_by="id", value=self.account_resolution_field_node_id
                    ),
                    properties=SAMLEdgeProperties(
                        match_values=match_values,
                        canonical_match_values=match_values,
                    ),
                )

    @property
    def _has_account_resolution_rule_edge(self):
        if self.service_provider_node_id and self.account_resolution_rule_node_id:
            yield Edge(
                kind=ek.SAML_HAS_ACCOUNT_RESOLUTION_RULE,
                start=EdgePath(match_by="id", value=self.service_provider_node_id),
                end=EdgePath(match_by="id", value=self.account_resolution_rule_node_id),
                properties=SAMLEdgeProperties(),
            )

    @property
    def edges(self):
        yield from self._implements_edge
        yield from self._trusts_issuer_edge
        yield from self._has_acs_edge
        yield from self._has_account_resolution_rule_edge
        yield from self._has_account_edges


@app.asset(
    description="Normalized Jamf SAML account-resolution rule.",
    node=NodeDef(
        kind=nk.SAML_ACCOUNT_RESOLUTION_RULE,
        description="SAML account-resolution rule node",
        icon="link",
        properties=SAMLNodeProperties,
    ),
    edges=[
        EdgeDef(
            start=nk.SAML_ACCOUNT_RESOLUTION_RULE,
            end=nk.SAML_ACCOUNT_RESOLUTION_FIELD,
            kind=ek.SAML_USES_ACCOUNT_RESOLUTION_FIELD,
            description="The rule reads this exceptional Jamf account field.",
        )
    ],
)
class SAMLAccountResolutionRule(SAMLSSOBase):
    @property
    def as_node(self):
        if (
            not self.account_resolution_rule_objectid
            or not self.account_resolution_expression
            or not self.account_resolution_summary
        ):
            return None
        return SAMLNode(
            kinds=[nk.SAML_ACCOUNT_RESOLUTION_RULE],
            properties=SAMLNodeProperties(
                source_object_id=self.account_resolution_rule_objectid,
                name=f"Jamf {self.match_mapping_attribute} account resolution",
                displayname=f"Jamf {self.match_mapping_attribute} account resolution",
                environmentid=self.tenant_node_id,
                source_kind="jamf",
                native_object_id=self.native_sso_id,
                native_object_kind=nk.SSO_INTEGRATION,
                expression_language="cel",
                expression_profile=ACCOUNT_RESOLUTION_PROFILE,
                expression=self.account_resolution_expression,
                summary=self.account_resolution_summary,
            ),
        )

    @property
    def edges(self):
        if self.account_resolution_field_node_id:
            yield Edge(
                kind=ek.SAML_USES_ACCOUNT_RESOLUTION_FIELD,
                start=EdgePath(
                    match_by="id", value=self.account_resolution_rule_node_id
                ),
                end=EdgePath(
                    match_by="id", value=self.account_resolution_field_node_id
                ),
                properties=SAMLEdgeProperties(),
            )


@app.asset(
    description="Normalized exceptional Jamf SAML account field.",
    node=NodeDef(
        kind=nk.SAML_ACCOUNT_RESOLUTION_FIELD,
        description="SAML account-resolution field node",
        icon="tag",
        properties=SAMLNodeProperties,
    ),
)
class SAMLAccountResolutionField(SAMLSSOBase):
    @property
    def as_node(self):
        if not self.account_resolution_field_objectid:
            return None
        return SAMLNode(
            kinds=[nk.SAML_ACCOUNT_RESOLUTION_FIELD],
            properties=SAMLNodeProperties(
                source_object_id=self.account_resolution_field_objectid,
                name="username",
                displayname="Jamf account username",
                environmentid=self.tenant_node_id,
                source_kind="jamf",
                native_object_id=self.native_sso_id,
                native_object_kind=nk.SSO_INTEGRATION,
            ),
        )

    @property
    def edges(self):
        return []


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
            source_object_id=self.issuer_objectid,
            name=f"Trusted issuer {self.issuer_entity_id}",
            displayname=f"Trusted issuer {self.issuer_entity_id}",
            environmentid=self.tenant_node_id,
            source_kind="jamf",
            entity_id=self.issuer_entity_id,
            issuer=self.issuer_entity_id,
            comparison_mode="exact_trimmed",
            metadata_errors=self.metadata_errors,
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
    saml_acs: ParsedAssertionConsumerService | None = Field(
        alias="samlAcs",
        default=None,
    )

    @property
    def selected_acs(self) -> ParsedAssertionConsumerService | None:
        if self.saml_acs and self.saml_acs.acs_url:
            return self.saml_acs
        return self.acs_services[0] if self.acs_services else None

    @property
    def as_node(self):
        acs = self.selected_acs
        if not acs or not acs.acs_url or not self.sp_entity_id:
            return None
        objectid = self.acs_objectid_for(acs.acs_url)
        if not objectid:
            return None
        properties = SAMLNodeProperties(
            source_object_id=objectid,
            name=f"Jamf ACS {acs.acs_url}",
            displayname=f"Jamf ACS {acs.acs_url}",
            environmentid=self.tenant_node_id,
            source_kind="jamf",
            acs_url=acs.acs_url,
            sp_entity_id=self.sp_entity_id,
            route_key="acs_url + sp_entity_id",
            metadata_errors=self.metadata_errors,
        )
        return SAMLNode(
            kinds=[nk.SAML_ASSERTION_CONSUMER_SERVICE], properties=properties
        )

    @property
    def edges(self):
        return []
