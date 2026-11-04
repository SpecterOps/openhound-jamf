import logging
import math
import re
from datetime import UTC, datetime
from uuid import UUID

from openhound.core.asset import EdgeDef, NodeDef
from openhound.core.models.entries import Node as PydanticNode
from openhound.core.models.entries import NodeProperties as PydanticProperties
from openhound.core.models.entries_dataclass import (
    ConditionalEdgePath,
    Edge,
    EdgePath,
    EdgeProperties,
    PropertyMatch,
)
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    computed_field,
    model_serializer,
    model_validator,
)

from openhound_jamf.graph import JAMFAsset, JAMFNode
from openhound_jamf.kinds import edges as ek
from openhound_jamf.kinds import nodes as nk
from openhound_jamf.main import app

logger = logging.getLogger(__name__)


class CloudIntegration(BaseModel):
    """One Cloud Identity Provider returned by Jamf."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    id: str
    display_name: str = Field(alias="displayName")
    enabled: StrictBool
    provider_name: str = Field(alias="providerName")
    provider_description: str = Field(alias="providerDescription")


class CloudIntegrationResponse(BaseModel):
    """One page returned by GET /api/v1/cloud-idp."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    total_count: int = Field(alias="totalCount", ge=0)
    results: list[CloudIntegration]


class CloudIntegrationSnapshot(BaseModel):
    """Complete collection evidence; never exported as a graph node."""

    total_count: int = Field(ge=0)
    results: list[CloudIntegration]
    cloudintegrationenabled: StrictBool


class AzureConfigurationModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")


class AzureCommonConfiguration(AzureConfigurationModel):
    id: str
    display_name: str = Field(alias="displayName")
    provider_name: str = Field(alias="providerName")


class AzureMappings(AzureConfigurationModel):
    user_id: str | None = Field(default=None, alias="userId")
    user_name: str | None = Field(default=None, alias="userName")
    real_name: str | None = Field(default=None, alias="realName")
    email: str | None = None
    department: str | None = None
    building: str | None = None
    room: str | None = None
    phone: str | None = None
    position: str | None = None
    group_id: str | None = Field(default=None, alias="groupId")
    group_name: str | None = Field(default=None, alias="groupName")


class AzureSCIMSettings(AzureConfigurationModel):
    username_change_enabled: StrictBool | None = Field(
        default=None, alias="usernameChangeEnabled"
    )
    group_name_change_enabled: StrictBool | None = Field(
        default=None, alias="groupNameChangeEnabled"
    )


class AzureServerConfiguration(AzureConfigurationModel):
    id: str
    tenant_id: str = Field(alias="tenantId")
    enabled: StrictBool
    migrated: StrictBool | None = None
    type: str | None = None
    mappings: AzureMappings | None = None
    search_timeout: StrictInt | None = Field(default=None, alias="searchTimeout")
    transitive_membership_enabled: StrictBool | None = Field(
        default=None, alias="transitiveMembershipEnabled"
    )
    transitive_membership_user_field: str | None = Field(
        default=None, alias="transitiveMembershipUserField"
    )
    transitive_directory_membership_enabled: StrictBool | None = Field(
        default=None, alias="transitiveDirectoryMembershipEnabled"
    )
    membership_calculation_optimization_enabled: StrictBool | None = Field(
        default=None, alias="membershipCalculationOptimizationEnabled"
    )
    deprecated_consent: StrictBool | None = Field(
        default=None, alias="deprecatedConsent"
    )
    scim_support_settings: AzureSCIMSettings | None = Field(
        default=None, alias="scimSupportSettings"
    )


def _primitive_property(value):
    if type(value) in (str, bool, int):
        return True
    if type(value) is float:
        return math.isfinite(value)
    if isinstance(value, list):
        return any(
            all(type(item) in types and _primitive_property(item) for item in value)
            for types in ((str,), (bool,), (int, float))
        )
    return False


def flatten_cloud_properties(payload: dict) -> dict:
    """Preserve non-null leaves under unambiguous lowercase property paths."""
    result = {}

    def visit(value, path):
        if isinstance(value, dict):
            for key, child in value.items():
                key = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", key)
                key = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key)
                key = re.sub(r"[^a-zA-Z0-9_]", "_", key).lower()
                visit(child, (*path, key))
        elif value is not None:
            key = "_".join(path)
            if not key or key == "objectid" or key in result:
                raise ValueError("Cloud property paths collide or use a reserved name")
            if not _primitive_property(value):
                raise ValueError(f"Unsupported OpenGraph property type at {key}")
            result[key] = value

    visit(payload, ())
    return result


class AzureCloudConfiguration(AzureConfigurationModel):
    cloud_idp_common: AzureCommonConfiguration = Field(alias="cloudIdPCommon")
    server: AzureServerConfiguration

    @model_validator(mode="after")
    def valid_azure_configuration(self):
        if self.cloud_idp_common.provider_name != "AZURE":
            raise ValueError("Cloud configuration is not an Azure provider")
        if self.cloud_idp_common.id != self.server.id:
            raise ValueError("Cloud common and server IDs disagree")
        flatten_cloud_properties(self.model_dump(mode="json", exclude_none=True))
        return self


class CloudIntegrationProperties(PydanticProperties):
    id: str
    tenant: str
    tier: int = 0
    collected: bool = True
    display_name: str
    enabled: StrictBool
    provider_name: str
    provider_description: str
    details_collected: bool
    details_error: str | None = None

    @model_validator(mode="after")
    def valid_extra_properties(self):
        for key, value in (self.__pydantic_extra__ or {}).items():
            if key == "objectid" or (
                value is not None and not _primitive_property(value)
            ):
                raise ValueError(f"Invalid OpenGraph property: {key}")
        return self

    @model_serializer(mode="wrap")
    def omit_null_properties(self, handler):
        return {key: value for key, value in handler(self).items() if value is not None}


class CloudIntegrationNode(PydanticNode):
    graph_id: str = Field(exclude=True)
    properties: CloudIntegrationProperties

    @classmethod
    def guid(cls, name, node_type, *args):
        return JAMFNode.guid(name, node_type, *args)

    @computed_field
    @property
    def id(self) -> str:
        return self.graph_id


@app.asset(
    node=NodeDef(
        kind=nk.CLOUD_INTEGRATION,
        description="Azure Cloud Identity Provider configuration collected from Jamf Pro.",
        icon="cloud-arrow-up",
        color="#0078D4",
        properties=CloudIntegrationProperties,
    ),
    edges=[
        EdgeDef(
            start=nk.TENANT,
            end=nk.CLOUD_INTEGRATION,
            kind=ek.CLOUD_INTEGRATION_LINK,
            description="The Jamf Pro tenant contains this cloud integration configuration.",
            traversable=False,
        ),
        EdgeDef(
            start=nk.CLOUD_INTEGRATION,
            end="AZTenant",
            kind=ek.CLOUD_INTEGRATION_LINK,
            description="The cloud integration configuration references this Azure tenant.",
            traversable=False,
        ),
    ],
)
class CloudIntegrationAsset(JAMFAsset):
    """Persist the collection-time identity and both API response representations."""

    summary: CloudIntegration
    details: AzureCloudConfiguration | None = None
    graph_id: str
    tenant: str
    details_error: str | None = None
    collected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="after")
    def consistent_identity(self):
        if self.summary.provider_name != "AZURE":
            raise ValueError("Only Azure cloud integration nodes are supported")
        expected = JAMFNode.guid(self.summary.id, nk.CLOUD_INTEGRATION, self.tenant)
        if self.graph_id != expected:
            raise ValueError(
                "Cloud integration graph ID does not match its source identity"
            )
        if (
            self.details is not None
            and self.details.cloud_idp_common.id != self.summary.id
        ):
            raise ValueError("Cloud integration summary and detail IDs disagree")
        if self.details is not None:
            detailed = flatten_cloud_properties(
                self.details.model_dump(mode="json", exclude_none=True)
            )
            if self.summary.model_dump().keys() & detailed.keys():
                raise ValueError(
                    "Cloud integration summary and detail property paths collide"
                )
        return self

    @property
    def as_node(self):
        properties = self.summary.model_dump(mode="json")
        if self.details is not None:
            detailed = flatten_cloud_properties(
                self.details.model_dump(mode="json", exclude_none=True)
            )
            if properties.keys() & detailed.keys():
                raise ValueError(
                    "Cloud integration summary and detail property paths collide"
                )
            properties.update(detailed)
        return CloudIntegrationNode(
            graph_id=self.graph_id,
            kinds=[nk.CLOUD_INTEGRATION],
            properties=CloudIntegrationProperties(
                **properties,
                name=self.summary.display_name.upper(),
                displayname=self.summary.display_name,
                tenant=self.tenant,
                environmentid=JAMFNode.guid(self.tenant, nk.TENANT, self.tenant),
                last_seen=self.collected_at,
                details_collected=self.details is not None,
                details_error=self.details_error,
            ),
        )

    @property
    def edges(self):
        edges = [
            Edge(
                kind=ek.CLOUD_INTEGRATION_LINK,
                start=EdgePath(
                    match_by="id",
                    value=JAMFNode.guid(self.tenant, nk.TENANT, self.tenant),
                ),
                end=EdgePath(match_by="id", value=self.graph_id),
                properties=EdgeProperties(traversable=False),
            )
        ]
        if self.details is None:
            logger.warning(
                "Skipping Azure tenant link for cloud integration %s: details unavailable",
                self.summary.id,
            )
            return edges
        try:
            azure_tenant_id = str(UUID(self.details.server.tenant_id)).upper()
        except ValueError:
            logger.warning(
                "Skipping Azure tenant link for cloud integration %s: invalid tenant UUID",
                self.summary.id,
            )
            return edges
        edges.append(
            Edge(
                kind=ek.CLOUD_INTEGRATION_LINK,
                start=EdgePath(match_by="id", value=self.graph_id),
                end=ConditionalEdgePath(
                    kind="AZTenant",
                    property_matchers=[
                        PropertyMatch(key="objectid", value=azure_tenant_id)
                    ],
                ),
                properties=EdgeProperties(traversable=False),
            )
        )
        return edges
