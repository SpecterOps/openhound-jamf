from dataclasses import dataclass, field

from openhound.core.asset import BaseAsset
from openhound.core.models.entries_dataclass import (
    EdgeProperties,
    Node as BaseNode,
)
from openhound.core.models.entries_dataclass import (
    NodeProperties as BaseProperties,
)

from openhound_jamf.kinds.nodes import TENANT


@dataclass
class JAMFNodeProperties(BaseProperties):
    tenant: str
    id: int | str
    tier: int
    environmentid: str

    def __post_init__(self):
        self.name = self.name.upper()


@dataclass
class JAMFAssignedUserEdgeProperties(EdgeProperties):
    """Evidence describing how a computer-to-user assignment was resolved.

    Attributes:
        match_type: ``hard`` for a native Jamf user/computer link or
            ``soft_legacy`` for a USER_AND_LOCATION inference.
        confidence: Human-readable confidence level for the relationship.
        evidence_source: Jamf API field or resource that supplied the evidence.
        match_basis: Native ID, email, username, or synthetic inventory identity.
        reason: Operator-facing explanation shown with the edge in BloodHound.
    """

    match_type: str = "hard"
    confidence: str = "high"
    evidence_source: str = "jamf_user_links_computers"
    match_basis: str = "jamf_native_id"
    reason: str | None = None


@dataclass
class JAMFNode(BaseNode):
    properties: JAMFNodeProperties  # pyright: ignore[reportIncompatibleVariableOverride]
    id: str = field(init=False)

    @staticmethod
    def guid(
        id: str,
        node_type: str,
        tenant: str,
    ) -> str:
        return BaseNode.guid(id, node_type, tenant).upper()

    def __post_init__(self):
        self.id = self.guid(
            str(self.properties.id), self.kinds[0], self.properties.tenant
        )


class JAMFAsset(BaseAsset):
    @property
    def tenant_id(self) -> str:
        return self._lookup.tenant_id()

    @property
    def tenant_node_id(self) -> str:
        return JAMFNode.guid(self.tenant_id, TENANT, self.tenant_id)
