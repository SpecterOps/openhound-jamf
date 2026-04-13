from dataclasses import dataclass, field

from openhound.core.asset import BaseAsset
from openhound.core.models.entries_dataclass import (
    Node as BaseNode,
)
from openhound.core.models.entries_dataclass import (
    NodeProperties as BaseProperties,
)

from openhound_jamf.kinds.nodes import TENANT


@dataclass
class JAMFNodeProperties(BaseProperties):
    tenant: str
    id: int
    tier: int
    environmentid: str


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
        return BaseNode.guid(id, node_type, tenant)

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
