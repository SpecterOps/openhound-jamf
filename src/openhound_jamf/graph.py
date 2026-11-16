from dataclasses import dataclass, field

from openhound.core.asset import BaseAsset
from openhound.core.models.entries_dataclass import (
    Node as BaseNode,
)
from openhound.core.models.entries_dataclass import (
    NodeProperties as BaseProperties,
)

from openhound_jamf.kinds.nodes import TENANT

# Kind that every native Jamf node carries. The app does not set `source_kind`,
# because OpenHound would also add it to the SAML nodes, which carry only the
# kinds of the producer library.
JAMF_SOURCE_KIND = "jamf"


@dataclass
class JAMFNodeProperties(BaseProperties):
    tenant: str
    id: int
    tier: int
    environmentid: str

    def __post_init__(self):
        self.name = self.name.upper()


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
        if JAMF_SOURCE_KIND not in self.kinds:
            self.kinds.append(JAMF_SOURCE_KIND)


class JAMFAsset(BaseAsset):
    @property
    def tenant_id(self) -> str:
        return self._lookup.tenant_id()

    @property
    def tenant_node_id(self) -> str:
        return JAMFNode.guid(self.tenant_id, TENANT, self.tenant_id)
