from dataclasses import dataclass

from openhound.core.asset import NodeDef

from openhound_jamf.graph import JAMFAsset, JAMFNode, JAMFNodeProperties
from openhound_jamf.kinds import nodes as nk
from openhound_jamf.main import app


@dataclass
class TenantProperties(JAMFNodeProperties):
    """JAMF Tenant node properties"""

    collected: bool = True


@app.asset(
    description="Jamf Tenant asset. Returns a node representing a Jamf Tenant with no edges.",
    node=NodeDef(
        kind=nk.TENANT,
        description="Jamf Tenant node",
        icon="building",
        properties=TenantProperties,
    ),
)
class Tenant(JAMFAsset):
    id: str
    name: str

    @property
    def as_node(self):
        """Return the OpenGraph node representation for this resource."""
        properties = TenantProperties(
            id=self.id,
            name=self.name,
            displayname=self.name,
            tenant=self.id,
            tier=0,
            environmentid=self.tenant_node_id,
        )
        return JAMFNode(kinds=[nk.TENANT], properties=properties)

    @property
    def edges(self):
        return []
