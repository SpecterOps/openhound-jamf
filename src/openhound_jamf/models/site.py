from dataclasses import dataclass

from openhound.core.asset import EdgeDef, NodeDef
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties

from openhound_jamf.graph import JAMFAsset, JAMFNode, JAMFNodeProperties
from openhound_jamf.kinds import edges as ek
from openhound_jamf.kinds import nodes as nk
from openhound_jamf.main import app


@dataclass
class SiteProperties(JAMFNodeProperties):
    """JAMF Site node properties"""

    pass


@app.asset(
    description="Jamf Site asset. Returns a node representing a Jamf Site and edges to its tenant.",
    node=NodeDef(
        kind=nk.SITE,
        description="Jamf Site node",
        icon="map-location",
        properties=SiteProperties,
    ),
    edges=[
        EdgeDef(
            start=nk.TENANT,
            end=nk.SITE,
            kind=ek.CONTAINS,
            description="Something something",
        ),
    ],
)
class Site(JAMFAsset):
    id: int
    name: str

    @property
    def as_node(self):
        properties = SiteProperties(
            id=self.id,
            name=self.name,
            displayname=self.name,
            tenant=self.tenant_id,
            tier=1,
            environmentid=self.tenant_node_id,
        )
        return JAMFNode(kinds=[nk.SITE], properties=properties)

    @property
    def _node_id(self) -> str:
        return self.as_node.id

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
        yield from self._contains_edge
