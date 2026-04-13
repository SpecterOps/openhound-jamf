from openhound.core.asset import BaseAsset
from pydantic import ConfigDict, Field

from openhound_jamf.main import app


@app.asset(
    description="Jamf API Role asset. Returns a node representing a Jamf API Role with edges to its tenant."
)
class ApiRole(BaseAsset):
    """JAMF API role resource parsed into a Pydantic model.

    Parses the raw JAMF API role payload and exposes OpenGraph Node and Edges via
    the `as_node` and `edges` properties.

    Args:
        BaseAsset (BaseAsset): Base class providing OpenGraph node/edge exports.
    """

    model_config = ConfigDict(populate_by_name=True)

    id: int
    display_name: str = Field(alias="displayName")
    privileges: list[str]

    @property
    def as_node(self):
        return None

    @property
    def edges(self):
        return []
