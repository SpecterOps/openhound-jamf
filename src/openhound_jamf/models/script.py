from enum import Enum
from typing import Any

from openhound.core.asset import BaseAsset
from pydantic import BaseModel

from openhound_jamf.main import app


class Priority(Enum):
    Before = "Before"
    After = "After"
    During = "During"


class BaseScript(BaseModel):
    id: int
    name: str


@app.asset(
    description="Jamf Script asset. Returns a node representing a Jamf Script and edges to its tenant."
)
class Script(BaseAsset):
    """JAMF script resource parsed into a Pydantic model.

    Parses the raw JAMF script payload and exposes OpenGraph Node and Edges via
    the `as_node` and `edges` properties.

    Args:
        BaseAsset (BaseAsset): Base class providing OpenGraph node/edge exports.
    """

    id: int
    name: str
    category: str
    filename: str
    info: str
    notes: str
    priority: Priority
    parameters: dict[str, Any]
    os_requirements: str
    script_contents_encoded: str

    @property
    def as_node(self):
        return None

    @property
    def edges(self):
        return []
