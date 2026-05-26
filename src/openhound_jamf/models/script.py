from enum import Enum
from typing import Any

from openhound.core.asset import BaseAsset
from pydantic import BaseModel, Field

from openhound_jamf.main import app


class Priority(Enum):
    Before = "Before"
    After = "After"
    During = "During"


class BaseScript(BaseModel):
    id: int
    name: str | None = None


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
    category: str | None = None
    filename: str | None = None
    info: str | None = None
    notes: str | None = None
    priority: Priority | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    os_requirements: str | None = None
    script_contents_encoded: str | None = None

    @property
    def as_node(self):
        return None

    @property
    def edges(self):
        return []
