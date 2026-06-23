from openhound.core.asset import BaseAsset
from pydantic import BaseModel, Field

from openhound_jamf.main import app


class BasePolicy(BaseModel):
    id: int


class ScopedComputer(BaseModel):
    id: int


class ExcludedComputer(BaseModel):
    udid: str


class Exclusions(BaseModel):
    computers: list[ExcludedComputer]


class Script(BaseModel):
    id: int | None = None
    name: str | None = None
    priority: str | None = None
    parameter4: str | None = None
    parameter5: str | None = None
    parameter6: str | None = None
    parameter7: str | None = None
    parameter8: str | None = None
    parameter9: str | None = None
    parameter10: str | None = None
    parameter11: str | None = None


class Scope(BaseModel):
    all_computers: bool
    computers: list[ScopedComputer]
    exclusions: Exclusions


@app.asset(
    description="Jamf Policy asset. Returns no graph output directly; policy data feeds recurring-script transforms."
)
class Policy(BaseAsset):
    """JAMF policy fields needed by recurring-script edge transforms."""

    id: int
    enabled: bool
    frequency: str
    scope: Scope
    scripts: list[Script] = Field(default_factory=list)

    @property
    def as_node(self):
        return None

    @property
    def edges(self):
        return []
