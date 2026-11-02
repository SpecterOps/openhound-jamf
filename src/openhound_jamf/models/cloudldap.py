from datetime import UTC, datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class LDAPServer(BaseModel):
    """An account or group's configured directory association, not a graph node."""

    id: str
    name: str = ""

    @field_validator("id", mode="before")
    @classmethod
    def normalize_id(cls, value):
        return str(value) if isinstance(value, int) else value


class CloudUserResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    uuid: UUID
    id: UUID | None = None
    server_id: str = Field(alias="serverId")
    name: str = ""
    distinguished_name: str = Field(default="", alias="distinguishedName")
    attributes: dict[str, Any] = Field(default_factory=dict)

    @field_validator("server_id", mode="before")
    @classmethod
    def normalize_server_id(cls, value):
        return str(value) if isinstance(value, int) else value

    @model_validator(mode="after")
    def consistent_identity(self):
        if self.id is not None and self.id != self.uuid:
            raise ValueError("Cloud directory id and uuid disagree")
        return self


class CloudUserResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    total_count: int = Field(alias="totalCount", ge=0)
    results: list[CloudUserResult]

    @model_validator(mode="after")
    def complete_results(self):
        if self.total_count != len(self.results):
            raise ValueError("Cloud directory search returned an incomplete result set")
        return self


class CloudUserTest(BaseModel):
    """Collected search evidence; never exported as graph properties."""

    provider_id: str
    provider_name: str
    requested_username: str
    status: Literal["success", "error", "unsupported"]
    total_count: int = Field(default=0, ge=0)
    results: list[CloudUserResult] = Field(default_factory=list)
    error: str = ""
    collected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


def normalize_ldap_servers(value):
    if value is None or value == {}:
        return []
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [entry for entry in value if entry is not None and entry != {}]
    return value


def matched_cloud_users(test: CloudUserTest, email: str) -> list[tuple[str, str]]:
    """Resolve complete, provider-bound evidence without guessing between users."""
    if test.status != "success" or test.provider_name != "AZURE":
        return []
    if test.total_count != len(test.results):
        return []
    if any(result.server_id != test.provider_id for result in test.results):
        return []
    if len(test.results) == 1:
        return [(str(test.results[0].uuid).upper(), "single_result")]

    normalized_email = email.strip().casefold()
    if not normalized_email:
        return []
    matches = set()
    for result in test.results:
        # Explicit email fields only; other attributes are not identity evidence.
        for key in ("emailAddress", "email", "mail", "email_address"):
            value = result.attributes.get(key)
            if isinstance(value, str) and value.strip().casefold() == normalized_email:
                matches.add((str(result.uuid).upper(), "email"))
    return sorted(matches)
