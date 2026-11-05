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
        """Convert integer LDAP server IDs to strings before field validation."""
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
        """Convert integer provider IDs to strings before field validation."""
        return str(value) if isinstance(value, int) else value

    @model_validator(mode="after")
    def consistent_identity(self):
        """Require a returned user ID to match its UUID when both are present.

        Return this result, or raise ValueError when the two identifiers disagree.
        """
        if self.id is not None and self.id != self.uuid:
            raise ValueError("Cloud directory id and uuid disagree")
        return self


class CloudUserResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    total_count: int = Field(alias="totalCount", ge=0)
    results: list[CloudUserResult]

    @model_validator(mode="after")
    def complete_results(self):
        """Require the reported user count to match the returned result count.

        Return this response, or raise ValueError for incomplete or inconsistent
        search results so they cannot be used as identity-matching evidence.
        """
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


class CloudGroupResult(BaseModel):
    """An Azure group resolved by a Cloud Identity Provider test search."""

    model_config = ConfigDict(populate_by_name=True)

    uuid: UUID
    id: str | None = None
    server_id: str = Field(alias="serverId")
    name: str
    distinguished_name: str = Field(default="", alias="distinguishedName")

    @field_validator("id", "server_id", mode="before")
    @classmethod
    def normalize_id(cls, value):
        """Convert integer group and provider IDs to strings before field validation."""
        return str(value) if isinstance(value, int) else value

    @model_validator(mode="after")
    def consistent_identity(self):
        # Jamf's generic id can be a group name; uuid identifies the Azure object.
        """Validate UUID-shaped group IDs against the returned UUID.

        Allow non-UUID generic IDs because Jamf may return the group name in id.
        Raise ValueError when a UUID-shaped ID conflicts with the group's UUID.
        """
        if self.id is not None:
            try:
                object_id = UUID(self.id)
            except ValueError:
                return self
            if object_id != self.uuid:
                raise ValueError("Cloud directory group id and uuid disagree")
        return self


class CloudGroupResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    total_count: int = Field(alias="totalCount", ge=0)
    results: list[CloudGroupResult]

    @model_validator(mode="after")
    def complete_results(self):
        """Require the reported group count to match the returned result count.

        Return this response, or raise ValueError for incomplete or inconsistent
        search results so they cannot be used as group-matching evidence.
        """
        if self.total_count != len(self.results):
            raise ValueError(
                "Cloud directory group search returned an incomplete result set"
            )
        return self


class CloudGroupTest(BaseModel):
    """Collected group search evidence; never exported as graph properties."""

    provider_id: str
    provider_name: str
    requested_groupname: str
    status: Literal["success", "error", "unsupported"]
    total_count: int = Field(default=0, ge=0)
    results: list[CloudGroupResult] = Field(default_factory=list)
    error: str = ""
    collected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


def normalize_ldap_servers(value):
    """Normalize the API's missing, single, or multiple LDAP server associations.

    Return an empty list for null or empty-object input, wrap a single object
    in a list, and remove null or empty-object entries from lists. Leave other
    input types unchanged so model validation can reject malformed values.
    """
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


def matched_cloud_groups(test: CloudGroupTest, name: str) -> list[tuple[str, str]]:
    """Resolve complete group evidence, requiring matching names for ambiguity."""
    if test.status != "success" or test.provider_name != "AZURE":
        return []
    if test.total_count != len(test.results):
        return []
    if any(result.server_id != test.provider_id for result in test.results):
        return []
    if len(test.results) == 1:
        return [(str(test.results[0].uuid).upper(), "single_result")]
    normalized_name = name.strip().casefold()
    if not normalized_name:
        return []
    return sorted(
        {
            (str(result.uuid).upper(), "name")
            for result in test.results
            if result.name.strip().casefold() == normalized_name
        }
    )
