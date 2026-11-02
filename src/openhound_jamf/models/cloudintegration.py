from pydantic import BaseModel, ConfigDict, Field, StrictBool


class CloudIntegration(BaseModel):
    """One Cloud Identity Provider returned by Jamf."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    id: str
    display_name: str = Field(alias="displayName")
    enabled: StrictBool
    provider_name: str = Field(alias="providerName")
    provider_description: str = Field(alias="providerDescription")


class CloudIntegrationResponse(BaseModel):
    """One page returned by GET /api/v1/cloud-idp."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    total_count: int = Field(alias="totalCount", ge=0)
    results: list[CloudIntegration]


class CloudIntegrationSnapshot(BaseModel):
    """Complete collection evidence; never exported as a graph node."""

    total_count: int = Field(ge=0)
    results: list[CloudIntegration]
    cloudintegrationenabled: StrictBool
