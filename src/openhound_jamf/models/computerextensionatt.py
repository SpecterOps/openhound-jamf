from pydantic import BaseModel


class ComputerextensionAttribute(BaseModel):
    id: int
    name: str | None = None
    enabled: bool | None = None
