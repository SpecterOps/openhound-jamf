from pydantic import BaseModel


class ComputerextensionAttribute(BaseModel):
    id: int
    name: str
    enabled: bool
