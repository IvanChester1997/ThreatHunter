from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class EvidenceType(StrEnum):
    LOG = "log"
    FILE = "file"
    NETWORK = "network"
    PROCESS = "process"
    AUTHENTICATION = "authentication"
    COMMAND = "command"
    OTHER = "other"


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    case_id: str = Field(min_length=1)
    type: EvidenceType
    source: str = Field(min_length=1)
    value: str = Field(min_length=1)
    description: str = ""
    collected_at: datetime
