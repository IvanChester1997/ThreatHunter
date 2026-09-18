from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.evidence import EvidenceType


class TimelineEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    case_id: str = Field(min_length=1)
    timestamp: datetime
    event_type: EvidenceType
    source: str = Field(min_length=1)
    description: str = Field(min_length=1)
    evidence_id: str = Field(min_length=1)
