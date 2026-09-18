from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.evidence import Evidence
from app.models.mitre import MITREMapping
from app.models.timeline import TimelineEvent


class InvestigationReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str
    title: str
    generated_at: datetime
    status: str
    severity: str
    risk_score: int = Field(ge=0, le=100)
    risk_level: str
    summary: str = Field(min_length=1)
    evidence: list[Evidence]
    timeline: list[TimelineEvent]
    mitre_mappings: list[MITREMapping]
