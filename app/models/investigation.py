from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class InvestigationStatus(StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"


class InvestigationSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class InvestigationCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    title: str = Field(min_length=1)
    description: str = ""
    status: InvestigationStatus = InvestigationStatus.OPEN
    severity: InvestigationSeverity = InvestigationSeverity.MEDIUM
    risk_score: int = Field(default=0, ge=0, le=100)
    ioc_ids: list[str] = Field(default_factory=list)
    match_ids: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime
