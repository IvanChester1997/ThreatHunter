from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str
    score: int = Field(ge=0, le=100)
    level: RiskLevel
    factors: dict[str, int]
    rationale: str = Field(min_length=1)
