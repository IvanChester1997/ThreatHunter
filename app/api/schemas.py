from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.evidence import EvidenceType
from app.models.investigation import InvestigationSeverity, InvestigationStatus
from app.models.ioc import IOCType


class IOCCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    type: IOCType
    value: str
    source: str = Field(min_length=1)
    confidence: int = Field(ge=0, le=100)


class InvestigationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    description: str = ""
    status: InvestigationStatus = InvestigationStatus.OPEN
    severity: InvestigationSeverity = InvestigationSeverity.MEDIUM
    risk_score: int = Field(default=0, ge=0, le=100)


class StatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: InvestigationStatus


class SeverityUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    severity: InvestigationSeverity


class RiskUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    risk_score: int = Field(ge=0, le=100)


class EvidenceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    case_id: str = Field(min_length=1)
    type: EvidenceType
    source: str = Field(min_length=1)
    value: str = Field(min_length=1)
    description: str = ""
    collected_at: datetime | None = None
