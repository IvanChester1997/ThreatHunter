from pydantic import BaseModel, ConfigDict

from app.models.mitre import MITREMapping
from app.models.report import InvestigationReport
from app.models.risk import RiskAssessment
from app.models.timeline import TimelineEvent
from app.services.ioc_matcher import IOCMatch


class HuntingMatch(IOCMatch):
    evidence_id: str


class ThreatHuntingResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str
    matches: list[HuntingMatch]
    timeline: list[TimelineEvent]
    mitre_mappings: list[MITREMapping]
    risk: RiskAssessment
    report: InvestigationReport
