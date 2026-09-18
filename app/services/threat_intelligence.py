from pydantic import BaseModel, ConfigDict

from app.models.ioc import IOC, IOCType


class ThreatLevel(str):
    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatIntelResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ioc_id: str
    ioc_type: IOCType
    value: str
    source: str
    confidence: int
    threat_level: str


class ThreatIntelligenceEngine:
    def analyze(self, ioc: IOC) -> ThreatIntelResult:
        return ThreatIntelResult(
            ioc_id=ioc.id,
            ioc_type=ioc.type,
            value=ioc.value,
            source=ioc.source,
            confidence=ioc.confidence,
            threat_level=self._threat_level(ioc.confidence),
        )

    @staticmethod
    def _threat_level(confidence: int) -> str:
        if confidence >= 90:
            return ThreatLevel.CRITICAL
        if confidence >= 75:
            return ThreatLevel.HIGH
        if confidence >= 50:
            return ThreatLevel.MEDIUM
        if confidence >= 25:
            return ThreatLevel.LOW
        return ThreatLevel.UNKNOWN
