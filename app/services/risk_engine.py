from app.models.investigation import InvestigationCase, InvestigationSeverity
from app.models.ioc import IOC
from app.models.mitre import MITREMapping
from app.models.risk import RiskAssessment, RiskLevel


class RiskEngine:
    _SEVERITY_SCORES = {
        InvestigationSeverity.INFO: 10,
        InvestigationSeverity.LOW: 30,
        InvestigationSeverity.MEDIUM: 50,
        InvestigationSeverity.HIGH: 75,
        InvestigationSeverity.CRITICAL: 100,
    }

    def assess(
        self,
        case: InvestigationCase,
        iocs: list[IOC] | None = None,
        mappings: list[MITREMapping] | None = None,
    ) -> RiskAssessment:
        iocs = iocs or []
        mappings = mappings or []

        severity_score = self._SEVERITY_SCORES[case.severity]
        ioc_confidence = max(
            (ioc.confidence for ioc in iocs),
            default=0,
        )
        mitre_confidence = max(
            (mapping.confidence for mapping in mappings),
            default=0,
        )

        score = round(
            severity_score * 0.50
            + ioc_confidence * 0.30
            + mitre_confidence * 0.20
        )
        score = min(100, max(0, score))

        factors = {
            "severity": severity_score,
            "ioc_confidence": ioc_confidence,
            "mitre_confidence": mitre_confidence,
        }

        return RiskAssessment(
            case_id=case.id,
            score=score,
            level=self._level(score),
            factors=factors,
            rationale=(
                "Risk score combines investigation severity (50%), "
                "highest IOC confidence (30%), and highest MITRE "
                "mapping confidence (20%)."
            ),
        )

    @staticmethod
    def _level(score: int) -> RiskLevel:
        if score >= 75:
            return RiskLevel.CRITICAL
        if score >= 50:
            return RiskLevel.HIGH
        if score >= 25:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW
