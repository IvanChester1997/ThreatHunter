from app.models.evidence import Evidence
from app.models.hunting import HuntingMatch, ThreatHuntingResult
from app.models.investigation import InvestigationCase
from app.models.ioc import IOC
from app.services.ioc_matcher import IOCMatcher
from app.services.mitre_mapper import MITREMapper
from app.services.report_generator import ReportGenerator
from app.services.risk_engine import RiskEngine
from app.services.timeline_builder import TimelineBuilder


class ThreatHuntingService:
    def __init__(
        self,
        matcher: IOCMatcher | None = None,
        timeline_builder: TimelineBuilder | None = None,
        mitre_mapper: MITREMapper | None = None,
        risk_engine: RiskEngine | None = None,
        report_generator: ReportGenerator | None = None,
    ) -> None:
        self.matcher = matcher or IOCMatcher()
        self.timeline_builder = timeline_builder or TimelineBuilder()
        self.mitre_mapper = mitre_mapper or MITREMapper()
        self.risk_engine = risk_engine or RiskEngine()
        self.report_generator = report_generator or ReportGenerator()

    def investigate(
        self,
        case: InvestigationCase,
        iocs: list[IOC],
        evidence: list[Evidence],
    ) -> ThreatHuntingResult:
        ordered_evidence = sorted(
            evidence,
            key=lambda item: (item.collected_at, item.id),
        )

        matches: list[HuntingMatch] = []

        for item in ordered_evidence:
            event = item.model_dump(mode="python")
            evidence_matches = self.matcher.match(iocs, event)

            matches.extend(
                HuntingMatch(
                    evidence_id=item.id,
                    **match.model_dump(),
                )
                for match in evidence_matches
            )

        matched_ioc_ids = {match.ioc_id for match in matches}
        matched_iocs = [
            ioc for ioc in iocs if ioc.id in matched_ioc_ids
        ]

        timeline = self.timeline_builder.build(ordered_evidence)
        mitre_mappings = self.mitre_mapper.map_many(ordered_evidence)
        risk = self.risk_engine.assess(
            case,
            matched_iocs,
            mitre_mappings,
        )
        report = self.report_generator.generate(
            case,
            evidence,
            timeline,
            mitre_mappings,
            risk,
        )

        return ThreatHuntingResult(
            case_id=case.id,
            matches=matches,
            timeline=timeline,
            mitre_mappings=mitre_mappings,
            risk=risk,
            report=report,
        )
