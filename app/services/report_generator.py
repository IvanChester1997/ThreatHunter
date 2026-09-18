from datetime import UTC, datetime

from app.models.evidence import Evidence
from app.models.investigation import InvestigationCase
from app.models.mitre import MITREMapping
from app.models.report import InvestigationReport
from app.models.risk import RiskAssessment
from app.models.timeline import TimelineEvent


class ReportGenerator:
    def generate(
        self,
        case: InvestigationCase,
        evidence: list[Evidence],
        timeline: list[TimelineEvent],
        mappings: list[MITREMapping],
        risk: RiskAssessment,
        generated_at: datetime | None = None,
    ) -> InvestigationReport:
        self._validate_case_links(case, evidence, timeline, risk)

        return InvestigationReport(
            case_id=case.id,
            title=case.title,
            generated_at=generated_at or datetime.now(UTC),
            status=case.status,
            severity=case.severity,
            risk_score=risk.score,
            risk_level=risk.level,
            summary=(
                f"Investigation {case.id} ({case.title}) is "
                f"{case.status} with {risk.level} risk "
                f"(score {risk.score}/100). "
                f"{len(evidence)} evidence item(s) and "
                f"{len(mappings)} MITRE mapping(s) are associated "
                "with the investigation."
            ),
            evidence=list(evidence),
            timeline=list(timeline),
            mitre_mappings=list(mappings),
        )

    @staticmethod
    def render_markdown(report: InvestigationReport) -> str:
        lines = [
            f"# Investigation Report: {report.case_id}",
            "",
            f"**Title:** {report.title}",
            f"**Status:** {report.status}",
            f"**Severity:** {report.severity}",
            f"**Risk:** {report.risk_level} ({report.risk_score}/100)",
            f"**Generated:** {report.generated_at.isoformat()}",
            "",
            "## Summary",
            "",
            report.summary,
            "",
            "## Evidence",
            "",
        ]

        if report.evidence:
            for item in report.evidence:
                lines.append(
                    f"- `{item.id}` [{item.type}] "
                    f"{item.source}: {item.description or item.value}"
                )
        else:
            lines.append("No evidence collected.")

        lines.extend(["", "## Timeline", ""])

        if report.timeline:
            for event in report.timeline:
                lines.append(
                    f"- `{event.timestamp.isoformat()}` "
                    f"`{event.event_type}` "
                    f"({event.evidence_id}) "
                    f"{event.description}"
                )
        else:
            lines.append("No timeline events.")

        lines.extend(["", "## MITRE ATT&CK", ""])

        if report.mitre_mappings:
            for mapping in report.mitre_mappings:
                lines.append(
                    f"- `{mapping.technique.id}` "
                    f"{mapping.technique.name} — "
                    f"confidence {mapping.confidence}: "
                    f"{mapping.rationale}"
                )
        else:
            lines.append("No MITRE mappings.")

        return "\n".join(lines)

    @staticmethod
    def _validate_case_links(
        case: InvestigationCase,
        evidence: list[Evidence],
        timeline: list[TimelineEvent],
        risk: RiskAssessment,
    ) -> None:
        if risk.case_id != case.id:
            raise ValueError("Risk assessment belongs to another case")

        if any(item.case_id != case.id for item in evidence):
            raise ValueError("Evidence belongs to another case")

        if any(item.case_id != case.id for item in timeline):
            raise ValueError("Timeline event belongs to another case")
