from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.models.evidence import Evidence, EvidenceType
from app.models.investigation import (
    InvestigationCase,
    InvestigationSeverity,
    InvestigationStatus,
)
from app.models.mitre import MITREMapping, MITRETactic, MITRETechnique
from app.models.report import InvestigationReport
from app.models.risk import RiskAssessment, RiskLevel
from app.models.timeline import TimelineEvent
from app.services.report_generator import ReportGenerator

GENERATED_AT = datetime(2026, 9, 18, 12, 0, tzinfo=UTC)
EVENT_TIME = datetime(2026, 9, 18, 11, 0, tzinfo=UTC)


def make_case() -> InvestigationCase:
    return InvestigationCase(
        id="CASE-000001",
        title="SSH brute force investigation",
        description="Suspicious authentication activity",
        status=InvestigationStatus.IN_PROGRESS,
        severity=InvestigationSeverity.HIGH,
        risk_score=80,
        created_at=EVENT_TIME,
        updated_at=GENERATED_AT,
    )


def make_evidence(
    evidence_id: str = "EVD-000001",
    case_id: str = "CASE-000001",
) -> Evidence:
    return Evidence(
        id=evidence_id,
        case_id=case_id,
        type=EvidenceType.LOG,
        source="/var/log/auth.log",
        value="Failed password for root",
        description="SSH brute force detected",
        collected_at=EVENT_TIME,
    )


def make_timeline(
    evidence_id: str = "EVD-000001",
    case_id: str = "CASE-000001",
) -> TimelineEvent:
    return TimelineEvent(
        id=f"TL-{evidence_id}",
        case_id=case_id,
        timestamp=EVENT_TIME,
        event_type=EvidenceType.LOG,
        source="/var/log/auth.log",
        description="SSH brute force detected",
        evidence_id=evidence_id,
    )


def make_mapping(
    evidence_id: str = "EVD-000001",
) -> MITREMapping:
    return MITREMapping(
        evidence_id=evidence_id,
        technique=MITRETechnique(
            id="T1110",
            name="Brute Force",
            tactic=MITRETactic.CREDENTIAL_ACCESS,
        ),
        confidence=90,
        rationale="Authentication attack evidence",
    )


def make_risk(
    case_id: str = "CASE-000001",
) -> RiskAssessment:
    return RiskAssessment(
        case_id=case_id,
        score=80,
        level=RiskLevel.CRITICAL,
        factors={
            "severity": 75,
            "ioc_confidence": 80,
            "mitre_confidence": 90,
        },
        rationale="Deterministic risk assessment",
    )


def test_generate_preserves_case_context() -> None:
    generator = ReportGenerator()

    report = generator.generate(
        make_case(),
        [make_evidence()],
        [make_timeline()],
        [make_mapping()],
        make_risk(),
        generated_at=GENERATED_AT,
    )

    assert report.case_id == "CASE-000001"
    assert report.title == "SSH brute force investigation"
    assert report.status == "in_progress"
    assert report.severity == "high"
    assert report.risk_score == 80
    assert report.risk_level == "critical"
    assert report.generated_at == GENERATED_AT


def test_generate_includes_all_report_sections() -> None:
    generator = ReportGenerator()
    evidence = [make_evidence()]
    timeline = [make_timeline()]
    mappings = [make_mapping()]

    report = generator.generate(
        make_case(),
        evidence,
        timeline,
        mappings,
        make_risk(),
        generated_at=GENERATED_AT,
    )

    assert report.evidence == evidence
    assert report.timeline == timeline
    assert report.mitre_mappings == mappings


def test_summary_contains_key_investigation_facts() -> None:
    report = ReportGenerator().generate(
        make_case(),
        [make_evidence()],
        [make_timeline()],
        [make_mapping()],
        make_risk(),
        generated_at=GENERATED_AT,
    )

    assert "CASE-000001" in report.summary
    assert "critical risk" in report.summary
    assert "score 80/100" in report.summary
    assert "1 evidence item(s)" in report.summary
    assert "1 MITRE mapping(s)" in report.summary


def test_markdown_contains_all_sections() -> None:
    generator = ReportGenerator()
    report = generator.generate(
        make_case(),
        [make_evidence()],
        [make_timeline()],
        [make_mapping()],
        make_risk(),
        generated_at=GENERATED_AT,
    )

    markdown = generator.render_markdown(report)

    assert "# Investigation Report: CASE-000001" in markdown
    assert "## Summary" in markdown
    assert "## Evidence" in markdown
    assert "## Timeline" in markdown
    assert "## MITRE ATT&CK" in markdown
    assert "`EVD-000001`" in markdown
    assert "`T1110` Brute Force" in markdown


def test_empty_report_sections_are_rendered() -> None:
    generator = ReportGenerator()
    report = generator.generate(
        make_case(),
        [],
        [],
        [],
        make_risk(),
        generated_at=GENERATED_AT,
    )

    markdown = generator.render_markdown(report)

    assert "No evidence collected." in markdown
    assert "No timeline events." in markdown
    assert "No MITRE mappings." in markdown


@pytest.mark.parametrize(
    ("case_id", "error"),
    [
        ("CASE-000002", "Risk assessment belongs to another case"),
    ],
)
def test_report_rejects_mismatched_risk(
    case_id: str,
    error: str,
) -> None:
    with pytest.raises(ValueError, match=error):
        ReportGenerator().generate(
            make_case(),
            [],
            [],
            [],
            make_risk(case_id),
            generated_at=GENERATED_AT,
        )


def test_report_rejects_mismatched_evidence() -> None:
    with pytest.raises(
        ValueError,
        match="Evidence belongs to another case",
    ):
        ReportGenerator().generate(
            make_case(),
            [make_evidence(case_id="CASE-000002")],
            [],
            [],
            make_risk(),
            generated_at=GENERATED_AT,
        )


def test_report_rejects_mismatched_timeline() -> None:
    with pytest.raises(
        ValueError,
        match="Timeline event belongs to another case",
    ):
        ReportGenerator().generate(
            make_case(),
            [],
            [make_timeline(case_id="CASE-000002")],
            [],
            make_risk(),
            generated_at=GENERATED_AT,
        )


def test_report_model_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        InvestigationReport(
            case_id="CASE-000001",
            title="Test",
            generated_at=GENERATED_AT,
            status="open",
            severity="medium",
            risk_score=50,
            risk_level="medium",
            summary="Test report",
            evidence=[],
            timeline=[],
            mitre_mappings=[],
            unexpected="value",
        )
