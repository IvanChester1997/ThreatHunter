from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.models.evidence import Evidence, EvidenceType
from app.models.hunting import ThreatHuntingResult
from app.models.investigation import (
    InvestigationCase,
    InvestigationSeverity,
)
from app.models.ioc import IOC, IOCType
from app.services.hunting_service import ThreatHuntingService


def make_case(
    case_id: str = "CASE-000001",
    severity: InvestigationSeverity = InvestigationSeverity.HIGH,
) -> InvestigationCase:
    now = datetime.now(UTC)

    return InvestigationCase(
        id=case_id,
        title="Threat hunting investigation",
        severity=severity,
        created_at=now,
        updated_at=now,
    )


def make_ioc(
    ioc_id: str,
    value: str,
    confidence: int,
) -> IOC:
    return IOC(
        id=ioc_id,
        type=IOCType.DOMAIN,
        value=value,
        source="test-feed",
        confidence=confidence,
        created_at=datetime.now(UTC),
    )


def make_evidence(
    evidence_id: str,
    value: str,
    description: str,
    collected_at: datetime,
    case_id: str = "CASE-000001",
) -> Evidence:
    return Evidence(
        id=evidence_id,
        case_id=case_id,
        type=EvidenceType.LOG,
        source="/var/log/auth.log",
        value=value,
        description=description,
        collected_at=collected_at,
    )


def test_investigate_runs_full_workflow() -> None:
    timestamp = datetime(2026, 9, 18, 10, 0, tzinfo=UTC)
    ioc = make_ioc(
        "IOC-000001",
        "malicious.example",
        90,
    )
    evidence = make_evidence(
        "EVD-000001",
        "MALICIOUS.EXAMPLE",
        "SSH brute force detected",
        timestamp,
    )

    result = ThreatHuntingService().investigate(
        make_case(),
        [ioc],
        [evidence],
    )

    assert result.case_id == "CASE-000001"
    assert len(result.matches) == 1
    assert result.matches[0].ioc_id == "IOC-000001"
    assert result.matches[0].evidence_id == "EVD-000001"

    assert [event.evidence_id for event in result.timeline] == [
        "EVD-000001",
    ]
    assert [mapping.technique.id for mapping in result.mitre_mappings] == [
        "T1110",
    ]
    assert result.risk.factors["ioc_confidence"] == 90
    assert result.report.case_id == "CASE-000001"
    assert result.report.risk_score == result.risk.score


def test_risk_uses_only_matched_iocs() -> None:
    matched = make_ioc(
        "IOC-000001",
        "malicious.example",
        60,
    )
    unmatched = make_ioc(
        "IOC-000002",
        "benign.example",
        100,
    )
    evidence = make_evidence(
        "EVD-000001",
        "malicious.example",
        "Suspicious network activity",
        datetime.now(UTC),
    )

    result = ThreatHuntingService().investigate(
        make_case(severity=InvestigationSeverity.MEDIUM),
        [matched, unmatched],
        [evidence],
    )

    assert [match.ioc_id for match in result.matches] == [
        "IOC-000001",
    ]
    assert result.risk.factors["ioc_confidence"] == 60


def test_unmatched_iocs_do_not_create_matches() -> None:
    ioc = make_ioc(
        "IOC-000001",
        "malicious.example",
        90,
    )
    evidence = make_evidence(
        "EVD-000001",
        "Connection to benign.example",
        "Normal application traffic",
        datetime.now(UTC),
    )

    result = ThreatHuntingService().investigate(
        make_case(),
        [ioc],
        [evidence],
    )

    assert result.matches == []
    assert result.risk.factors["ioc_confidence"] == 0


def test_multiple_evidence_items_create_multiple_results() -> None:
    ioc = make_ioc(
        "IOC-000001",
        "malicious.example",
        80,
    )
    first_time = datetime(2026, 9, 18, 12, 0, tzinfo=UTC)
    second_time = datetime(2026, 9, 18, 9, 0, tzinfo=UTC)

    later = make_evidence(
        "EVD-000002",
        "malicious.example",
        "SSH brute force detected",
        first_time,
    )
    earlier = make_evidence(
        "EVD-000001",
        "malicious.example",
        "Password spraying detected",
        second_time,
    )

    result = ThreatHuntingService().investigate(
        make_case(),
        [ioc],
        [later, earlier],
    )

    assert len(result.matches) == 2
    assert [event.evidence_id for event in result.timeline] == [
        "EVD-000001",
        "EVD-000002",
    ]
    assert [mapping.technique.id for mapping in result.mitre_mappings] == [
        "T1110.003",
        "T1110",
    ]


def test_case_link_is_preserved_across_result() -> None:
    case = make_case("CASE-000042")
    evidence = make_evidence(
        "EVD-000001",
        "malicious.example",
        "Suspicious activity",
        datetime.now(UTC),
        case_id="CASE-000042",
    )

    result = ThreatHuntingService().investigate(
        case,
        [],
        [evidence],
    )

    assert result.case_id == "CASE-000042"
    assert result.report.case_id == "CASE-000042"
    assert result.risk.case_id == "CASE-000042"


def test_mismatched_evidence_case_is_rejected() -> None:
    case = make_case("CASE-000001")
    evidence = make_evidence(
        "EVD-000001",
        "malicious.example",
        "Suspicious activity",
        datetime.now(UTC),
        case_id="CASE-000002",
    )

    with pytest.raises(
        ValueError,
        match="Evidence belongs to another case",
    ):
        ThreatHuntingService().investigate(
            case,
            [],
            [evidence],
        )


def test_result_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        ThreatHuntingResult(
            case_id="CASE-000001",
            matches=[],
            timeline=[],
            mitre_mappings=[],
            risk={
                "case_id": "CASE-000001",
                "score": 0,
                "level": "low",
                "factors": {},
                "rationale": "test",
            },
            report={
                "case_id": "CASE-000001",
                "title": "Test",
                "generated_at": datetime.now(UTC),
                "status": "open",
                "severity": "medium",
                "risk_score": 0,
                "risk_level": "low",
                "summary": "test",
                "evidence": [],
                "timeline": [],
                "mitre_mappings": [],
            },
            unexpected="value",
        )
