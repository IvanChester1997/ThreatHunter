from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.models.investigation import (
    InvestigationCase,
    InvestigationSeverity,
)
from app.models.ioc import IOC, IOCType
from app.models.mitre import MITREMapping, MITRETactic, MITRETechnique
from app.models.risk import RiskAssessment, RiskLevel
from app.services.risk_engine import RiskEngine


def make_case(
    severity: InvestigationSeverity = InvestigationSeverity.MEDIUM,
) -> InvestigationCase:
    now = datetime.now(UTC)

    return InvestigationCase(
        id="CASE-000001",
        title="Threat investigation",
        severity=severity,
        created_at=now,
        updated_at=now,
    )


def make_ioc(confidence: int) -> IOC:
    return IOC(
        id=f"IOC-{confidence:06d}",
        type=IOCType.IP,
        value=f"192.168.1.{confidence % 254 + 1}",
        source="test-feed",
        confidence=confidence,
        created_at=datetime.now(UTC),
    )


def make_mapping(confidence: int) -> MITREMapping:
    return MITREMapping(
        evidence_id="EVD-000001",
        technique=MITRETechnique(
            id="T1110",
            name="Brute Force",
            tactic=MITRETactic.CREDENTIAL_ACCESS,
        ),
        confidence=confidence,
        rationale="Authentication attack evidence",
    )


def test_medium_case_without_indicators_has_expected_score() -> None:
    assessment = RiskEngine().assess(make_case())

    assert assessment.score == 25
    assert assessment.level == RiskLevel.MEDIUM
    assert assessment.factors == {
        "severity": 50,
        "ioc_confidence": 0,
        "mitre_confidence": 0,
    }


def test_score_combines_all_three_factors() -> None:
    assessment = RiskEngine().assess(
        make_case(InvestigationSeverity.HIGH),
        [make_ioc(80)],
        [make_mapping(90)],
    )

    assert assessment.score == 80
    assert assessment.level == RiskLevel.CRITICAL
    assert assessment.factors == {
        "severity": 75,
        "ioc_confidence": 80,
        "mitre_confidence": 90,
    }


@pytest.mark.parametrize(
    ("severity", "expected_base"),
    [
        (InvestigationSeverity.INFO, 10),
        (InvestigationSeverity.LOW, 30),
        (InvestigationSeverity.MEDIUM, 50),
        (InvestigationSeverity.HIGH, 75),
        (InvestigationSeverity.CRITICAL, 100),
    ],
)
def test_severity_maps_to_expected_base_score(
    severity: InvestigationSeverity,
    expected_base: int,
) -> None:
    assessment = RiskEngine().assess(make_case(severity))

    assert assessment.factors["severity"] == expected_base


def test_highest_ioc_confidence_is_used() -> None:
    assessment = RiskEngine().assess(
        make_case(),
        [make_ioc(20), make_ioc(85), make_ioc(60)],
    )

    assert assessment.factors["ioc_confidence"] == 85


def test_highest_mitre_confidence_is_used() -> None:
    assessment = RiskEngine().assess(
        make_case(),
        mappings=[make_mapping(40), make_mapping(95)],
    )

    assert assessment.factors["mitre_confidence"] == 95


@pytest.mark.parametrize(
    ("score", "expected_level"),
    [
        (0, RiskLevel.LOW),
        (24, RiskLevel.LOW),
        (25, RiskLevel.MEDIUM),
        (49, RiskLevel.MEDIUM),
        (50, RiskLevel.HIGH),
        (74, RiskLevel.HIGH),
        (75, RiskLevel.CRITICAL),
        (100, RiskLevel.CRITICAL),
    ],
)
def test_score_maps_to_risk_level(
    score: int,
    expected_level: RiskLevel,
) -> None:
    assert RiskEngine._level(score) == expected_level


def test_critical_inputs_are_capped_at_one_hundred() -> None:
    assessment = RiskEngine().assess(
        make_case(InvestigationSeverity.CRITICAL),
        [make_ioc(100)],
        [make_mapping(100)],
    )

    assert assessment.score == 100
    assert assessment.level == RiskLevel.CRITICAL


def test_assessment_preserves_case_id() -> None:
    assessment = RiskEngine().assess(make_case())

    assert assessment.case_id == "CASE-000001"


def test_rationale_explains_formula() -> None:
    assessment = RiskEngine().assess(make_case())

    assert "50%" in assessment.rationale
    assert "30%" in assessment.rationale
    assert "20%" in assessment.rationale


def test_risk_assessment_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        RiskAssessment(
            case_id="CASE-000001",
            score=50,
            level=RiskLevel.HIGH,
            factors={"severity": 50},
            rationale="test",
            unexpected="value",
        )
