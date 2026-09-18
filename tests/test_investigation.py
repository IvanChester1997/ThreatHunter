from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from app.models.investigation import (
    InvestigationCase,
    InvestigationSeverity,
    InvestigationStatus,
)
from app.services.investigation_manager import InvestigationManager


def make_case(
    case_id: str = "CASE-000001",
    risk_score: int = 50,
) -> InvestigationCase:
    now = datetime.now(UTC)

    return InvestigationCase(
        id=case_id,
        title="Suspicious authentication activity",
        description="Investigation of suspicious login activity",
        severity=InvestigationSeverity.MEDIUM,
        risk_score=risk_score,
        created_at=now,
        updated_at=now,
    )


def test_investigation_case_defaults() -> None:
    case = make_case()

    assert case.status == InvestigationStatus.OPEN
    assert case.severity == InvestigationSeverity.MEDIUM
    assert case.risk_score == 50
    assert case.ioc_ids == []
    assert case.match_ids == []


@pytest.mark.parametrize(
    "risk_score",
    [-1, 101],
)
def test_risk_score_must_be_between_zero_and_one_hundred(
    risk_score: int,
) -> None:
    with pytest.raises(ValidationError):
        make_case(risk_score=risk_score)


def test_extra_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        InvestigationCase(
            id="CASE-000001",
            title="Test case",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            unexpected="value",
        )


def test_create_and_get_case() -> None:
    manager = InvestigationManager()
    case = make_case()

    assert manager.create(case) == case
    assert manager.get(case.id) == case


def test_duplicate_case_id_is_rejected() -> None:
    manager = InvestigationManager()
    manager.create(make_case())

    with pytest.raises(ValueError, match="Investigation case already exists"):
        manager.create(make_case())


def test_case_lifecycle_and_risk_are_updated() -> None:
    manager = InvestigationManager()
    case = make_case()

    manager.create(case)
    original_updated_at = case.updated_at

    manager.update_status(
        case.id,
        InvestigationStatus.IN_PROGRESS,
    )
    manager.update_severity(
        case.id,
        InvestigationSeverity.HIGH,
    )
    manager.set_risk_score(case.id, 85)

    assert case.status == InvestigationStatus.IN_PROGRESS
    assert case.severity == InvestigationSeverity.HIGH
    assert case.risk_score == 85
    assert case.updated_at >= original_updated_at


def test_iocs_and_matches_are_attached_without_duplicates() -> None:
    manager = InvestigationManager()
    case = make_case()
    manager.create(case)

    manager.attach_ioc(case.id, "IOC-000001")
    manager.attach_ioc(case.id, "IOC-000001")
    manager.attach_match(case.id, "MATCH-000001")
    manager.attach_match(case.id, "MATCH-000001")

    assert case.ioc_ids == ["IOC-000001"]
    assert case.match_ids == ["MATCH-000001"]


def test_missing_case_raises_key_error() -> None:
    manager = InvestigationManager()

    with pytest.raises(KeyError, match="Investigation case not found"):
        manager.update_status(
            "CASE-999999",
            InvestigationStatus.CLOSED,
        )


def test_updates_refresh_updated_at() -> None:
    manager = InvestigationManager()
    case = make_case()
    manager.create(case)

    before = case.updated_at
    case.updated_at = before - timedelta(seconds=1)

    updated = manager.update_status(
        case.id,
        InvestigationStatus.RESOLVED,
    )

    assert updated.updated_at > before
