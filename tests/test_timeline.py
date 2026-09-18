from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.models.evidence import Evidence, EvidenceType
from app.models.timeline import TimelineEvent
from app.services.timeline_builder import TimelineBuilder


def make_evidence(
    evidence_id: str,
    collected_at: datetime,
    case_id: str = "CASE-000001",
    evidence_type: EvidenceType = EvidenceType.LOG,
    source: str = "/var/log/auth.log",
    value: str = "authentication event",
    description: str = "Authentication event observed",
) -> Evidence:
    return Evidence(
        id=evidence_id,
        case_id=case_id,
        type=evidence_type,
        source=source,
        value=value,
        description=description,
        collected_at=collected_at,
    )


def test_build_creates_timeline_events() -> None:
    builder = TimelineBuilder()
    evidence = make_evidence(
        "EVD-000001",
        datetime(2026, 9, 18, 10, 0, tzinfo=UTC),
    )

    timeline = builder.build([evidence])

    assert len(timeline) == 1
    assert timeline[0] == TimelineEvent(
        id="TL-EVD-000001",
        case_id="CASE-000001",
        timestamp=evidence.collected_at,
        event_type=EvidenceType.LOG,
        source="/var/log/auth.log",
        description="Authentication event observed",
        evidence_id="EVD-000001",
    )


def test_timeline_is_sorted_chronologically() -> None:
    builder = TimelineBuilder()
    later = make_evidence(
        "EVD-000002",
        datetime(2026, 9, 18, 12, 0, tzinfo=UTC),
    )
    earlier = make_evidence(
        "EVD-000001",
        datetime(2026, 9, 18, 9, 0, tzinfo=UTC),
    )
    middle = make_evidence(
        "EVD-000003",
        datetime(2026, 9, 18, 10, 30, tzinfo=UTC),
    )

    timeline = builder.build([later, earlier, middle])

    assert [event.evidence_id for event in timeline] == [
        "EVD-000001",
        "EVD-000003",
        "EVD-000002",
    ]


def test_same_timestamp_uses_event_id_as_deterministic_tiebreaker() -> None:
    builder = TimelineBuilder()
    timestamp = datetime(2026, 9, 18, 10, 0, tzinfo=UTC)

    second = make_evidence("EVD-000002", timestamp)
    first = make_evidence("EVD-000001", timestamp)

    timeline = builder.build([second, first])

    assert [event.id for event in timeline] == [
        "TL-EVD-000001",
        "TL-EVD-000002",
    ]


def test_empty_evidence_returns_empty_timeline() -> None:
    assert TimelineBuilder().build([]) == []


def test_description_falls_back_to_evidence_value() -> None:
    builder = TimelineBuilder()
    evidence = make_evidence(
        "EVD-000004",
        datetime(2026, 9, 18, 10, 0, tzinfo=UTC),
        description="",
        value="Failed password for root",
    )

    timeline = builder.build([evidence])

    assert timeline[0].description == "Failed password for root"


def test_case_id_is_preserved() -> None:
    builder = TimelineBuilder()
    evidence = make_evidence(
        "EVD-000005",
        datetime(2026, 9, 18, 10, 0, tzinfo=UTC),
        case_id="CASE-000042",
    )

    timeline = builder.build([evidence])

    assert timeline[0].case_id == "CASE-000042"


def test_extra_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        TimelineEvent(
            id="TL-EVD-000001",
            case_id="CASE-000001",
            timestamp=datetime.now(UTC),
            event_type=EvidenceType.LOG,
            source="test",
            description="event",
            evidence_id="EVD-000001",
            unexpected="value",
        )
