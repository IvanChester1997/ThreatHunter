from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.models.evidence import Evidence, EvidenceType
from app.services.evidence_manager import EvidenceManager


def make_evidence(
    evidence_id: str = "EVD-000001",
    case_id: str = "CASE-000001",
    evidence_type: EvidenceType = EvidenceType.LOG,
    value: str = "Failed password for user root",
) -> Evidence:
    return Evidence(
        id=evidence_id,
        case_id=case_id,
        type=evidence_type,
        source="/var/log/auth.log",
        value=value,
        description="SSH authentication failure",
        collected_at=datetime.now(UTC),
    )


def test_evidence_model_preserves_context() -> None:
    evidence = make_evidence()

    assert evidence.id == "EVD-000001"
    assert evidence.case_id == "CASE-000001"
    assert evidence.type == EvidenceType.LOG
    assert evidence.source == "/var/log/auth.log"
    assert evidence.value == "Failed password for user root"
    assert evidence.description == "SSH authentication failure"


@pytest.mark.parametrize(
    "evidence_type",
    list(EvidenceType),
)
def test_supported_evidence_types_are_valid(
    evidence_type: EvidenceType,
) -> None:
    evidence = make_evidence(evidence_type=evidence_type)

    assert evidence.type == evidence_type


def test_empty_case_id_is_rejected() -> None:
    with pytest.raises(ValidationError):
        make_evidence(case_id="")


def test_extra_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        Evidence(
            id="EVD-000001",
            case_id="CASE-000001",
            type=EvidenceType.LOG,
            source="test",
            value="evidence",
            collected_at=datetime.now(UTC),
            unexpected="value",
        )


def test_create_and_get_evidence() -> None:
    manager = EvidenceManager()
    evidence = make_evidence()

    assert manager.create(evidence) == evidence
    assert manager.get(evidence.id) == evidence


def test_duplicate_evidence_id_is_rejected() -> None:
    manager = EvidenceManager()
    manager.create(make_evidence())

    with pytest.raises(ValueError, match="Evidence already exists"):
        manager.create(make_evidence())


def test_list_returns_all_evidence() -> None:
    manager = EvidenceManager()
    first = make_evidence()
    second = make_evidence(
        evidence_id="EVD-000002",
        case_id="CASE-000002",
        evidence_type=EvidenceType.NETWORK,
        value="192.168.1.10:22",
    )

    manager.create(first)
    manager.create(second)

    assert manager.list() == [first, second]


def test_list_for_case_filters_evidence() -> None:
    manager = EvidenceManager()
    first = make_evidence()
    second = make_evidence(
        evidence_id="EVD-000002",
        case_id="CASE-000002",
        evidence_type=EvidenceType.FILE,
        value="/tmp/suspicious.bin",
    )
    third = make_evidence(
        evidence_id="EVD-000003",
        case_id="CASE-000001",
        evidence_type=EvidenceType.PROCESS,
        value="/tmp/malware --connect 10.0.0.5",
    )

    manager.create(first)
    manager.create(second)
    manager.create(third)

    assert manager.list_for_case("CASE-000001") == [first, third]
    assert manager.list_for_case("CASE-999999") == []


def test_delete_existing_evidence() -> None:
    manager = EvidenceManager()
    evidence = make_evidence()
    manager.create(evidence)

    assert manager.delete(evidence.id) is True
    assert manager.get(evidence.id) is None


def test_delete_unknown_evidence_returns_false() -> None:
    manager = EvidenceManager()

    assert manager.delete("EVD-999999") is False
