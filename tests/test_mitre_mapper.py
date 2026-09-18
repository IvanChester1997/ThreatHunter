from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.models.evidence import Evidence, EvidenceType
from app.models.mitre import MITREMapping, MITRETactic, MITRETechnique
from app.services.mitre_mapper import MITREMapper


def make_evidence(
    evidence_id: str,
    value: str,
    description: str,
    evidence_type: EvidenceType = EvidenceType.LOG,
) -> Evidence:
    return Evidence(
        id=evidence_id,
        case_id="CASE-000001",
        type=evidence_type,
        source="test-source",
        value=value,
        description=description,
        collected_at=datetime.now(UTC),
    )


def test_password_spraying_maps_to_subtechnique() -> None:
    mapper = MITREMapper()

    mappings = mapper.map_evidence(
        make_evidence(
            "EVD-000001",
            "multiple users targeted",
            "Password spraying detected against SSH",
        )
    )

    assert len(mappings) == 1
    assert mappings[0].technique.id == "T1110.003"
    assert mappings[0].technique.name == "Password Spraying"
    assert mappings[0].technique.tactic == MITRETactic.CREDENTIAL_ACCESS
    assert mappings[0].confidence == 95


def test_brute_force_maps_to_parent_technique() -> None:
    mapper = MITREMapper()

    mappings = mapper.map_evidence(
        make_evidence(
            "EVD-000002",
            "failed authentication attempts",
            "SSH brute force detected",
        )
    )

    assert [mapping.technique.id for mapping in mappings] == ["T1110"]


@pytest.mark.parametrize(
    ("value", "expected_technique"),
    [
        ("powershell.exe -enc AAA", "T1059.001"),
        ("cmd.exe /c whoami", "T1059.003"),
        ("/bin/bash -c id", "T1059.004"),
    ],
)
def test_shell_indicators_map_to_mitre_subtechniques(
    value: str,
    expected_technique: str,
) -> None:
    mapper = MITREMapper()

    mappings = mapper.map_evidence(
        make_evidence(
            f"EVD-{expected_technique}",
            value,
            "Suspicious command execution",
            EvidenceType.COMMAND,
        )
    )

    assert [mapping.technique.id for mapping in mappings] == [expected_technique]
    assert mappings[0].technique.tactic == MITRETactic.EXECUTION


def test_multiple_rules_can_map_one_evidence() -> None:
    mapper = MITREMapper()

    mappings = mapper.map_evidence(
        make_evidence(
            "EVD-000006",
            "powershell.exe",
            "Password spraying followed by PowerShell execution",
            EvidenceType.COMMAND,
        )
    )

    assert [mapping.technique.id for mapping in mappings] == [
        "T1110.003",
        "T1059.001",
    ]


def test_unmatched_evidence_returns_empty_list() -> None:
    mapper = MITREMapper()

    mappings = mapper.map_evidence(
        make_evidence(
            "EVD-000007",
            "/var/log/app.log",
            "Application started successfully",
        )
    )

    assert mappings == []


def test_map_many_preserves_evidence_order() -> None:
    mapper = MITREMapper()
    evidence = [
        make_evidence(
            "EVD-000008",
            "cmd.exe /c whoami",
            "Command execution",
            EvidenceType.COMMAND,
        ),
        make_evidence(
            "EVD-000009",
            "password spray",
            "Password spraying detected",
        ),
    ]

    mappings = mapper.map_many(evidence)

    assert [mapping.evidence_id for mapping in mappings] == [
        "EVD-000008",
        "EVD-000009",
    ]


def test_technique_rejects_invalid_id() -> None:
    with pytest.raises(ValidationError):
        MITRETechnique(
            id="INVALID",
            name="Invalid",
            tactic=MITRETactic.EXECUTION,
        )


def test_mapping_rejects_invalid_confidence() -> None:
    with pytest.raises(ValidationError):
        MITREMapping(
            evidence_id="EVD-000010",
            technique=MITRETechnique(
                id="T1110",
                name="Brute Force",
                tactic=MITRETactic.CREDENTIAL_ACCESS,
            ),
            confidence=101,
            rationale="test",
        )


def test_mapping_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        MITREMapping(
            evidence_id="EVD-000011",
            technique=MITRETechnique(
                id="T1059",
                name="Command and Scripting Interpreter",
                tactic=MITRETactic.EXECUTION,
            ),
            confidence=90,
            rationale="test",
            unexpected="value",
        )
