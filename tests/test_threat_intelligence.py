from datetime import UTC, datetime

import pytest

from app.models.ioc import IOC, IOCType
from app.services.threat_intelligence import (
    ThreatIntelligenceEngine,
    ThreatLevel,
)


def make_ioc(confidence: int) -> IOC:
    return IOC(
        id="IOC-000001",
        type=IOCType.IP,
        value="192.168.1.10",
        source="test-feed",
        confidence=confidence,
        created_at=datetime.now(UTC),
    )


@pytest.mark.parametrize(
    ("confidence", "expected_level"),
    [
        (0, ThreatLevel.UNKNOWN),
        (24, ThreatLevel.UNKNOWN),
        (25, ThreatLevel.LOW),
        (49, ThreatLevel.LOW),
        (50, ThreatLevel.MEDIUM),
        (74, ThreatLevel.MEDIUM),
        (75, ThreatLevel.HIGH),
        (89, ThreatLevel.HIGH),
        (90, ThreatLevel.CRITICAL),
        (100, ThreatLevel.CRITICAL),
    ],
)
def test_confidence_maps_to_threat_level(
    confidence: int,
    expected_level: str,
) -> None:
    engine = ThreatIntelligenceEngine()

    result = engine.analyze(make_ioc(confidence))

    assert result.threat_level == expected_level


def test_analyze_preserves_ioc_context() -> None:
    engine = ThreatIntelligenceEngine()
    ioc = IOC(
        id="IOC-000042",
        type=IOCType.DOMAIN,
        value="malicious.example",
        source="test-feed",
        confidence=85,
        created_at=datetime.now(UTC),
    )

    result = engine.analyze(ioc)

    assert result.ioc_id == "IOC-000042"
    assert result.ioc_type == IOCType.DOMAIN
    assert result.value == "malicious.example"
    assert result.source == "test-feed"
    assert result.confidence == 85
    assert result.threat_level == ThreatLevel.HIGH


def test_result_rejects_extra_fields() -> None:
    engine = ThreatIntelligenceEngine()
    ioc = make_ioc(90)

    result = engine.analyze(ioc)
    data = result.model_dump()
    data["unexpected"] = "value"

    with pytest.raises(ValueError):
        type(result)(**data)
