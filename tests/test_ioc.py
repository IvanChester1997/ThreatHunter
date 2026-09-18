from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.models.ioc import IOC, IOCType

CREATED_AT = datetime.now(UTC)


@pytest.mark.parametrize(
    ("ioc_type", "value"),
    [
        (IOCType.IP, "192.168.1.10"),
        (IOCType.DOMAIN, "malicious.example"),
        (IOCType.URL, "https://malicious.example/payload"),
        (IOCType.HASH, "a" * 64),
        (IOCType.EMAIL, "attacker@example.com"),
    ],
)
def test_valid_ioc(ioc_type: IOCType, value: str) -> None:
    ioc = IOC(
        id="IOC-000001",
        type=ioc_type,
        value=value,
        source="test-feed",
        confidence=90,
        created_at=CREATED_AT,
    )

    assert ioc.type == ioc_type
    assert ioc.value == value
    assert ioc.confidence == 90


@pytest.mark.parametrize(
    ("ioc_type", "value"),
    [
        (IOCType.IP, "not-an-ip"),
        (IOCType.DOMAIN, "not a domain"),
        (IOCType.URL, "not-a-url"),
        (IOCType.HASH, "not-a-hash"),
        (IOCType.EMAIL, "not-an-email"),
    ],
)
def test_invalid_ioc_value(ioc_type: IOCType, value: str) -> None:
    with pytest.raises(ValidationError):
        IOC(
            id="IOC-000001",
            type=ioc_type,
            value=value,
            source="test-feed",
            confidence=90,
            created_at=CREATED_AT,
        )


def test_confidence_must_be_between_zero_and_one_hundred() -> None:
    with pytest.raises(ValidationError):
        IOC(
            id="IOC-000001",
            type=IOCType.IP,
            value="192.168.1.10",
            source="test-feed",
            confidence=101,
            created_at=CREATED_AT,
        )


def test_extra_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        IOC(
            id="IOC-000001",
            type=IOCType.IP,
            value="192.168.1.10",
            source="test-feed",
            confidence=90,
            created_at=CREATED_AT,
            extra_field="forbidden",
        )
