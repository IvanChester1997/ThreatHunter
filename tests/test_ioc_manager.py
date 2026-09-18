from datetime import UTC, datetime

import pytest

from app.models.ioc import IOC, IOCType
from app.services.ioc_manager import IOCManager


def make_ioc(
    ioc_id: str = "IOC-000001",
    value: str = "192.168.1.10",
) -> IOC:
    return IOC(
        id=ioc_id,
        type=IOCType.IP,
        value=value,
        source="test-feed",
        confidence=90,
        created_at=datetime.now(UTC),
    )


def test_create_and_get_ioc() -> None:
    manager = IOCManager()
    ioc = make_ioc()

    created = manager.create(ioc)

    assert created == ioc
    assert manager.get("IOC-000001") == ioc


def test_list_returns_all_iocs() -> None:
    manager = IOCManager()

    first = make_ioc()
    second = make_ioc("IOC-000002", "10.0.0.5")

    manager.create(first)
    manager.create(second)

    assert manager.list() == [first, second]


def test_duplicate_ioc_is_rejected() -> None:
    manager = IOCManager()

    manager.create(make_ioc())

    with pytest.raises(ValueError, match="IOC already exists"):
        manager.create(make_ioc("IOC-000002"))


def test_get_unknown_ioc_returns_none() -> None:
    manager = IOCManager()

    assert manager.get("IOC-999999") is None


def test_delete_existing_ioc() -> None:
    manager = IOCManager()
    ioc = make_ioc()

    manager.create(ioc)

    assert manager.delete("IOC-000001") is True
    assert manager.get("IOC-000001") is None


def test_delete_unknown_ioc_returns_false() -> None:
    manager = IOCManager()

    assert manager.delete("IOC-999999") is False
