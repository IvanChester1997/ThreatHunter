from datetime import UTC, datetime

from app.models.ioc import IOC, IOCType
from app.services.ioc_matcher import IOCMatcher


def make_ioc(
    ioc_id: str,
    ioc_type: IOCType,
    value: str,
) -> IOC:
    return IOC(
        id=ioc_id,
        type=ioc_type,
        value=value,
        source="test-feed",
        confidence=90,
        created_at=datetime.now(UTC),
    )


def test_matches_ip_and_reports_field() -> None:
    matcher = IOCMatcher()
    ioc = make_ioc("IOC-000001", IOCType.IP, "192.168.1.10")

    matches = matcher.match(
        [ioc],
        {"source_ip": "192.168.1.10"},
    )

    assert len(matches) == 1
    assert matches[0].ioc_id == "IOC-000001"
    assert matches[0].ioc_type == IOCType.IP
    assert matches[0].ioc_value == "192.168.1.10"
    assert matches[0].field == "source_ip"
    assert matches[0].observed_value == "192.168.1.10"


def test_domain_matching_is_case_insensitive() -> None:
    matcher = IOCMatcher()
    ioc = make_ioc("IOC-000002", IOCType.DOMAIN, "Malicious.Example")

    matches = matcher.match(
        [ioc],
        {"destination_domain": "malicious.example"},
    )

    assert len(matches) == 1


def test_matches_nested_and_list_values() -> None:
    matcher = IOCMatcher()
    ioc = make_ioc("IOC-000003", IOCType.EMAIL, "attacker@example.com")

    matches = matcher.match(
        [ioc],
        {
            "user": {
                "emails": [
                    "user@example.com",
                    "ATTACKER@EXAMPLE.COM",
                ],
            },
        },
    )

    assert len(matches) == 1
    assert matches[0].field == "user.emails[1]"
    assert matches[0].observed_value == "ATTACKER@EXAMPLE.COM"


def test_returns_multiple_matches() -> None:
    matcher = IOCMatcher()
    ip_ioc = make_ioc("IOC-000004", IOCType.IP, "10.0.0.5")
    hash_ioc = make_ioc("IOC-000005", IOCType.HASH, "a" * 64)

    matches = matcher.match(
        [ip_ioc, hash_ioc],
        {
            "source_ip": "10.0.0.5",
            "file_hash": "A" * 64,
        },
    )

    assert [match.ioc_id for match in matches] == [
        "IOC-000004",
        "IOC-000005",
    ]


def test_no_match_returns_empty_list() -> None:
    matcher = IOCMatcher()
    ioc = make_ioc("IOC-000006", IOCType.IP, "10.0.0.5")

    matches = matcher.match(
        [ioc],
        {"source_ip": "10.0.0.6"},
    )

    assert matches == []


def test_non_string_values_are_ignored() -> None:
    matcher = IOCMatcher()
    ioc = make_ioc("IOC-000007", IOCType.IP, "10.0.0.5")

    matches = matcher.match(
        [ioc],
        {
            "port": 443,
            "success": True,
            "metadata": None,
            "source_ip": "10.0.0.5",
        },
    )

    assert len(matches) == 1
    assert matches[0].field == "source_ip"


def test_hash_matching_is_case_insensitive() -> None:
    matcher = IOCMatcher()
    ioc = make_ioc("IOC-000008", IOCType.HASH, "a" * 64)

    matches = matcher.match(
        [ioc],
        {"file_hash": "A" * 64},
    )

    assert len(matches) == 1
