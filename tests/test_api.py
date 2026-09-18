from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(create_app()) as test_client:
        yield test_client


def investigation_payload(
    case_id: str = "CASE-000001",
) -> dict[str, object]:
    return {
        "id": case_id,
        "title": "Suspicious activity",
        "description": "Investigation case",
        "severity": "high",
    }


def evidence_payload(
    evidence_id: str = "EVD-000001",
    case_id: str = "CASE-000001",
) -> dict[str, object]:
    return {
        "id": evidence_id,
        "case_id": case_id,
        "type": "log",
        "source": "/var/log/auth.log",
        "value": "Failed password for root",
        "description": "SSH authentication failure",
    }


def test_health_endpoint(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "ThreatHunter",
    }


def test_create_and_get_ioc(client: TestClient) -> None:
    payload = {
        "id": "IOC-000001",
        "type": "ip",
        "value": "192.168.1.10",
        "source": "test-feed",
        "confidence": 90,
    }

    response = client.post("/api/v1/iocs", json=payload)

    assert response.status_code == 201
    assert response.json()["id"] == "IOC-000001"

    response = client.get("/api/v1/iocs/IOC-000001")

    assert response.status_code == 200
    assert response.json()["value"] == "192.168.1.10"


def test_list_iocs(client: TestClient) -> None:
    for index in range(2):
        response = client.post(
            "/api/v1/iocs",
            json={
                "id": f"IOC-00000{index + 1}",
                "type": "ip",
                "value": f"192.168.1.{index + 10}",
                "source": "test-feed",
                "confidence": 80,
            },
        )
        assert response.status_code == 201

    response = client.get("/api/v1/iocs")

    assert response.status_code == 200
    assert len(response.json()) == 2


def test_duplicate_ioc_returns_conflict(client: TestClient) -> None:
    payload = {
        "id": "IOC-000001",
        "type": "ip",
        "value": "192.168.1.10",
        "source": "test-feed",
        "confidence": 90,
    }

    assert client.post("/api/v1/iocs", json=payload).status_code == 201

    duplicate = payload | {"id": "IOC-000002"}
    response = client.post("/api/v1/iocs", json=duplicate)

    assert response.status_code == 409
    assert response.json()["detail"] == "IOC already exists"


def test_invalid_ioc_returns_unprocessable_entity(client: TestClient) -> None:
    response = client.post(
        "/api/v1/iocs",
        json={
            "id": "IOC-000001",
            "type": "ip",
            "value": "not-an-ip",
            "source": "test-feed",
            "confidence": 90,
        },
    )

    assert response.status_code == 422


def test_missing_ioc_returns_not_found(client: TestClient) -> None:
    response = client.get("/api/v1/iocs/IOC-999999")

    assert response.status_code == 404


def test_delete_ioc(client: TestClient) -> None:
    payload = {
        "id": "IOC-000001",
        "type": "ip",
        "value": "192.168.1.10",
        "source": "test-feed",
        "confidence": 90,
    }

    client.post("/api/v1/iocs", json=payload)

    assert client.delete("/api/v1/iocs/IOC-000001").status_code == 204
    assert client.get("/api/v1/iocs/IOC-000001").status_code == 404


def test_create_and_update_investigation(client: TestClient) -> None:
    response = client.post(
        "/api/v1/investigations",
        json=investigation_payload(),
    )

    assert response.status_code == 201
    assert response.json()["status"] == "open"

    response = client.patch(
        "/api/v1/investigations/CASE-000001/status",
        json={"status": "in_progress"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "in_progress"

    response = client.patch(
        "/api/v1/investigations/CASE-000001/severity",
        json={"severity": "critical"},
    )

    assert response.status_code == 200
    assert response.json()["severity"] == "critical"

    response = client.patch(
        "/api/v1/investigations/CASE-000001/risk",
        json={"risk_score": 90},
    )

    assert response.status_code == 200
    assert response.json()["risk_score"] == 90


def test_duplicate_investigation_returns_conflict(client: TestClient) -> None:
    assert client.post(
        "/api/v1/investigations",
        json=investigation_payload(),
    ).status_code == 201

    response = client.post(
        "/api/v1/investigations",
        json=investigation_payload(),
    )

    assert response.status_code == 409


def test_missing_investigation_returns_not_found(client: TestClient) -> None:
    assert client.get(
        "/api/v1/investigations/CASE-999999",
    ).status_code == 404

    assert client.patch(
        "/api/v1/investigations/CASE-999999/status",
        json={"status": "closed"},
    ).status_code == 404


def test_create_evidence_requires_existing_case(client: TestClient) -> None:
    response = client.post(
        "/api/v1/evidence",
        json=evidence_payload(),
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Investigation case not found"


def test_create_and_get_evidence(client: TestClient) -> None:
    assert client.post(
        "/api/v1/investigations",
        json=investigation_payload(),
    ).status_code == 201

    response = client.post(
        "/api/v1/evidence",
        json=evidence_payload(),
    )

    assert response.status_code == 201
    assert response.json()["id"] == "EVD-000001"

    response = client.get("/api/v1/evidence/EVD-000001")

    assert response.status_code == 200
    assert response.json()["case_id"] == "CASE-000001"


def test_list_evidence_for_case(client: TestClient) -> None:
    assert client.post(
        "/api/v1/investigations",
        json=investigation_payload(),
    ).status_code == 201

    for index in range(2):
        response = client.post(
            "/api/v1/evidence",
            json=evidence_payload(
                evidence_id=f"EVD-00000{index + 1}",
            ),
        )
        assert response.status_code == 201

    response = client.get(
        "/api/v1/investigations/CASE-000001/evidence",
    )

    assert response.status_code == 200
    assert len(response.json()) == 2


def test_duplicate_evidence_returns_conflict(client: TestClient) -> None:
    assert client.post(
        "/api/v1/investigations",
        json=investigation_payload(),
    ).status_code == 201

    payload = evidence_payload()
    assert client.post("/api/v1/evidence", json=payload).status_code == 201

    response = client.post("/api/v1/evidence", json=payload)

    assert response.status_code == 409


def test_delete_evidence(client: TestClient) -> None:
    assert client.post(
        "/api/v1/investigations",
        json=investigation_payload(),
    ).status_code == 201

    assert client.post(
        "/api/v1/evidence",
        json=evidence_payload(),
    ).status_code == 201

    assert client.delete("/api/v1/evidence/EVD-000001").status_code == 204
    assert client.get("/api/v1/evidence/EVD-000001").status_code == 404


def test_extra_api_fields_are_rejected(client: TestClient) -> None:
    payload = investigation_payload() | {"unexpected": "value"}

    response = client.post(
        "/api/v1/investigations",
        json=payload,
    )

    assert response.status_code == 422
