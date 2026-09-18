from __future__ import annotations

from app.models.evidence import Evidence


class EvidenceManager:
    def __init__(self) -> None:
        self._evidence: dict[str, Evidence] = {}

    def create(self, evidence: Evidence) -> Evidence:
        if evidence.id in self._evidence:
            raise ValueError("Evidence already exists")

        self._evidence[evidence.id] = evidence
        return evidence

    def get(self, evidence_id: str) -> Evidence | None:
        return self._evidence.get(evidence_id)

    def list(self) -> list[Evidence]:
        return list(self._evidence.values())

    def list_for_case(self, case_id: str) -> list[Evidence]:
        return [
            evidence
            for evidence in self._evidence.values()
            if evidence.case_id == case_id
        ]

    def delete(self, evidence_id: str) -> bool:
        return self._evidence.pop(evidence_id, None) is not None
