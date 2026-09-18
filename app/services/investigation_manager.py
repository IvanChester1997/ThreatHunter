from datetime import UTC, datetime

from app.models.investigation import (
    InvestigationCase,
    InvestigationSeverity,
    InvestigationStatus,
)


class InvestigationManager:
    def __init__(self) -> None:
        self._cases: dict[str, InvestigationCase] = {}

    def create(self, case: InvestigationCase) -> InvestigationCase:
        if case.id in self._cases:
            raise ValueError("Investigation case already exists")

        self._cases[case.id] = case
        return case

    def get(self, case_id: str) -> InvestigationCase | None:
        return self._cases.get(case_id)

    def list(self) -> list[InvestigationCase]:
        return list(self._cases.values())

    def update_status(
        self,
        case_id: str,
        status: InvestigationStatus,
    ) -> InvestigationCase:
        case = self._require(case_id)
        case.status = status
        case.updated_at = datetime.now(UTC)
        return case

    def update_severity(
        self,
        case_id: str,
        severity: InvestigationSeverity,
    ) -> InvestigationCase:
        case = self._require(case_id)
        case.severity = severity
        case.updated_at = datetime.now(UTC)
        return case

    def set_risk_score(
        self,
        case_id: str,
        risk_score: int,
    ) -> InvestigationCase:
        if not 0 <= risk_score <= 100:
            raise ValueError("risk score must be between 0 and 100")

        case = self._require(case_id)
        case.risk_score = risk_score
        case.updated_at = datetime.now(UTC)
        return case

    def attach_ioc(
        self,
        case_id: str,
        ioc_id: str,
    ) -> InvestigationCase:
        case = self._require(case_id)

        if ioc_id not in case.ioc_ids:
            case.ioc_ids.append(ioc_id)

        case.updated_at = datetime.now(UTC)
        return case

    def attach_match(
        self,
        case_id: str,
        match_id: str,
    ) -> InvestigationCase:
        case = self._require(case_id)

        if match_id not in case.match_ids:
            case.match_ids.append(match_id)

        case.updated_at = datetime.now(UTC)
        return case

    def _require(self, case_id: str) -> InvestigationCase:
        case = self.get(case_id)
        if case is None:
            raise KeyError(f"Investigation case not found: {case_id}")

        return case
