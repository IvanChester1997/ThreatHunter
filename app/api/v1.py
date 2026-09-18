from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import ValidationError

from app.api.schemas import (
    EvidenceCreate,
    HuntingRequest,
    InvestigationCreate,
    IOCCreate,
    RiskUpdate,
    SeverityUpdate,
    StatusUpdate,
)
from app.models.evidence import Evidence
from app.models.hunting import ThreatHuntingResult
from app.models.investigation import InvestigationCase
from app.models.ioc import IOC
from app.services.evidence_manager import EvidenceManager
from app.services.hunting_service import ThreatHuntingService
from app.services.investigation_manager import InvestigationManager
from app.services.ioc_manager import IOCManager

router = APIRouter(prefix="/api/v1")


def get_ioc_manager(request: Request) -> IOCManager:
    return request.app.state.ioc_manager


def get_investigation_manager(request: Request) -> InvestigationManager:
    return request.app.state.investigation_manager


def get_evidence_manager(request: Request) -> EvidenceManager:
    return request.app.state.evidence_manager


def get_hunting_service(request: Request) -> ThreatHuntingService:
    return request.app.state.hunting_service


@router.post(
    "/iocs",
    response_model=IOC,
    status_code=status.HTTP_201_CREATED,
)
def create_ioc(
    payload: IOCCreate,
    request: Request,
) -> IOC:
    manager = get_ioc_manager(request)

    try:
        ioc = IOC(
            id=payload.id,
            type=payload.type,
            value=payload.value,
            source=payload.source,
            confidence=payload.confidence,
            created_at=datetime.now(UTC),
        )
    except ValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=exc.errors(include_context=False),
        ) from exc

    try:
        return manager.create(ioc)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc


@router.get("/iocs", response_model=list[IOC])
def list_iocs(request: Request) -> list[IOC]:
    return get_ioc_manager(request).list()


@router.get("/iocs/{ioc_id}", response_model=IOC)
def get_ioc(ioc_id: str, request: Request) -> IOC:
    ioc = get_ioc_manager(request).get(ioc_id)

    if ioc is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="IOC not found",
        )

    return ioc


@router.delete(
    "/iocs/{ioc_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_ioc(ioc_id: str, request: Request) -> None:
    if not get_ioc_manager(request).delete(ioc_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="IOC not found",
        )


@router.post(
    "/investigations",
    response_model=InvestigationCase,
    status_code=status.HTTP_201_CREATED,
)
def create_investigation(
    payload: InvestigationCreate,
    request: Request,
) -> InvestigationCase:
    now = datetime.now(UTC)
    case = InvestigationCase(
        id=payload.id,
        title=payload.title,
        description=payload.description,
        status=payload.status,
        severity=payload.severity,
        risk_score=payload.risk_score,
        created_at=now,
        updated_at=now,
    )

    try:
        return get_investigation_manager(request).create(case)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc


@router.get("/investigations", response_model=list[InvestigationCase])
def list_investigations(request: Request) -> list[InvestigationCase]:
    return get_investigation_manager(request).list()


@router.get(
    "/investigations/{case_id}",
    response_model=InvestigationCase,
)
def get_investigation(
    case_id: str,
    request: Request,
) -> InvestigationCase:
    case = get_investigation_manager(request).get(case_id)

    if case is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation case not found",
        )

    return case


@router.patch(
    "/investigations/{case_id}/status",
    response_model=InvestigationCase,
)
def update_investigation_status(
    case_id: str,
    payload: StatusUpdate,
    request: Request,
) -> InvestigationCase:
    try:
        return get_investigation_manager(request).update_status(
            case_id,
            payload.status,
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation case not found",
        ) from exc


@router.patch(
    "/investigations/{case_id}/severity",
    response_model=InvestigationCase,
)
def update_investigation_severity(
    case_id: str,
    payload: SeverityUpdate,
    request: Request,
) -> InvestigationCase:
    try:
        return get_investigation_manager(request).update_severity(
            case_id,
            payload.severity,
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation case not found",
        ) from exc


@router.patch(
    "/investigations/{case_id}/risk",
    response_model=InvestigationCase,
)
def update_investigation_risk(
    case_id: str,
    payload: RiskUpdate,
    request: Request,
) -> InvestigationCase:
    try:
        return get_investigation_manager(request).set_risk_score(
            case_id,
            payload.risk_score,
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation case not found",
        ) from exc


@router.post(
    "/evidence",
    response_model=Evidence,
    status_code=status.HTTP_201_CREATED,
)
def create_evidence(
    payload: EvidenceCreate,
    request: Request,
) -> Evidence:
    investigation_manager = get_investigation_manager(request)

    if investigation_manager.get(payload.case_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation case not found",
        )

    evidence = Evidence(
        id=payload.id,
        case_id=payload.case_id,
        type=payload.type,
        source=payload.source,
        value=payload.value,
        description=payload.description,
        collected_at=payload.collected_at or datetime.now(UTC),
    )

    try:
        return get_evidence_manager(request).create(evidence)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc


@router.get("/evidence", response_model=list[Evidence])
def list_evidence(request: Request) -> list[Evidence]:
    return get_evidence_manager(request).list()


@router.get(
    "/investigations/{case_id}/evidence",
    response_model=list[Evidence],
)
def list_case_evidence(
    case_id: str,
    request: Request,
) -> list[Evidence]:
    if get_investigation_manager(request).get(case_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation case not found",
        )

    return get_evidence_manager(request).list_for_case(case_id)


@router.get("/evidence/{evidence_id}", response_model=Evidence)
def get_evidence(
    evidence_id: str,
    request: Request,
) -> Evidence:
    evidence = get_evidence_manager(request).get(evidence_id)

    if evidence is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence not found",
        )

    return evidence


@router.delete(
    "/evidence/{evidence_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_evidence(
    evidence_id: str,
    request: Request,
) -> None:
    if not get_evidence_manager(request).delete(evidence_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence not found",
        )


@router.post(
    "/investigations/{case_id}/hunt",
    response_model=ThreatHuntingResult,
)
def hunt_investigation(
    case_id: str,
    payload: HuntingRequest,
    request: Request,
) -> ThreatHuntingResult:
    investigation_manager = get_investigation_manager(request)
    case = investigation_manager.get(case_id)

    if case is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation case not found",
        )

    iocs: list[IOC] = []
    ioc_manager = get_ioc_manager(request)

    for ioc_id in payload.ioc_ids:
        ioc = ioc_manager.get(ioc_id)

        if ioc is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"IOC not found: {ioc_id}",
            )

        iocs.append(ioc)

    evidence: list[Evidence] = []
    evidence_manager = get_evidence_manager(request)

    for evidence_id in payload.evidence_ids:
        item = evidence_manager.get(evidence_id)

        if item is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Evidence not found: {evidence_id}",
            )

        if item.case_id != case_id:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Evidence belongs to another case",
            )

        evidence.append(item)

    return get_hunting_service(request).investigate(
        case,
        iocs,
        evidence,
    )
