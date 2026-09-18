from fastapi import FastAPI

from app.api.v1 import router
from app.config import settings
from app.services.evidence_manager import EvidenceManager
from app.services.hunting_service import ThreatHuntingService
from app.services.investigation_manager import InvestigationManager
from app.services.ioc_manager import IOCManager


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        debug=settings.debug,
    )

    app.state.ioc_manager = IOCManager()
    app.state.investigation_manager = InvestigationManager()
    app.state.evidence_manager = EvidenceManager()
    app.state.hunting_service = ThreatHuntingService()

    app.include_router(router)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {
            "status": "ok",
            "service": settings.app_name,
        }

    return app


app = create_app()
