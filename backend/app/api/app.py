from __future__ import annotations

from fastapi import FastAPI

from app.api.finding_routes import router as finding_router
from app.api.project_routes import router as project_router
from app.api.scan_routes import router as scan_router


def create_app() -> FastAPI:
    app = FastAPI(
        title="CredHunter-X Backend API",
        version="0.4.0",
        description="Pipeline-aware Git leak detection backend.",
    )

    @app.get("/health")
    def health_check() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(scan_router, prefix="/api")
    app.include_router(finding_router, prefix="/api")
    app.include_router(project_router, prefix="/api")
    return app


app = create_app()
