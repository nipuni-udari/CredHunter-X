from __future__ import annotations

import os

from fastapi import Depends, FastAPI

from app.api.finding_routes import router as finding_router
from app.api.project_routes import router as project_router
from app.api.scan_routes import router as scan_router
from app.api.security import require_api_key
from app.core.env import load_local_env


def create_app() -> FastAPI:
    load_local_env()
    app = FastAPI(
        title="CredHunter-X Backend API",
        version="0.4.0",
        description="Pipeline-aware Git leak detection backend.",
    )

    @app.get("/health")
    def health_check() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/health/ready")
    def readiness_check() -> dict[str, str]:
        storage = "mongodb" if os.getenv("CREDHUNTER_MONGODB_URI") else "memory"
        return {"status": "ready", "storage": storage}

    api_auth = [Depends(require_api_key)]
    app.include_router(scan_router, prefix="/api", dependencies=api_auth)
    app.include_router(finding_router, prefix="/api", dependencies=api_auth)
    app.include_router(project_router, prefix="/api", dependencies=api_auth)
    return app


app = create_app()
