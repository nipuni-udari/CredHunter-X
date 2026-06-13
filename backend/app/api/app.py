from __future__ import annotations

import os

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

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

    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins(),
        allow_methods=["*"],
        allow_headers=["*"],
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


def _cors_origins() -> list[str]:
    """Allowed browser origins for the dashboard.

    Configurable via CREDHUNTER_CORS_ORIGINS (comma-separated). Defaults to the
    local Vite dev server.
    """

    raw = os.getenv("CREDHUNTER_CORS_ORIGINS", "")
    origins = [origin.strip() for origin in raw.split(",") if origin.strip()]
    return origins or ["http://localhost:5173", "http://127.0.0.1:5173"]


app = create_app()
