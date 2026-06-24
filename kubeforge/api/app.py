"""
kubeforge/api/app.py
──────────────────────
FastAPI application factory.
All routers are registered here.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from kubeforge.api.routes import health, scan, dashboard, history, export
from kubeforge.config import settings
from kubeforge.utils.logger import setup_logging, get_logger
from kubeforge.db.database import init_db
from kubeforge.scheduler import start_scheduler, stop_scheduler

logger = get_logger("api.app")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown logic."""
    setup_logging(debug=settings.debug)
    init_db()

    # Import here to avoid circular imports
    from kubeforge.api.routes.scan import _run_scan
    start_scheduler(_run_scan)

    logger.info(
        "kubeforge_starting",
        app=settings.app_name,
        version=settings.version,
        environment=settings.environment,
        port=settings.api_port,
    )
    yield
    stop_scheduler()
    logger.info("kubeforge_shutting_down")


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version=settings.version,
        description=(
            "KubeForge Security AI Co-Pilot — "
            "automated threat detection and AI-powered analysis for modern infrastructure."
        ),
        lifespan=lifespan,
    )

    # CORS — tighten in production
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"] if settings.environment == "development" else [],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Routers
    app.include_router(dashboard.router)
    app.include_router(health.router)
    app.include_router(scan.router, prefix="/api/v1")
    app.include_router(history.router, prefix="/api/v1")
    app.include_router(export.router, prefix="/api/v1")

    return app


app = create_app()
