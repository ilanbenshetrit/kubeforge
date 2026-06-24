"""
main.py
────────
Entry point for the KubeForge Core platform.
Run with:  python main.py
           uvicorn main:app --host 0.0.0.0 --port 8080 --reload
"""

import uvicorn
from kubeforge.api.app import app  # noqa: F401 — re-exported for uvicorn
from kubeforge.config import settings

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.environment == "development",
        log_level="debug" if settings.debug else "info",
    )
