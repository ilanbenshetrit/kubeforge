"""
kubeforge/scheduler.py
───────────────────────
Background scheduler — runs automatic scans on a configurable interval.
Uses APScheduler (already in requirements.txt).
"""

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from kubeforge.config import settings
from kubeforge.utils.logger import get_logger

logger = get_logger("scheduler")

scheduler = AsyncIOScheduler()


def start_scheduler(scan_func):
    """
    Start the background scheduler.
    scan_func: async callable that runs a scan (from api.routes.scan).
    """
    interval = settings.scan_interval_seconds

    scheduler.add_job(
        scan_func,
        trigger="interval",
        seconds=interval,
        id="auto_scan",
        replace_existing=True,
        kwargs={"paths": None, "enrich_with_ai": True},
    )
    scheduler.start()
    logger.info("scheduler_started", interval_seconds=interval)


def stop_scheduler():
    if scheduler.running:
        scheduler.shutdown()
        logger.info("scheduler_stopped")
