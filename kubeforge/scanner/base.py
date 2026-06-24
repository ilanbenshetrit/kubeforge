"""
kubeforge/scanner/base.py
─────────────────────────
Abstract base class for all scanners.
Every scanner in the system inherits from BaseScanner and must implement `scan()`.
This gives us a uniform interface — the API and scheduler don't care
which scanner they're calling.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from kubeforge.models.threat import ScanSummary
from kubeforge.utils.logger import get_logger

logger = get_logger("scanner.base")


class BaseScanner(ABC):
    """
    All scanners inherit from this class.
    Subclasses must implement: scan()
    """

    name: str = "base_scanner"

    def __init__(self):
        self._running = False

    @abstractmethod
    async def scan(self) -> ScanSummary:
        """
        Run one scan cycle and return a ScanSummary with all findings.
        Must be async so multiple scanners can run concurrently.
        """
        ...

    async def run(self) -> ScanSummary:
        """Wrapper around scan() — adds timing and logging."""
        if self._running:
            logger.warning("scanner_already_running", scanner=self.name)
            return None

        self._running = True
        started_at = datetime.utcnow()
        logger.info("scan_started", scanner=self.name)

        try:
            summary = await self.scan()
            summary.started_at = started_at
            summary.finished_at = datetime.utcnow()
            summary.scanner_name = self.name

            logger.info(
                "scan_finished",
                scanner=self.name,
                threats_found=summary.total_threats_found,
                duration_seconds=round(summary.duration_seconds, 2),
            )
            return summary

        except Exception as exc:
            logger.error("scan_failed", scanner=self.name, error=str(exc))
            raise

        finally:
            self._running = False
