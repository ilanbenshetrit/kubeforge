"""
kubeforge/scanner/data_scanner.py
──────────────────────────────────
DataScanner — scans files for sensitive data patterns:
  • API keys & tokens
  • Passwords in plain text
  • PII (emails, phone numbers, Israeli ID numbers)
  • Credit card numbers
  • Private keys (PEM, SSH)

Uses regex patterns. In future sprints this will be enhanced
with ML-based classification and context-aware detection.
"""

import re
import os
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Iterator, List, Optional

from kubeforge.scanner.base import BaseScanner
from kubeforge.models.threat import ScanSummary, ThreatEvent, Severity, ThreatCategory
from kubeforge.config import settings
from kubeforge.utils.logger import get_logger

logger = get_logger("scanner.data")


# ── Sensitive pattern definitions ────────────────────────────────────────────
PATTERNS: list[dict] = [
    {
        "name": "AWS Access Key",
        "regex": r"AKIA[0-9A-Z]{16}",
        "severity": Severity.CRITICAL,
        "category": ThreatCategory.SENSITIVE_DATA_EXPOSED,
    },
    {
        "name": "Generic API Key / Secret",
        "regex": r"(?i)(api[_\-]?key|api[_\-]?secret|access[_\-]?token)\s*[:=]\s*['\"]?([A-Za-z0-9\-_]{16,})['\"]?",
        "severity": Severity.HIGH,
        "category": ThreatCategory.SENSITIVE_DATA_EXPOSED,
    },
    {
        "name": "Password in plain text",
        "regex": r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{6,})['\"]?",
        "severity": Severity.HIGH,
        "category": ThreatCategory.SENSITIVE_DATA_EXPOSED,
    },
    {
        "name": "PEM Private Key",
        "regex": r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "severity": Severity.CRITICAL,
        "category": ThreatCategory.SENSITIVE_DATA_EXPOSED,
    },
    {
        "name": "Email Address (PII)",
        "regex": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        "severity": Severity.LOW,
        "category": ThreatCategory.SENSITIVE_DATA_EXPOSED,
    },
    {
        "name": "Israeli ID Number (תעודת זהות)",
        "regex": r"(?i)(id|tz|teudat[_\-]?zehut|id[_\-]?number)\s*[:=]\s*['\"]?\b[0-9]{8,9}\b['\"]?",
        "severity": Severity.MEDIUM,
        "category": ThreatCategory.SENSITIVE_DATA_EXPOSED,
    },
    {
        "name": "Credit Card Number",
        "regex": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
        "severity": Severity.CRITICAL,
        "category": ThreatCategory.SENSITIVE_DATA_EXPOSED,
    },
    {
        "name": "Connection String / DSN",
        "regex": r"(?i)(mongodb|postgresql|mysql|redis|amqp):\/\/[^\s\"']+",
        "severity": Severity.CRITICAL,
        "category": ThreatCategory.SENSITIVE_DATA_EXPOSED,
    },
]

# File extensions we care about
SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".json", ".yaml", ".yml",
    ".env", ".cfg", ".conf", ".ini", ".txt",
    ".sh", ".bash", ".tf", ".toml", ".pem", ".key", ".crt",
}

# Paths to always skip
SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv", ".mypy_cache",
}


class DataScanner(BaseScanner):
    """Scans files in configured target paths for sensitive data patterns."""

    name = "data_scanner"

    def __init__(self, target_paths: Optional[List[str]] = None):
        super().__init__()
        self.target_paths = target_paths or settings.scan_target_paths
        self.max_file_bytes = settings.max_file_size_mb * 1024 * 1024
        self._compiled = [
            {**p, "compiled": re.compile(p["regex"])}
            for p in PATTERNS
        ]

    def _iter_files(self, root: str) -> Iterator[Path]:
        """Walk a directory and yield files worth scanning."""
        for dirpath, dirnames, filenames in os.walk(root):
            # Skip unwanted directories in-place (modifies walk)
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for filename in filenames:
                path = Path(dirpath) / filename
                if path.suffix.lower() in SCAN_EXTENSIONS:
                    if path.stat().st_size <= self.max_file_bytes:
                        yield path

    def _scan_file(self, path: Path) -> list[ThreatEvent]:
        """Scan a single file and return any threat events found."""
        events = []
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception as exc:
            logger.warning("file_read_error", path=str(path), error=str(exc))
            return events

        for pattern in self._compiled:
            for match in pattern["compiled"].finditer(content):
                # Find line number
                line_no = content[: match.start()].count("\n") + 1
                evidence = match.group(0)[:120]  # cap evidence length

                events.append(ThreatEvent(
                    category=pattern["category"],
                    severity=pattern["severity"],
                    title=f"{pattern['name']} detected",
                    description=(
                        f"Pattern '{pattern['name']}' matched in file "
                        f"{path.name} at line {line_no}."
                    ),
                    source=self.name,
                    location=f"{path}:{line_no}",
                    raw_evidence=evidence,
                ))
        return events

    async def scan(self) -> ScanSummary:
        """Run full scan across all target paths."""
        summary = ScanSummary(
            started_at=datetime.utcnow(),
            finished_at=datetime.utcnow(),  # updated by base class
            scanner_name=self.name,
        )

        for root in self.target_paths:
            if not os.path.exists(root):
                logger.warning("scan_path_not_found", path=root)
                continue

            # Run file scanning in a thread pool so we don't block the event loop
            loop = asyncio.get_event_loop()
            files = list(self._iter_files(root))
            summary.total_files_scanned += len(files)

            for path in files:
                events = await loop.run_in_executor(None, self._scan_file, path)
                for event in events:
                    summary.add_event(event)
                    logger.info(
                        "threat_detected",
                        severity=event.severity.value,
                        title=event.title,
                        location=event.location,
                    )

        return summary
