# KubeForge - Full Python Source Code
# Generated: Tue Jun 23 16:37:51 UTC 2026


# ════════════════════════════════════════════════════════
# FILE: main.py
# ════════════════════════════════════════════════════════

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


# ════════════════════════════════════════════════════════
# FILE: kubeforge/config.py
# ════════════════════════════════════════════════════════

"""
kubeforge/config.py
────────────────────
Central configuration for the KubeForge platform.
All settings are loaded from environment variables (or a .env file).
Uses pydantic-settings so every value is type-validated at startup.
"""

from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    # ── General ──────────────────────────────────────────────────────────
    app_name: str = Field(default="KubeForge Security Platform", alias="APP_NAME")
    version: str = Field(default="0.1.0", alias="VERSION")
    environment: str = Field(default="development", alias="ENVIRONMENT")  # development | production
    debug: bool = Field(default=False, alias="DEBUG")

    # ── API Server ────────────────────────────────────────────────────────
    api_host: str = Field(default="0.0.0.0", alias="API_HOST")
    api_port: int = Field(default=8080, alias="API_PORT")
    api_secret_key: str = Field(default="change-me-in-production", alias="API_SECRET_KEY")

    # ── AI Co-Pilot ───────────────────────────────────────────────────────
    openai_api_key: str = Field(default="", alias="OPENAI_API_KEY")
    openai_model: str = Field(default="gpt-4o", alias="OPENAI_MODEL")
    copilot_language: str = Field(default="hebrew", alias="COPILOT_LANGUAGE")  # hebrew | english

    # ── Scanner ───────────────────────────────────────────────────────────
    scan_interval_seconds: int = Field(default=60, alias="SCAN_INTERVAL_SECONDS")
    scan_target_paths: list[str] = Field(default=["/data", "/tmp"], alias="SCAN_TARGET_PATHS")
    max_file_size_mb: int = Field(default=50, alias="MAX_FILE_SIZE_MB")

    # ── Network Scanner ───────────────────────────────────────────────────
    network_scan_hosts: list[str] = Field(default=[], alias="NETWORK_SCAN_HOSTS")

    # ── Alerts ────────────────────────────────────────────────────────────
    alert_email: str = Field(default="", alias="ALERT_EMAIL")
    slack_webhook_url: str = Field(default="", alias="SLACK_WEBHOOK_URL")

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "populate_by_name": True,
    }


# Singleton — import this everywhere
settings = Settings()


# ════════════════════════════════════════════════════════
# FILE: kubeforge/models/threat.py
# ════════════════════════════════════════════════════════

"""
kubeforge/models/threat.py
──────────────────────────
Core data models for threats and security events.
Everything flows through these Pydantic models — scanner output,
AI analysis, API responses — all use the same shapes.
"""

from __future__ import annotations
from enum import Enum
from datetime import datetime
from typing import Optional, Dict, List
from pydantic import BaseModel, Field
import uuid


class Severity(str, Enum):
    """Threat severity levels — used for triage and alerting."""
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class ThreatCategory(str, Enum):
    """What kind of threat was detected."""
    SENSITIVE_DATA_EXPOSED  = "sensitive_data_exposed"   # PII, credentials found in plain text
    ANOMALOUS_BEHAVIOR      = "anomalous_behavior"        # Unusual access pattern
    POLICY_VIOLATION        = "policy_violation"          # Config / compliance issue
    AI_DATA_LEAK            = "ai_data_leak"              # Data flowed to an AI model without approval
    UNAUTHORIZED_ACCESS     = "unauthorized_access"        # Access to restricted resource
    VULNERABILITY           = "vulnerability"              # Known CVE or weak config


class ThreatEvent(BaseModel):
    """
    A single security finding produced by any scanner.
    This is the atomic unit that flows through the entire system.
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # What happened
    category: ThreatCategory
    severity: Severity
    title: str
    description: str

    # Where it happened
    source: str          # e.g. "file_scanner", "network_monitor"
    location: str        # e.g. file path, hostname, endpoint
    raw_evidence: str    # the actual fragment that triggered this finding

    # AI analysis (filled in by Co-Pilot after detection)
    ai_summary: Optional[str] = None          # Plain-language explanation
    ai_recommendation: Optional[str] = None   # What to do about it
    ai_risk_score: Optional[int] = None       # 1–10

    # State
    resolved: bool = False
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None

    def is_urgent(self) -> bool:
        return self.severity in (Severity.CRITICAL, Severity.HIGH)


class ScanSummary(BaseModel):
    """Aggregated result of one full scan cycle."""
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    started_at: datetime
    finished_at: datetime
    scanner_name: str
    total_files_scanned: int = 0
    total_threats_found: int = 0
    threats_by_severity: dict[str, int] = Field(default_factory=dict)
    events: list[ThreatEvent] = Field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()

    def add_event(self, event: ThreatEvent) -> None:
        self.events.append(event)
        self.total_threats_found += 1
        self.threats_by_severity[event.severity.value] = (
            self.threats_by_severity.get(event.severity.value, 0) + 1
        )


# ════════════════════════════════════════════════════════
# FILE: kubeforge/utils/logger.py
# ════════════════════════════════════════════════════════

"""
kubeforge/utils/logger.py
─────────────────────────
Structured logger for the entire platform.
Every log line is JSON — easy to ingest into ELK, Grafana Loki, etc.
"""

import structlog
import logging
import sys


def setup_logging(debug: bool = False) -> None:
    """Call once at startup to configure structlog."""
    level = logging.DEBUG if debug else logging.INFO

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=level,
    )

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str = "kubeforge"):
    """Return a bound logger with the given name."""
    return structlog.get_logger(name)


# ════════════════════════════════════════════════════════
# FILE: kubeforge/db/database.py
# ════════════════════════════════════════════════════════

"""
kubeforge/db/database.py
─────────────────────────
SQLite persistence layer for scan history.
Uses the built-in sqlite3 module — no extra dependencies.

Tables:
  scan_history   — one row per completed scan
  threat_events  — one row per threat, linked to scan_history
"""

import sqlite3
import json
import os
from pathlib import Path
from typing import Optional

from kubeforge.models.threat import ScanSummary, ThreatEvent
from kubeforge.utils.logger import get_logger

logger = get_logger("db")

# DB lives next to the project root
_DB_PATH = os.environ.get(
    "KUBEFORGE_DB_PATH",
    str(Path(__file__).parent.parent.parent / "kubeforge.db")
)

_CREATE_SCAN_HISTORY = """
CREATE TABLE IF NOT EXISTS scan_history (
    scan_id              TEXT PRIMARY KEY,
    scanner_name         TEXT NOT NULL,
    started_at           TEXT NOT NULL,
    finished_at          TEXT NOT NULL,
    duration_seconds     REAL NOT NULL,
    total_files_scanned  INTEGER NOT NULL,
    total_threats_found  INTEGER NOT NULL,
    threats_by_severity  TEXT NOT NULL   -- JSON
);
"""

_CREATE_THREAT_EVENTS = """
CREATE TABLE IF NOT EXISTS threat_events (
    id               TEXT PRIMARY KEY,
    scan_id          TEXT NOT NULL,
    timestamp        TEXT NOT NULL,
    category         TEXT NOT NULL,
    severity         TEXT NOT NULL,
    title            TEXT NOT NULL,
    description      TEXT NOT NULL,
    source           TEXT NOT NULL,
    location         TEXT NOT NULL,
    raw_evidence     TEXT NOT NULL,
    ai_summary       TEXT,
    ai_recommendation TEXT,
    ai_risk_score    INTEGER,
    FOREIGN KEY (scan_id) REFERENCES scan_history(scan_id)
);
"""


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create tables if they don't exist. Call once at startup."""
    with _get_conn() as conn:
        conn.execute(_CREATE_SCAN_HISTORY)
        conn.execute(_CREATE_THREAT_EVENTS)
        conn.commit()
    logger.info("db_initialized", path=_DB_PATH)


def save_scan(summary: ScanSummary) -> None:
    """Persist a completed ScanSummary to the database."""
    with _get_conn() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO scan_history
               (scan_id, scanner_name, started_at, finished_at,
                duration_seconds, total_files_scanned, total_threats_found, threats_by_severity)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                summary.scan_id,
                summary.scanner_name,
                summary.started_at.isoformat(),
                summary.finished_at.isoformat(),
                round(summary.duration_seconds, 3),
                summary.total_files_scanned,
                summary.total_threats_found,
                json.dumps(summary.threats_by_severity),
            ),
        )
        for event in summary.events:
            conn.execute(
                """INSERT OR REPLACE INTO threat_events
                   (id, scan_id, timestamp, category, severity, title, description,
                    source, location, raw_evidence, ai_summary, ai_recommendation, ai_risk_score)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event.id,
                    summary.scan_id,
                    event.timestamp.isoformat(),
                    event.category.value,
                    event.severity.value,
                    event.title,
                    event.description,
                    event.source,
                    event.location,
                    event.raw_evidence,
                    event.ai_summary,
                    event.ai_recommendation,
                    event.ai_risk_score,
                ),
            )
        conn.commit()
    logger.info("scan_saved", scan_id=summary.scan_id, threats=summary.total_threats_found)


def list_scans(limit: int = 50) -> list[dict]:
    """Return the most recent scans (without threats)."""
    with _get_conn() as conn:
        rows = conn.execute(
            """SELECT * FROM scan_history
               ORDER BY finished_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    return [
        {
            **dict(row),
            "threats_by_severity": json.loads(row["threats_by_severity"]),
        }
        for row in rows
    ]


def get_scan_threats(scan_id: str) -> list[dict]:
    """Return all threat events for a given scan_id."""
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM threat_events WHERE scan_id = ? ORDER BY severity",
            (scan_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_scan(scan_id: str) -> Optional[dict]:
    """Return a single scan summary."""
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM scan_history WHERE scan_id = ?", (scan_id,)
        ).fetchone()
    if not row:
        return None
    d = dict(row)
    d["threats_by_severity"] = json.loads(d["threats_by_severity"])
    return d


# ════════════════════════════════════════════════════════
# FILE: kubeforge/scanner/base.py
# ════════════════════════════════════════════════════════

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


# ════════════════════════════════════════════════════════
# FILE: kubeforge/scanner/data_scanner.py
# ════════════════════════════════════════════════════════

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


# ════════════════════════════════════════════════════════
# FILE: kubeforge/scanner/k8s_scanner.py
# ════════════════════════════════════════════════════════

"""
kubeforge/scanner/k8s_scanner.py
──────────────────────────────────
K8sScanner — scans Kubernetes YAML manifests and Dockerfiles for
security misconfigurations.

Kubernetes checks:
  • privileged containers
  • hostPID / hostNetwork / hostIPC
  • runAsRoot / missing runAsNonRoot
  • allowPrivilegeEscalation
  • missing resource limits
  • :latest image tag

Dockerfile checks:
  • running as root / missing USER directive
  • hardcoded secrets via ENV
  • remote ADD (ADD http://...)
  • --no-check-certificate
"""

import os
import re
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Iterator, List, Optional

from kubeforge.scanner.base import BaseScanner
from kubeforge.models.threat import ScanSummary, ThreatEvent, Severity, ThreatCategory
from kubeforge.config import settings
from kubeforge.utils.logger import get_logger

logger = get_logger("scanner.k8s")


# ── Kubernetes YAML patterns ──────────────────────────────────────────────────
K8S_PATTERNS: list[dict] = [
    {
        "name": "Privileged Container",
        "regex": r"privileged\s*:\s*true",
        "severity": Severity.CRITICAL,
        "description": "Container runs in privileged mode — full host access.",
    },
    {
        "name": "Host PID Namespace",
        "regex": r"hostPID\s*:\s*true",
        "severity": Severity.HIGH,
        "description": "Pod shares host PID namespace — can see/kill host processes.",
    },
    {
        "name": "Host Network",
        "regex": r"hostNetwork\s*:\s*true",
        "severity": Severity.HIGH,
        "description": "Pod shares host network — bypasses network policies.",
    },
    {
        "name": "Host IPC",
        "regex": r"hostIPC\s*:\s*true",
        "severity": Severity.HIGH,
        "description": "Pod shares host IPC namespace.",
    },
    {
        "name": "Running as Root (runAsUser: 0)",
        "regex": r"runAsUser\s*:\s*0",
        "severity": Severity.HIGH,
        "description": "Container explicitly runs as root user (UID 0).",
    },
    {
        "name": "runAsNonRoot disabled",
        "regex": r"runAsNonRoot\s*:\s*false",
        "severity": Severity.HIGH,
        "description": "runAsNonRoot is explicitly set to false.",
    },
    {
        "name": "Allow Privilege Escalation",
        "regex": r"allowPrivilegeEscalation\s*:\s*true",
        "severity": Severity.HIGH,
        "description": "Container can gain more privileges than its parent process.",
    },
    {
        "name": "Hardcoded Secret in K8s Manifest",
        "regex": r"(?i)(password|secret|token|api[_\-]?key)\s*:\s*['\"]?[A-Za-z0-9+/=\-_]{8,}['\"]?",
        "severity": Severity.CRITICAL,
        "description": "Possible hardcoded secret found in Kubernetes manifest.",
    },
    {
        "name": "Image using :latest tag",
        "regex": r"image\s*:\s*[^\s]+:latest",
        "severity": Severity.LOW,
        "description": "Using :latest tag makes deployments non-reproducible.",
    },
    {
        "name": "Writable Root Filesystem",
        "regex": r"readOnlyRootFilesystem\s*:\s*false",
        "severity": Severity.MEDIUM,
        "description": "Container root filesystem is writable — increases attack surface.",
    },
]

# ── Dockerfile patterns ───────────────────────────────────────────────────────
DOCKER_PATTERNS: list[dict] = [
    {
        "name": "Running as Root in Dockerfile",
        "regex": r"^USER\s+root",
        "severity": Severity.HIGH,
        "description": "Dockerfile explicitly sets USER to root.",
        "multiline": True,
    },
    {
        "name": "Hardcoded Secret via ENV",
        "regex": r"(?i)^ENV\s+.*(password|secret|token|api[_\-]?key)\s*[=\s]\s*\S+",
        "severity": Severity.CRITICAL,
        "description": "Secret baked into image via ENV instruction.",
        "multiline": True,
    },
    {
        "name": "Remote ADD (prefer COPY)",
        "regex": r"^ADD\s+https?://",
        "severity": Severity.MEDIUM,
        "description": "ADD with a remote URL — use COPY + curl with checksum instead.",
        "multiline": True,
    },
    {
        "name": "Skipping TLS verification",
        "regex": r"--no-check-certificate|--insecure|-k\s",
        "severity": Severity.HIGH,
        "description": "TLS verification disabled — vulnerable to MITM attacks.",
    },
    {
        "name": "apt-get without --no-install-recommends",
        "regex": r"apt-get install(?!.*--no-install-recommends)",
        "severity": Severity.LOW,
        "description": "Installs unnecessary packages — increases image size and attack surface.",
    },
    {
        "name": "Pinned package version missing",
        "regex": r"apt-get install\s+[a-z][\w\-]+((?!\=).)*$",
        "severity": Severity.LOW,
        "description": "Package versions not pinned — builds may be non-reproducible.",
        "multiline": True,
    },
]

# File patterns for K8s
K8S_EXTENSIONS = {".yaml", ".yml"}
K8S_KEYWORDS   = re.compile(r"(apiVersion|kind\s*:|spec\s*:|containers\s*:)", re.IGNORECASE)

# File patterns for Docker
DOCKER_NAMES = re.compile(r"^(Dockerfile|dockerfile)([\.\-].+)?$", re.IGNORECASE)
DOCKER_EXTENSIONS = {".dockerfile"}

SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv"}


class K8sScanner(BaseScanner):
    """Scans Kubernetes manifests and Dockerfiles for security issues."""

    name = "k8s_scanner"

    def __init__(self, target_paths: Optional[List[str]] = None):
        super().__init__()
        self.target_paths = target_paths or settings.scan_target_paths
        self.max_file_bytes = settings.max_file_size_mb * 1024 * 1024

        self._k8s_compiled = [
            {**p, "compiled": re.compile(p["regex"], re.MULTILINE | re.IGNORECASE)}
            for p in K8S_PATTERNS
        ]
        self._docker_compiled = [
            {**p, "compiled": re.compile(p["regex"], re.MULTILINE | re.IGNORECASE)}
            for p in DOCKER_PATTERNS
        ]

    def _is_k8s_file(self, path: Path) -> bool:
        if path.suffix.lower() not in K8S_EXTENSIONS:
            return False
        try:
            head = path.read_text(encoding="utf-8", errors="ignore")[:500]
            return bool(K8S_KEYWORDS.search(head))
        except Exception:
            return False

    def _is_docker_file(self, path: Path) -> bool:
        return (
            bool(DOCKER_NAMES.match(path.name))
            or path.suffix.lower() in DOCKER_EXTENSIONS
        )

    def _iter_files(self, root: str) -> Iterator[tuple[Path, str]]:
        """Yield (path, file_type) tuples."""
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for filename in filenames:
                path = Path(dirpath) / filename
                try:
                    if path.stat().st_size > self.max_file_bytes:
                        continue
                except OSError:
                    continue
                if self._is_docker_file(path):
                    yield path, "docker"
                elif self._is_k8s_file(path):
                    yield path, "k8s"

    def _scan_file(self, path: Path, file_type: str) -> list[ThreatEvent]:
        events = []
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception as exc:
            logger.warning("file_read_error", path=str(path), error=str(exc))
            return events

        patterns = self._k8s_compiled if file_type == "k8s" else self._docker_compiled

        for pattern in patterns:
            for match in pattern["compiled"].finditer(content):
                line_no = content[: match.start()].count("\n") + 1
                evidence = match.group(0)[:120]
                events.append(ThreatEvent(
                    category=ThreatCategory.POLICY_VIOLATION,
                    severity=pattern["severity"],
                    title=f"{pattern['name']} [{file_type.upper()}]",
                    description=pattern["description"],
                    source=self.name,
                    location=f"{path}:{line_no}",
                    raw_evidence=evidence,
                ))
        return events

    async def scan(self) -> ScanSummary:
        summary = ScanSummary(
            started_at=datetime.utcnow(),
            finished_at=datetime.utcnow(),
            scanner_name=self.name,
        )

        for root in self.target_paths:
            if not os.path.exists(root):
                logger.warning("scan_path_not_found", path=root)
                continue

            loop = asyncio.get_event_loop()
            files = list(self._iter_files(root))
            summary.total_files_scanned += len(files)

            for path, file_type in files:
                events = await loop.run_in_executor(
                    None, self._scan_file, path, file_type
                )
                for event in events:
                    summary.add_event(event)
                    logger.info(
                        "k8s_threat_detected",
                        severity=event.severity.value,
                        title=event.title,
                        location=event.location,
                    )

        return summary


# ════════════════════════════════════════════════════════
# FILE: kubeforge/scanner/deps_scanner.py
# ════════════════════════════════════════════════════════

"""
kubeforge/scanner/deps_scanner.py
───────────────────────────────────
DepsScanner — checks npm and pip packages for known CVE vulnerabilities.

npm:  runs `npm audit --json` on any directory containing package.json
pip:  runs `pip3 audit` (pip-audit) on any requirements.txt found

Both tools must be installed on the system. If they're missing, the scanner
logs a warning and skips gracefully — it never crashes the platform.
"""

import os
import json
import asyncio
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional, List

from kubeforge.scanner.base import BaseScanner
from kubeforge.models.threat import ScanSummary, ThreatEvent, Severity, ThreatCategory
from kubeforge.config import settings
from kubeforge.utils.logger import get_logger

logger = get_logger("scanner.deps")

SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv"}


def _npm_severity(sev: str) -> Severity:
    return {
        "critical": Severity.CRITICAL,
        "high":     Severity.HIGH,
        "moderate": Severity.MEDIUM,
        "low":      Severity.LOW,
        "info":     Severity.INFO,
    }.get(sev.lower(), Severity.MEDIUM)


class DepsScanner(BaseScanner):
    """Scans npm and pip dependency files for known CVEs."""

    name = "deps_scanner"

    def __init__(self, target_paths: Optional[List[str]] = None):
        super().__init__()
        self.target_paths = target_paths or settings.scan_target_paths

    # ── File discovery ──────────────────────────────────────────────────────

    def _find_files(self, root: str):
        """Yield (path, file_type) for package.json and requirements.txt files."""
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                if name == "package.json":
                    yield Path(dirpath) / name, "npm"
                elif name in ("requirements.txt", "requirements-dev.txt"):
                    yield Path(dirpath) / name, "pip"

    # ── npm audit ──────────────────────────────────────────────────────────

    def _scan_npm(self, package_json: Path) -> list[ThreatEvent]:
        """Run npm audit in the directory containing package.json."""
        project_dir = str(package_json.parent)
        events = []

        try:
            result = subprocess.run(
                ["npm", "audit", "--json"],
                cwd=project_dir,
                capture_output=True,
                text=True,
                timeout=60,
            )
            data = json.loads(result.stdout or "{}")
        except FileNotFoundError:
            logger.warning("npm_not_found")
            return events
        except (subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
            logger.warning("npm_audit_error", error=str(exc))
            return events

        # npm audit v7+ format
        vulns = data.get("vulnerabilities", {})
        for pkg_name, vuln in vulns.items():
            sev = vuln.get("severity", "low")
            via = vuln.get("via", [])
            cve_list = [v.get("url", "") for v in via if isinstance(v, dict)]
            title_detail = via[0].get("title", "") if via and isinstance(via[0], dict) else ""

            events.append(ThreatEvent(
                category=ThreatCategory.VULNERABILITY,
                severity=_npm_severity(sev),
                title=f"npm: {pkg_name} — {title_detail or sev + ' vulnerability'}",
                description=(
                    f"Package '{pkg_name}' has a {sev} severity vulnerability. "
                    f"CVE: {', '.join(cve_list) or 'unknown'}"
                ),
                source=self.name,
                location=str(package_json),
                raw_evidence=f"{pkg_name}@{vuln.get('range', '?')} ({sev})",
            ))
        return events

    # ── pip audit ──────────────────────────────────────────────────────────

    def _scan_pip(self, requirements_txt: Path) -> list[ThreatEvent]:
        """Run pip-audit on a requirements.txt file."""
        events = []

        try:
            result = subprocess.run(
                ["pip-audit", "--requirement", str(requirements_txt),
                 "--format", "json", "--skip-editable"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            data = json.loads(result.stdout or "[]")
        except FileNotFoundError:
            # pip-audit not installed — try pip3 audit fallback
            logger.warning("pip_audit_not_found", hint="pip install pip-audit")
            return events
        except (subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
            logger.warning("pip_audit_error", error=str(exc))
            return events

        for pkg in data:
            for vuln in pkg.get("vulns", []):
                events.append(ThreatEvent(
                    category=ThreatCategory.VULNERABILITY,
                    severity=Severity.HIGH,
                    title=f"pip: {pkg.get('name')} {pkg.get('version')} — {vuln.get('id')}",
                    description=vuln.get("description", "Known vulnerability in dependency."),
                    source=self.name,
                    location=str(requirements_txt),
                    raw_evidence=f"{pkg.get('name')}=={pkg.get('version')} ({vuln.get('id')})",
                ))
        return events

    # ── Main scan ──────────────────────────────────────────────────────────

    async def scan(self) -> ScanSummary:
        summary = ScanSummary(
            started_at=datetime.utcnow(),
            finished_at=datetime.utcnow(),
            scanner_name=self.name,
        )

        loop = asyncio.get_event_loop()

        for root in self.target_paths:
            if not os.path.exists(root):
                continue

            for path, file_type in self._find_files(root):
                summary.total_files_scanned += 1

                if file_type == "npm":
                    events = await loop.run_in_executor(None, self._scan_npm, path)
                else:
                    events = await loop.run_in_executor(None, self._scan_pip, path)

                for event in events:
                    summary.add_event(event)
                    logger.info(
                        "dep_vulnerability_found",
                        severity=event.severity.value,
                        title=event.title,
                    )

        return summary


# ════════════════════════════════════════════════════════
# FILE: kubeforge/scanner/network_scanner.py
# ════════════════════════════════════════════════════════

"""
kubeforge/scanner/network_scanner.py
──────────────────────────────────────
NetworkScanner — scans hosts for open ports and flags risky services.

Checks common dangerous ports:
  22   SSH
  23   Telnet (unencrypted)
  3306 MySQL exposed
  5432 PostgreSQL exposed
  6379 Redis (no auth by default)
  27017 MongoDB (no auth by default)
  9200 Elasticsearch (no auth by default)
  8080/8443 Admin panels
  2375/2376 Docker daemon (critical if exposed)
  10250 Kubernetes kubelet API
  etcd 2379/2380
"""

import asyncio
import socket
from datetime import datetime
from typing import Optional, List

from kubeforge.scanner.base import BaseScanner
from kubeforge.models.threat import ScanSummary, ThreatEvent, Severity, ThreatCategory
from kubeforge.config import settings
from kubeforge.utils.logger import get_logger

logger = get_logger("scanner.network")

RISKY_PORTS: list[dict] = [
    {"port": 23,    "name": "Telnet",               "severity": Severity.CRITICAL,
     "description": "Telnet is unencrypted — credentials sent in plain text."},
    {"port": 2375,  "name": "Docker Daemon (HTTP)",  "severity": Severity.CRITICAL,
     "description": "Docker daemon exposed without TLS — full container/host control."},
    {"port": 2376,  "name": "Docker Daemon (TLS)",   "severity": Severity.HIGH,
     "description": "Docker daemon exposed with TLS — verify access control."},
    {"port": 6379,  "name": "Redis",                 "severity": Severity.CRITICAL,
     "description": "Redis exposed — often runs without authentication by default."},
    {"port": 27017, "name": "MongoDB",               "severity": Severity.CRITICAL,
     "description": "MongoDB exposed — may be accessible without authentication."},
    {"port": 9200,  "name": "Elasticsearch",         "severity": Severity.CRITICAL,
     "description": "Elasticsearch exposed — data readable without authentication."},
    {"port": 2379,  "name": "etcd",                  "severity": Severity.CRITICAL,
     "description": "etcd exposed — contains Kubernetes secrets and config."},
    {"port": 2380,  "name": "etcd peer",             "severity": Severity.HIGH,
     "description": "etcd peer port exposed."},
    {"port": 10250, "name": "Kubernetes Kubelet API","severity": Severity.CRITICAL,
     "description": "Kubelet API exposed — can execute commands in any pod."},
    {"port": 10255, "name": "Kubernetes Kubelet (read-only)", "severity": Severity.HIGH,
     "description": "Kubelet read-only port exposed — leaks pod/node info."},
    {"port": 3306,  "name": "MySQL",                 "severity": Severity.HIGH,
     "description": "MySQL database port exposed to network."},
    {"port": 5432,  "name": "PostgreSQL",            "severity": Severity.HIGH,
     "description": "PostgreSQL database port exposed to network."},
    {"port": 1433,  "name": "MSSQL",                 "severity": Severity.HIGH,
     "description": "SQL Server port exposed to network."},
    {"port": 5984,  "name": "CouchDB",               "severity": Severity.HIGH,
     "description": "CouchDB exposed — may be accessible without authentication."},
    {"port": 8500,  "name": "Consul",                "severity": Severity.HIGH,
     "description": "HashiCorp Consul API exposed."},
    {"port": 4848,  "name": "GlassFish Admin",       "severity": Severity.HIGH,
     "description": "GlassFish admin console exposed."},
    {"port": 8080,  "name": "HTTP Alt / Admin Panel", "severity": Severity.MEDIUM,
     "description": "Alternative HTTP port open — may expose admin panel."},
    {"port": 8443,  "name": "HTTPS Alt / Admin Panel","severity": Severity.MEDIUM,
     "description": "Alternative HTTPS port open — may expose admin panel."},
    {"port": 22,    "name": "SSH",                   "severity": Severity.LOW,
     "description": "SSH port open — ensure key-based auth and no root login."},
    {"port": 21,    "name": "FTP",                   "severity": Severity.HIGH,
     "description": "FTP is unencrypted — use SFTP instead."},
    {"port": 25,    "name": "SMTP",                  "severity": Severity.MEDIUM,
     "description": "SMTP port open — verify relay restrictions."},
]

DEFAULT_TIMEOUT = 1.5  # seconds per port


async def _check_port(host: str, port: int, timeout: float) -> bool:
    """Return True if the port is open."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


class NetworkScanner(BaseScanner):
    """Scans hosts for open risky ports."""

    name = "network_scanner"

    def __init__(self, hosts: Optional[List[str]] = None):
        super().__init__()
        self.hosts = hosts or settings.network_scan_hosts

    async def scan(self) -> ScanSummary:
        summary = ScanSummary(
            started_at=datetime.utcnow(),
            finished_at=datetime.utcnow(),
            scanner_name=self.name,
        )

        if not self.hosts:
            logger.info("network_scan_skipped", reason="no hosts configured")
            return summary

        for host in self.hosts:
            logger.info("network_scanning_host", host=host)
            summary.total_files_scanned += 1  # reuse counter for hosts

            # Check all risky ports concurrently
            tasks = [
                _check_port(host, p["port"], DEFAULT_TIMEOUT)
                for p in RISKY_PORTS
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for port_def, is_open in zip(RISKY_PORTS, results):
                if is_open is True:
                    event = ThreatEvent(
                        category=ThreatCategory.POLICY_VIOLATION,
                        severity=port_def["severity"],
                        title=f"Open Port: {port_def['name']} ({port_def['port']})",
                        description=port_def["description"],
                        source=self.name,
                        location=f"{host}:{port_def['port']}",
                        raw_evidence=f"{host}:{port_def['port']} is OPEN",
                    )
                    summary.add_event(event)
                    logger.info(
                        "open_port_found",
                        host=host,
                        port=port_def["port"],
                        service=port_def["name"],
                        severity=port_def["severity"].value,
                    )

        return summary


# ════════════════════════════════════════════════════════
# FILE: kubeforge/scanner/git_history_scanner.py
# ════════════════════════════════════════════════════════

"""
kubeforge/scanner/git_history_scanner.py
──────────────────────────────────────────
GitHistoryScanner — scans git commit history for secrets that were
committed and later deleted (the classic "oops I pushed my API key" scenario).

Uses `git log -p` to get all diffs and applies the same regex patterns
as DataScanner to every added line (+) in the history.
"""

import re
import subprocess
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional

from kubeforge.scanner.base import BaseScanner
from kubeforge.scanner.data_scanner import PATTERNS
from kubeforge.models.threat import ScanSummary, ThreatEvent, Severity, ThreatCategory
from kubeforge.utils.logger import get_logger

logger = get_logger("scanner.git_history")

COMPILED = [
    {**p, "compiled": re.compile(p["regex"], re.IGNORECASE)}
    for p in PATTERNS
]


class GitHistoryScanner(BaseScanner):
    """Scans git commit history for secrets in added lines."""

    name = "git_history_scanner"

    def __init__(self, repo_path: Optional[str] = None):
        super().__init__()
        self.repo_path = repo_path or "."

    def _get_git_log(self) -> Optional[str]:
        """Run git log -p and return the full diff output."""
        try:
            result = subprocess.run(
                ["git", "log", "--all", "-p",
                 "--diff-filter=A,M",   # added/modified only
                 "--no-merges",
                 "--format=COMMIT:%H %s",
                 "--", "*.py", "*.js", "*.ts", "*.env", "*.json",
                       "*.yaml", "*.yml", "*.sh", "*.tf", "*.conf",
                       "*.cfg", "*.ini", "*.txt"],
                cwd=self.repo_path,
                capture_output=True, text=True, timeout=60,
            )
            if result.returncode != 0:
                logger.warning("git_log_failed", stderr=result.stderr[:200])
                return None
            return result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            logger.warning("git_not_available", error=str(exc))
            return None

    def _scan_diff(self, diff_output: str) -> list[ThreatEvent]:
        events = []
        current_commit = "unknown"
        current_file = "unknown"
        seen = set()  # deduplicate identical findings

        for line in diff_output.splitlines():
            if line.startswith("COMMIT:"):
                current_commit = line[7:].strip()
            elif line.startswith("+++ b/"):
                current_file = line[6:].strip()
            elif line.startswith("+") and not line.startswith("+++"):
                added_line = line[1:]  # strip the leading +

                for pattern in COMPILED:
                    for match in pattern["compiled"].finditer(added_line):
                        evidence = match.group(0)[:100]
                        dedup_key = (pattern["name"], evidence[:40])
                        if dedup_key in seen:
                            continue
                        seen.add(dedup_key)

                        events.append(ThreatEvent(
                            category=ThreatCategory.SENSITIVE_DATA_EXPOSED,
                            severity=pattern["severity"],
                            title=f"[GIT HISTORY] {pattern['name']} detected",
                            description=(
                                f"Secret found in git history — "
                                f"even if deleted from files, it remains in git log. "
                                f"Commit: {current_commit[:12]}"
                            ),
                            source=self.name,
                            location=f"{current_file} (commit {current_commit[:12]})",
                            raw_evidence=evidence,
                        ))
        return events

    async def scan(self) -> ScanSummary:
        summary = ScanSummary(
            started_at=datetime.utcnow(),
            finished_at=datetime.utcnow(),
            scanner_name=self.name,
        )

        if not Path(self.repo_path).joinpath(".git").exists():
            logger.info("not_a_git_repo", path=self.repo_path)
            return summary

        loop = asyncio.get_event_loop()
        diff_output = await loop.run_in_executor(None, self._get_git_log)

        if not diff_output:
            return summary

        summary.total_files_scanned = 1  # represents the git history
        events = await loop.run_in_executor(None, self._scan_diff, diff_output)
        for event in events:
            summary.add_event(event)
            logger.info(
                "git_history_threat",
                severity=event.severity.value,
                title=event.title,
            )

        return summary


# ════════════════════════════════════════════════════════
# FILE: kubeforge/scanner/github_scanner.py
# ════════════════════════════════════════════════════════

"""
kubeforge/scanner/github_scanner.py
─────────────────────────────────────
GitHubScanner — clones a public or private GitHub repo into a temp directory,
then runs DataScanner + K8sScanner + GitHistoryScanner on it.

Also scans git history for secrets that were committed and later deleted.
"""

import os
import shutil
import subprocess
import tempfile
import asyncio
from datetime import datetime
from typing import Optional

from kubeforge.scanner.base import BaseScanner
from kubeforge.scanner.data_scanner import DataScanner
from kubeforge.scanner.k8s_scanner import K8sScanner
from kubeforge.scanner.git_history_scanner import GitHistoryScanner
from kubeforge.models.threat import ScanSummary
from kubeforge.utils.logger import get_logger

logger = get_logger("scanner.github")


class GitHubScanner(BaseScanner):
    """
    Clones a GitHub repository and scans it for security issues.
    Supports public repos and private repos (via GITHUB_TOKEN env var).
    """

    name = "github_scanner"

    def __init__(self, repo_url: str, github_token: Optional[str] = None):
        super().__init__()
        self.repo_url = repo_url
        self.token = github_token or os.environ.get("GITHUB_TOKEN", "")
        self._tmp_dir: Optional[str] = None

    def _build_clone_url(self) -> str:
        """Inject token into URL for private repos."""
        if self.token and "github.com" in self.repo_url:
            # https://token@github.com/owner/repo.git
            return self.repo_url.replace(
                "https://", f"https://{self.token}@"
            )
        return self.repo_url

    def _clone(self, target_dir: str) -> bool:
        """Clone the repo. Returns True on success."""
        clone_url = self._build_clone_url()
        logger.info("cloning_repo", url=self.repo_url, target=target_dir)
        try:
            result = subprocess.run(
                ["git", "clone", "--depth", "50", clone_url, target_dir],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode != 0:
                logger.error("clone_failed", stderr=result.stderr[:300])
                return False
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            logger.error("clone_error", error=str(exc))
            return False

    def _merge_summaries(self, summaries: list[ScanSummary]) -> ScanSummary:
        merged = ScanSummary(
            started_at=min(s.started_at for s in summaries),
            finished_at=max(s.finished_at for s in summaries),
            scanner_name=self.name,
        )
        for s in summaries:
            merged.total_files_scanned += s.total_files_scanned
            for event in s.events:
                merged.add_event(event)
        return merged

    async def scan(self) -> ScanSummary:
        tmp_dir = tempfile.mkdtemp(prefix="kubeforge_github_")
        try:
            # Clone
            loop = asyncio.get_event_loop()
            cloned = await loop.run_in_executor(None, self._clone, tmp_dir)

            if not cloned:
                summary = ScanSummary(
                    started_at=datetime.utcnow(),
                    finished_at=datetime.utcnow(),
                    scanner_name=self.name,
                )
                return summary

            # Run all scanners on cloned repo
            paths = [tmp_dir]
            scanners = [
                DataScanner(target_paths=paths),
                K8sScanner(target_paths=paths),
                GitHistoryScanner(repo_path=tmp_dir),
            ]
            results = await asyncio.gather(
                *[s.run() for s in scanners],
                return_exceptions=True,
            )
            valid = [r for r in results if isinstance(r, ScanSummary)]
            if not valid:
                return ScanSummary(
                    started_at=datetime.utcnow(),
                    finished_at=datetime.utcnow(),
                    scanner_name=self.name,
                )
            return self._merge_summaries(valid)

        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            logger.info("temp_dir_cleaned", path=tmp_dir)


# ════════════════════════════════════════════════════════
# FILE: kubeforge/ai/copilot.py
# ════════════════════════════════════════════════════════

"""
kubeforge/ai/copilot.py
────────────────────────
The AI Co-Pilot — the brain of KubeForge.

Takes raw ThreatEvents from the scanner, sends them to the LLM,
and enriches each event with:
  • Plain-language summary
  • Risk explanation
  • Step-by-step recommendations
  • Numeric risk score (1–10)

Also produces executive summaries for full scan cycles.

Design principle: if OpenAI is unavailable, the platform keeps running —
we just skip AI enrichment and log a warning. Security never goes down
because the AI is slow or unreachable.
"""

import json
import asyncio
from typing import Optional

from openai import AsyncOpenAI, OpenAIError

from kubeforge.models.threat import ThreatEvent, ScanSummary
from kubeforge.ai.prompts import (
    SYSTEM_PROMPT_HE,
    SYSTEM_PROMPT_EN,
    THREAT_ANALYSIS_TEMPLATE,
    SCAN_SUMMARY_TEMPLATE,
)
from kubeforge.config import settings
from kubeforge.utils.logger import get_logger

logger = get_logger("ai.copilot")


class CoPilot:
    """
    AI Co-Pilot for KubeForge.
    Wraps OpenAI API calls with retry logic and graceful degradation.
    """

    def __init__(self):
        self._client: Optional[AsyncOpenAI] = None
        self._system_prompt = (
            SYSTEM_PROMPT_HE
            if settings.copilot_language == "hebrew"
            else SYSTEM_PROMPT_EN
        )
        self._enabled = bool(settings.openai_api_key)

        if not self._enabled:
            logger.warning("copilot_disabled", reason="OPENAI_API_KEY not set")

    @property
    def client(self) -> AsyncOpenAI:
        """Lazy-init the OpenAI client."""
        if self._client is None:
            self._client = AsyncOpenAI(api_key=settings.openai_api_key)
        return self._client

    async def _call_llm(self, user_message: str, max_tokens: int = 500) -> Optional[str]:
        """
        Low-level LLM call with error handling.
        Returns the response text or None on failure.
        """
        if not self._enabled:
            return None

        try:
            response = await self.client.chat.completions.create(
                model=settings.openai_model,
                messages=[
                    {"role": "system", "content": self._system_prompt},
                    {"role": "user", "content": user_message},
                ],
                max_tokens=max_tokens,
                temperature=0.2,  # low temperature = more consistent, factual answers
            )
            return response.choices[0].message.content

        except OpenAIError as exc:
            logger.error("openai_call_failed", error=str(exc))
            return None

    async def analyze_threat(self, event: ThreatEvent) -> ThreatEvent:
        """
        Enrich a ThreatEvent with AI analysis.
        Modifies the event in place and returns it.
        """
        prompt = THREAT_ANALYSIS_TEMPLATE.format(
            title=event.title,
            category=event.category.value,
            severity=event.severity.value,
            location=event.location,
            raw_evidence=event.raw_evidence[:200],  # don't send too much to LLM
            description=event.description,
        )

        raw_response = await self._call_llm(prompt, max_tokens=600)
        if not raw_response:
            return event

        try:
            # Strip markdown code fences if the LLM added them
            clean = raw_response.strip().removeprefix("```json").removesuffix("```").strip()
            data = json.loads(clean)

            event.ai_summary = data.get("summary", "")
            event.ai_recommendation = "\n".join(data.get("recommendations", []))
            event.ai_risk_score = int(data.get("risk_score", 5))

            logger.info(
                "threat_analyzed",
                event_id=event.id,
                risk_score=event.ai_risk_score,
            )

        except (json.JSONDecodeError, ValueError) as exc:
            logger.warning("copilot_parse_error", error=str(exc), raw=raw_response[:200])

        return event

    async def analyze_scan(self, summary: ScanSummary) -> str:
        """
        Generate an executive summary for a completed scan cycle.
        Returns the summary text (or an empty string if AI is unavailable).
        """
        prompt = SCAN_SUMMARY_TEMPLATE.format(
            total_files=summary.total_files_scanned,
            total_threats=summary.total_threats_found,
            by_severity=json.dumps(summary.threats_by_severity, ensure_ascii=False),
            duration=round(summary.duration_seconds, 1),
        )

        result = await self._call_llm(prompt, max_tokens=300)
        return result or "AI summary unavailable — check OPENAI_API_KEY configuration."

    async def enrich_summary(self, summary: ScanSummary) -> ScanSummary:
        """
        Enrich all high/critical events in a summary with AI analysis.
        Runs analyses concurrently for speed.
        """
        urgent_events = [e for e in summary.events if e.is_urgent()]

        if urgent_events:
            logger.info("enriching_events", count=len(urgent_events))
            tasks = [self.analyze_threat(event) for event in urgent_events]
            await asyncio.gather(*tasks)

        return summary


# Singleton
copilot = CoPilot()


# ════════════════════════════════════════════════════════
# FILE: kubeforge/ai/prompts.py
# ════════════════════════════════════════════════════════

"""
kubeforge/ai/prompts.py
────────────────────────
Prompt templates for the AI Co-Pilot.
Keeping prompts in one place makes it easy to tune them
without touching business logic.
"""

SYSTEM_PROMPT_HE = """
אתה Co-Pilot אבטחת מידע של KubeForge.
תפקידך לנתח ממצאי אבטחה ולהסביר אותם בצורה פשוטה וברורה לאנשי IT שאינם מומחי סייבר.
תמיד ענה בעברית.
היה תמציתי, ברור ומעשי.
הסבר מה קרה, למה זה מסוכן, ומה לעשות עכשיו.
"""

SYSTEM_PROMPT_EN = """
You are the KubeForge Security AI Co-Pilot.
Your role is to analyze security findings and explain them in plain language
to IT staff who are not cybersecurity experts.
Always answer in English.
Be concise, clear, and actionable.
Explain what happened, why it matters, and what to do now.
"""

THREAT_ANALYSIS_TEMPLATE = """
ממצא אבטחה שזוהה:
- כותרת: {title}
- קטגוריה: {category}
- חומרה: {severity}
- מיקום: {location}
- עדות גולמית: {raw_evidence}
- תיאור: {description}

אנא ספק:
1. סיכום קצר (2-3 משפטים) — מה קרה בפועל
2. למה זה מסוכן לארגון
3. שלושה צעדי תיקון מדויקים ומיידיים
4. ציון סיכון מ-1 עד 10

החזר תשובה בפורמט JSON בלבד:
{{
  "summary": "...",
  "risk_explanation": "...",
  "recommendations": ["צעד 1", "צעד 2", "צעד 3"],
  "risk_score": 8
}}
"""

SCAN_SUMMARY_TEMPLATE = """
סריקה הושלמה. להלן הממצאים:
- סה"כ קבצים שנסרקו: {total_files}
- סה"כ איומים שזוהו: {total_threats}
- לפי חומרה: {by_severity}
- זמן הסריקה: {duration} שניות

אנא ספק סיכום מנהלים קצר (3-4 משפטים) שמסביר את מצב האבטחה הכולל
ואת הפעולות הדחופות ביותר שיש לנקוט.
"""


# ════════════════════════════════════════════════════════
# FILE: kubeforge/alerts/slack.py
# ════════════════════════════════════════════════════════

"""
kubeforge/alerts/slack.py
──────────────────────────
Slack alerting — sends a webhook message when critical/high threats are found.
Set SLACK_WEBHOOK_URL in .env to enable.
"""

import httpx
from kubeforge.models.threat import ScanSummary, Severity
from kubeforge.config import settings
from kubeforge.utils.logger import get_logger

logger = get_logger("alerts.slack")


def _severity_emoji(severity: str) -> str:
    return {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(severity, "⚪")


async def send_scan_alert(summary: ScanSummary) -> None:
    """Send a Slack alert if critical or high threats were found."""
    if not settings.slack_webhook_url:
        return

    urgent = [e for e in summary.events if e.severity in (Severity.CRITICAL, Severity.HIGH)]
    if not urgent:
        return

    sev = summary.threats_by_severity
    lines = [
        f"*🛡️ KubeForge — Security Alert*",
        f"Scan `{summary.scan_id[:8]}...` found *{summary.total_threats_found} threats* "
        f"in {summary.total_files_scanned} files.",
        "",
        f"🔴 Critical: {sev.get('critical', 0)}  |  🟠 High: {sev.get('high', 0)}  |  "
        f"🟡 Medium: {sev.get('medium', 0)}",
        "",
        "*Top findings:*",
    ]

    for event in urgent[:5]:
        lines.append(
            f"{_severity_emoji(event.severity.value)} `{event.title}` — {event.location}"
        )

    if len(urgent) > 5:
        lines.append(f"_...and {len(urgent) - 5} more_")

    payload = {"text": "\n".join(lines)}

    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.post(settings.slack_webhook_url, json=payload)
            resp.raise_for_status()
        logger.info("slack_alert_sent", threats=len(urgent))
    except Exception as exc:
        logger.error("slack_alert_failed", error=str(exc))


# ════════════════════════════════════════════════════════
# FILE: kubeforge/scheduler.py
# ════════════════════════════════════════════════════════

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


# ════════════════════════════════════════════════════════
# FILE: kubeforge/api/app.py
# ════════════════════════════════════════════════════════

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


# ════════════════════════════════════════════════════════
# FILE: kubeforge/api/routes/scan.py
# ════════════════════════════════════════════════════════

"""
kubeforge/api/routes/scan.py
─────────────────────────────
Scan endpoints — trigger a scan and retrieve results.
Runs all scanners in parallel and merges results.
Saves every completed scan to SQLite for history.
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional
import asyncio

from kubeforge.scanner.data_scanner import DataScanner
from kubeforge.scanner.k8s_scanner import K8sScanner
from kubeforge.scanner.deps_scanner import DepsScanner
from kubeforge.scanner.network_scanner import NetworkScanner
from kubeforge.scanner.git_history_scanner import GitHistoryScanner
from kubeforge.scanner.github_scanner import GitHubScanner
from kubeforge.ai.copilot import copilot
from kubeforge.models.threat import ScanSummary
from kubeforge.db import database as db
from kubeforge.alerts.slack import send_scan_alert
from kubeforge.utils.logger import get_logger

router = APIRouter()
logger = get_logger("api.scan")

_latest_summary: Optional[ScanSummary] = None
_scan_lock = asyncio.Lock()


class ScanRequest(BaseModel):
    paths: Optional[list[str]] = None
    hosts: Optional[list[str]] = None        # for network scan
    enrich_with_ai: bool = True
    scan_git_history: bool = True


class GitHubScanRequest(BaseModel):
    repo_url: str
    github_token: Optional[str] = None
    enrich_with_ai: bool = True


class ScanStatusResponse(BaseModel):
    scan_id: str
    scanner_name: str
    started_at: str
    finished_at: str
    duration_seconds: float
    total_files_scanned: int
    total_threats_found: int
    threats_by_severity: dict
    ai_executive_summary: Optional[str] = None


def _merge_summaries(summaries: list[ScanSummary]) -> ScanSummary:
    if len(summaries) == 1:
        summaries[0].scanner_name = "multi_scanner"
        return summaries[0]
    merged = ScanSummary(
        started_at=min(s.started_at for s in summaries),
        finished_at=max(s.finished_at for s in summaries),
        scanner_name="multi_scanner",
    )
    for s in summaries:
        merged.total_files_scanned += s.total_files_scanned
        for event in s.events:
            merged.add_event(event)
    return merged


async def _run_scan(
    paths: Optional[list[str]],
    enrich_with_ai: bool,
    hosts: Optional[list[str]] = None,
    scan_git_history: bool = True,
):
    global _latest_summary

    async with _scan_lock:
        scanners = [
            DataScanner(target_paths=paths),
            K8sScanner(target_paths=paths),
            DepsScanner(target_paths=paths),
            NetworkScanner(hosts=hosts),
        ]

        # Add git history scanner for each path
        if scan_git_history and paths:
            for path in paths:
                scanners.append(GitHistoryScanner(repo_path=path))
        elif scan_git_history:
            scanners.append(GitHistoryScanner())

        results = await asyncio.gather(
            *[s.run() for s in scanners],
            return_exceptions=True,
        )

        summaries = [r for r in results if isinstance(r, ScanSummary)]
        if not summaries:
            logger.error("all_scanners_failed")
            return

        summary = _merge_summaries(summaries)

        if enrich_with_ai and summary.total_threats_found > 0:
            summary = await copilot.enrich_summary(summary)

        _latest_summary = summary
        db.save_scan(summary)
        logger.info("scan_stored", scan_id=summary.scan_id, threats=summary.total_threats_found)
        await send_scan_alert(summary)


async def _run_github_scan(repo_url: str, github_token: Optional[str], enrich_with_ai: bool):
    global _latest_summary

    async with _scan_lock:
        scanner = GitHubScanner(repo_url=repo_url, github_token=github_token)
        summary = await scanner.run()

        if enrich_with_ai and summary.total_threats_found > 0:
            summary = await copilot.enrich_summary(summary)

        _latest_summary = summary
        db.save_scan(summary)
        logger.info("github_scan_stored", repo=repo_url, threats=summary.total_threats_found)
        await send_scan_alert(summary)


@router.post("/scan", tags=["Scanner"])
async def trigger_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Trigger a full scan in the background."""
    background_tasks.add_task(
        _run_scan,
        paths=request.paths,
        enrich_with_ai=request.enrich_with_ai,
        hosts=request.hosts,
        scan_git_history=request.scan_git_history,
    )
    return {"message": "Scan started", "poll_url": "/api/v1/scan/latest"}


@router.post("/scan/github", tags=["Scanner"])
async def trigger_github_scan(request: GitHubScanRequest, background_tasks: BackgroundTasks):
    """Clone and scan a GitHub repository."""
    background_tasks.add_task(
        _run_github_scan,
        repo_url=request.repo_url,
        github_token=request.github_token,
        enrich_with_ai=request.enrich_with_ai,
    )
    return {"message": "GitHub scan started", "repo": request.repo_url, "poll_url": "/api/v1/scan/latest"}


@router.get("/scan/latest", response_model=ScanStatusResponse, tags=["Scanner"])
async def get_latest_scan():
    if _latest_summary is None:
        raise HTTPException(status_code=404, detail="No scan has been run yet.")
    return ScanStatusResponse(
        scan_id=_latest_summary.scan_id,
        scanner_name=_latest_summary.scanner_name,
        started_at=_latest_summary.started_at.isoformat(),
        finished_at=_latest_summary.finished_at.isoformat(),
        duration_seconds=round(_latest_summary.duration_seconds, 2),
        total_files_scanned=_latest_summary.total_files_scanned,
        total_threats_found=_latest_summary.total_threats_found,
        threats_by_severity=_latest_summary.threats_by_severity,
    )


@router.get("/scan/latest/threats", tags=["Scanner"])
async def get_latest_threats():
    if _latest_summary is None:
        raise HTTPException(status_code=404, detail="No scan has been run yet.")
    return {
        "scan_id": _latest_summary.scan_id,
        "total": _latest_summary.total_threats_found,
        "threats": [e.model_dump() for e in _latest_summary.events],
    }


# ════════════════════════════════════════════════════════
# FILE: kubeforge/api/routes/history.py
# ════════════════════════════════════════════════════════

"""
kubeforge/api/routes/history.py
─────────────────────────────────
Scan history endpoints — served from SQLite.
"""

from fastapi import APIRouter, HTTPException
from kubeforge.db import database as db

router = APIRouter(tags=["History"])


@router.get("/scans")
async def list_scans(limit: int = 50):
    """Return the N most recent scan summaries."""
    scans = db.list_scans(limit=limit)
    return {"total": len(scans), "scans": scans}


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: str):
    """Return a single scan summary by ID."""
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/scans/{scan_id}/threats")
async def get_scan_threats(scan_id: str):
    """Return all threats for a specific scan."""
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    threats = db.get_scan_threats(scan_id)
    return {"scan_id": scan_id, "total": len(threats), "threats": threats}


@router.get("/scans/{scan_id_a}/diff/{scan_id_b}")
async def diff_scans(scan_id_a: str, scan_id_b: str):
    """
    Compare two scans.
    Returns: new threats (in B but not A), resolved threats (in A but not B).
    """
    for sid in [scan_id_a, scan_id_b]:
        if not db.get_scan(sid):
            raise HTTPException(status_code=404, detail=f"Scan {sid} not found")

    threats_a = db.get_scan_threats(scan_id_a)
    threats_b = db.get_scan_threats(scan_id_b)

    # Use (title, location) as identity key
    keys_a = {(t["title"], t["location"]) for t in threats_a}
    keys_b = {(t["title"], t["location"]) for t in threats_b}

    new_threats      = [t for t in threats_b if (t["title"], t["location"]) not in keys_a]
    resolved_threats = [t for t in threats_a if (t["title"], t["location"]) not in keys_b]
    persisted        = [t for t in threats_b if (t["title"], t["location"]) in keys_a]

    return {
        "scan_a": scan_id_a,
        "scan_b": scan_id_b,
        "new_count":      len(new_threats),
        "resolved_count": len(resolved_threats),
        "persisted_count": len(persisted),
        "new":      new_threats,
        "resolved": resolved_threats,
    }


# ════════════════════════════════════════════════════════
# FILE: kubeforge/api/routes/export.py
# ════════════════════════════════════════════════════════

"""
kubeforge/api/routes/export.py
────────────────────────────────
Export endpoints — download scan results as CSV or printable HTML report.
"""

import csv
import io
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse, HTMLResponse
from kubeforge.db import database as db

router = APIRouter(tags=["Export"])


@router.get("/scans/{scan_id}/export/csv")
async def export_csv(scan_id: str):
    """Download threats for a scan as CSV."""
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    threats = db.get_scan_threats(scan_id)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["severity", "title", "category", "location", "raw_evidence",
                     "ai_summary", "ai_recommendation", "ai_risk_score"])
    for t in threats:
        writer.writerow([
            t.get("severity"), t.get("title"), t.get("category"),
            t.get("location"), t.get("raw_evidence"),
            t.get("ai_summary", ""), t.get("ai_recommendation", ""),
            t.get("ai_risk_score", ""),
        ])

    output.seek(0)
    filename = f"kubeforge-scan-{scan_id[:8]}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/scans/{scan_id}/export/report", response_class=HTMLResponse)
async def export_report(scan_id: str):
    """Printable HTML security report (use browser Print → Save as PDF)."""
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    threats = db.get_scan_threats(scan_id)
    sev = scan.get("threats_by_severity", {})

    def sev_color(s):
        return {"critical": "#FF4C4C", "high": "#FF8C00",
                "medium": "#FFD600", "low": "#2196F3"}.get(s, "#888")

    rows = ""
    for t in threats:
        color = sev_color(t.get("severity", ""))
        ai = f'<div style="margin-top:6px;color:#555;font-size:0.85em">{t.get("ai_summary","")}</div>' if t.get("ai_summary") else ""
        rec = f'<div style="margin-top:4px;color:#333;font-size:0.82em">💡 {t.get("ai_recommendation","")}</div>' if t.get("ai_recommendation") else ""
        rows += f"""
        <tr>
          <td><span style="color:{color};font-weight:700;text-transform:uppercase">{t.get("severity")}</span></td>
          <td><strong>{t.get("title")}</strong>{ai}{rec}</td>
          <td style="font-family:monospace;font-size:0.8em;color:#555">{t.get("location")}</td>
          <td style="font-family:monospace;font-size:0.8em;color:#777;max-width:200px;word-break:break-all">{t.get("raw_evidence","")[:80]}</td>
        </tr>"""

    from datetime import datetime
    finished = scan.get("finished_at", "")[:19].replace("T", " ")

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>KubeForge Security Report — {scan_id[:8]}</title>
<style>
  body {{ font-family: Arial, sans-serif; color: #111; margin: 40px; }}
  h1 {{ color: #111; font-size: 1.5em; margin-bottom: 4px; }}
  .meta {{ color: #666; font-size: 0.85em; margin-bottom: 24px; }}
  .stats {{ display: flex; gap: 24px; margin-bottom: 28px; }}
  .stat {{ text-align: center; padding: 12px 24px; border-radius: 8px; background: #f5f5f5; }}
  .stat-val {{ font-size: 2em; font-weight: 800; }}
  .stat-label {{ font-size: 0.75em; color: #666; text-transform: uppercase; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.88em; }}
  th {{ text-align: left; padding: 10px 12px; background: #f0f0f0; font-size: 0.78em;
        text-transform: uppercase; letter-spacing: 1px; }}
  td {{ padding: 12px; border-bottom: 1px solid #eee; vertical-align: top; }}
  @media print {{ body {{ margin: 20px; }} }}
</style>
</head>
<body>
<h1>🛡️ KubeForge Security Report</h1>
<div class="meta">
  Scan ID: {scan_id} &nbsp;|&nbsp; Date: {finished} &nbsp;|&nbsp;
  Files scanned: {scan.get("total_files_scanned")} &nbsp;|&nbsp;
  Duration: {scan.get("duration_seconds")}s
</div>
<div class="stats">
  <div class="stat"><div class="stat-val" style="color:#FF4C4C">{sev.get("critical",0)}</div><div class="stat-label">Critical</div></div>
  <div class="stat"><div class="stat-val" style="color:#FF8C00">{sev.get("high",0)}</div><div class="stat-label">High</div></div>
  <div class="stat"><div class="stat-val" style="color:#FFD600">{sev.get("medium",0)}</div><div class="stat-label">Medium</div></div>
  <div class="stat"><div class="stat-val" style="color:#2196F3">{sev.get("low",0)}</div><div class="stat-label">Low</div></div>
  <div class="stat"><div class="stat-val">{scan.get("total_threats_found",0)}</div><div class="stat-label">Total</div></div>
</div>
<table>
  <thead><tr><th>Severity</th><th>Finding</th><th>Location</th><th>Evidence</th></tr></thead>
  <tbody>{rows}</tbody>
</table>
<div style="margin-top:32px;color:#aaa;font-size:0.78em">Generated by KubeForge Security Platform</div>
</body>
</html>"""

    return HTMLResponse(content=html)


# ════════════════════════════════════════════════════════
# FILE: kubeforge/api/routes/health.py
# ════════════════════════════════════════════════════════

"""Health-check endpoints — used by Kubernetes liveness & readiness probes."""

from fastapi import APIRouter
from pydantic import BaseModel
from datetime import datetime
from kubeforge.config import settings

router = APIRouter()


class HealthResponse(BaseModel):
    status: str
    app: str
    version: str
    environment: str
    timestamp: str


@router.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    """Kubernetes liveness probe — always returns 200 if the process is up."""
    return HealthResponse(
        status="healthy",
        app=settings.app_name,
        version=settings.version,
        environment=settings.environment,
        timestamp=datetime.utcnow().isoformat(),
    )


@router.get("/ready", tags=["System"])
async def readiness_check():
    """Kubernetes readiness probe — add real dependency checks here."""
    return {"status": "ready"}


# ════════════════════════════════════════════════════════
# FILE: kubeforge/api/routes/dashboard.py
# ════════════════════════════════════════════════════════

"""Dashboard route — serves the main UI."""

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter()

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>KubeForge — Security Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root {
  --bg:        #EEF6FA;
  --bg2:       #FFFFFF;
  --bg3:       #F0F9FF;
  --bg4:       #E0F2FE;
  --teal:      #0D9488;
  --teal-dim:  rgba(13,148,136,0.1);
  --teal-glow: rgba(13,148,136,0.2);
  --green:     #059669;
  --green-dim: rgba(5,150,105,0.1);
  --sky:       #0284C7;
  --red:       #E11D48;
  --orange:    #EA580C;
  --yellow:    #D97706;
  --blue:      #2563EB;
  --text:      #0D4A3E;
  --text2:     #0F5C4A;
  --muted:     #3D7A6A;
  --border:    rgba(13,148,136,0.15);
  --border2:   rgba(13,148,136,0.25);
  --shadow:    0 4px 20px rgba(13,148,136,0.12);
}

* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: 'Inter', sans-serif;
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
  overflow-x: hidden;
}

::-webkit-scrollbar { width: 5px; }
::-webkit-scrollbar-track { background: var(--bg); }
::-webkit-scrollbar-thumb { background: var(--bg4); border-radius: 3px; }

/* ── NAV ── */
nav {
  display: flex; align-items: center; justify-content: space-between;
  padding: 0 28px; height: 60px;
  background: rgba(255,255,255,0.85);
  backdrop-filter: blur(16px);
  border-bottom: 1px solid var(--border);
  position: sticky; top: 0; z-index: 100;
  box-shadow: 0 1px 12px rgba(13,148,136,0.08);
}
.nav-logo { display: flex; align-items: center; gap: 11px; }
.logo-text { font-size: 1em; font-weight: 800; letter-spacing: 3px; color: var(--text); }
.logo-text span { color: var(--teal); }
.nav-right { display: flex; align-items: center; gap: 12px; }
.version-badge {
  font-size: 0.7em; color: var(--muted);
  background: var(--bg3); padding: 4px 11px; border-radius: 20px;
  border: 1px solid var(--border);
}
.status-pill {
  display: flex; align-items: center; gap: 7px;
  background: rgba(45,212,191,0.08);
  border: 1px solid var(--border2);
  color: var(--teal); padding: 5px 15px; border-radius: 20px;
  font-size: 0.74em; font-weight: 600; letter-spacing: 0.5px;
}
.status-dot {
  width: 6px; height: 6px; background: var(--teal);
  border-radius: 50%; animation: pulse 2s ease-in-out infinite;
  box-shadow: 0 0 6px var(--teal);
}
@keyframes pulse { 0%,100%{opacity:1;box-shadow:0 0 6px var(--teal)} 50%{opacity:0.5;box-shadow:0 0 2px var(--teal)} }

/* ── LAYOUT ── */
.layout { display: grid; grid-template-columns: 210px 1fr; min-height: calc(100vh - 60px); }

/* ── SIDEBAR ── */
aside {
  background: linear-gradient(180deg, #FFFFFF 0%, #F0F9FF 100%);
  border-right: 1px solid var(--border);
  padding: 20px 0;
  box-shadow: 2px 0 12px rgba(13,148,136,0.05);
}
.sidebar-section { margin-bottom: 6px; }
.sidebar-label {
  font-size: 0.63em; font-weight: 700; color: var(--muted);
  letter-spacing: 2.5px; text-transform: uppercase;
  padding: 12px 18px 6px;
}
.sidebar-item {
  display: flex; align-items: center;
  padding: 8px 14px; cursor: pointer; font-size: 0.82em;
  color: var(--text2); border: 1px solid transparent;
  transition: all 0.18s; margin: 2px 10px; border-radius: 8px;
  font-weight: 500;
}
.sidebar-item:hover {
  color: var(--teal);
  background: #ECFDF5;
  border-color: #60A5C8;
  box-shadow: 0 2px 8px rgba(96,165,200,0.15);
}
.sidebar-item.active {
  color: var(--teal);
  background: #ECFDF5;
  border-color: #60A5C8;
  font-weight: 700;
  box-shadow: 0 2px 8px rgba(96,165,200,0.2);
}

/* ── MAIN ── */
main { padding: 26px 30px; overflow-y: auto; }
.screen { display: none; }
.screen.active { display: block; }

/* ── STATS GRID ── */
.stats-grid { display: grid; grid-template-columns: repeat(4,1fr); gap: 14px; margin-bottom: 18px; }
.stat-card {
  background: linear-gradient(135deg, #F0FDF8 0%, #ECFDF5 100%);
  border: 1.5px solid #60A5C8;
  border-radius: 16px; padding: 20px 22px;
  position: relative; overflow: hidden;
  transition: transform 0.2s, box-shadow 0.2s;
}
.stat-card::after {
  content: ''; position: absolute;
  top: -40px; right: -40px;
  width: 100px; height: 100px; border-radius: 50%;
  opacity: 0.06;
}
.stat-card.critical::after { background: var(--red); }
.stat-card.high::after     { background: var(--orange); }
.stat-card.medium::after   { background: var(--yellow); }
.stat-card.safe::after     { background: var(--teal); }
.stat-card::before {
  content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
  border-radius: 16px 16px 0 0;
}
.stat-card.critical::before { background: linear-gradient(90deg, var(--red), transparent); }
.stat-card.high::before     { background: linear-gradient(90deg, var(--orange), transparent); }
.stat-card.medium::before   { background: linear-gradient(90deg, var(--yellow), transparent); }
.stat-card.safe::before     { background: linear-gradient(90deg, var(--teal), transparent); }
.stat-card:hover { transform: translateY(-3px); box-shadow: 0 12px 40px rgba(0,0,0,0.4); }
.stat-label {
  font-size: 0.68em; color: var(--muted); font-weight: 600;
  letter-spacing: 1.5px; text-transform: uppercase; margin-bottom: 10px;
}
.stat-value { font-size: 2.4em; font-weight: 800; line-height: 1; }
.stat-card.critical .stat-value { color: var(--red); }
.stat-card.high .stat-value     { color: var(--orange); }
.stat-card.medium .stat-value   { color: var(--yellow); }
.stat-card.safe .stat-value     { color: var(--teal); }
.stat-sub { font-size: 0.7em; color: var(--muted); margin-top: 7px; }

/* ── RISK SCORE ── */
#riskScoreBar {
  display: none;
  background: linear-gradient(135deg, #F0FDF8, #ECFDF5);
  border: 1.5px solid #60A5C8; border-radius: 16px;
  padding: 18px 24px; margin-bottom: 18px;
  align-items: center; gap: 24px;
}
.risk-title { font-size: 0.68em; color: var(--muted); font-weight: 700;
  text-transform: uppercase; letter-spacing: 1.5px; margin-bottom: 5px; }
.risk-label-text { font-size: 0.82em; color: var(--text2); }
.risk-number { font-size: 2.8em; font-weight: 800; min-width: 78px; text-align: center; }
.risk-track { flex: 1; height: 7px; background: var(--bg4); border-radius: 4px; overflow: hidden; }
.risk-fill { height: 100%; border-radius: 4px; transition: width 1.2s cubic-bezier(.4,0,.2,1); }

/* ── SCAN BAR ── */
.scan-bar {
  background: linear-gradient(135deg, #F0FDF8, #ECFDF5);
  border: 1.5px solid #60A5C8; border-radius: 16px;
  padding: 18px 22px; margin-bottom: 14px;
}
.scan-bar-top {
  display: flex; align-items: center; justify-content: space-between; margin-bottom: 14px;
}
.scan-bar-title { font-size: 0.9em; font-weight: 600; color: var(--text); }
.scan-bar-sub { font-size: 0.74em; color: var(--muted); margin-top: 3px; }
.path-row { display: flex; gap: 8px; }
.path-input {
  flex: 1; background: var(--bg4); border: 1px solid var(--border2);
  border-radius: 10px; padding: 9px 14px;
  color: var(--text2); font-size: 0.81em; font-family: 'Courier New', monospace;
  outline: none; transition: all 0.2s;
}
.path-input:focus { border-color: var(--teal); box-shadow: 0 0 0 3px rgba(45,212,191,0.1); }
.path-input::placeholder { color: var(--muted); }
.paths-list { display: flex; flex-wrap: wrap; gap: 7px; margin-top: 11px; }
.path-tag {
  display: inline-flex; align-items: center; gap: 5px;
  background: rgba(45,212,191,0.08); border: 1px solid var(--border2);
  color: var(--teal); padding: 4px 11px; border-radius: 8px;
  font-size: 0.72em; cursor: pointer; transition: all 0.15s;
}
.path-tag:hover { background: rgba(251,113,133,0.08); border-color: rgba(251,113,133,0.2); color: var(--red); }

/* ── BUTTONS ── */
.btn-scan {
  background: linear-gradient(135deg, #2DD4BF, #34D399);
  color: #0B1623; border: none; padding: 10px 24px; border-radius: 10px;
  font-size: 0.85em; font-weight: 700; cursor: pointer;
  font-family: inherit; display: flex; align-items: center; gap: 8px;
  transition: all 0.25s; white-space: nowrap;
  box-shadow: 0 4px 15px rgba(45,212,191,0.3);
}
.btn-scan:hover {
  background: linear-gradient(135deg, #5EEAD4, #6EE7B7);
  box-shadow: 0 6px 25px rgba(45,212,191,0.45);
  transform: translateY(-1px);
}
.btn-scan:disabled {
  background: var(--bg4); color: var(--muted);
  cursor: not-allowed; box-shadow: none; transform: none;
}
.btn-secondary {
  background: rgba(45,212,191,0.08);
  border: 1px solid var(--border2);
  color: var(--teal); padding: 9px 16px; border-radius: 10px;
  font-size: 0.8em; font-weight: 500; cursor: pointer;
  font-family: inherit; transition: all 0.2s; white-space: nowrap;
}
.btn-secondary:hover {
  background: rgba(45,212,191,0.15);
  border-color: var(--teal);
  box-shadow: 0 4px 12px rgba(45,212,191,0.15);
}
.spinner {
  width: 13px; height: 13px;
  border: 2px solid rgba(11,22,35,0.3); border-top-color: #0B1623;
  border-radius: 50%; animation: spin 0.7s linear infinite; display: none;
}
@keyframes spin { to { transform: rotate(360deg); } }

/* ── PROGRESS ── */
.progress-wrap { margin-bottom: 18px; display: none; }
.progress-label { font-size: 0.76em; color: var(--muted); margin-bottom: 8px; }
.progress-bar { height: 3px; background: var(--bg4); border-radius: 2px; overflow: hidden; }
.progress-fill {
  height: 100%;
  background: linear-gradient(90deg, var(--teal), var(--green), var(--sky));
  background-size: 200% 100%;
  border-radius: 2px;
  animation: progressAnim 1.8s ease-in-out infinite;
}
@keyframes progressAnim { 0%{width:5%;background-position:0%} 50%{width:80%;background-position:100%} 100%{width:95%;background-position:0%} }

/* ── EXPORT BAR ── */
#exportBar {
  display: none; gap: 8px; margin-bottom: 16px; align-items: center;
  padding: 10px 16px; background: #F0FDF8; border: 1.5px solid #60A5C8;
  border-radius: 12px;
}
#exportBar span { font-size: 0.76em; color: var(--muted); }

/* ── SECTION HEADER ── */
.section-header {
  display: flex; align-items: center; justify-content: space-between; margin-bottom: 14px;
}
.section-title { font-size: 0.88em; font-weight: 700; display: flex; align-items: center; gap: 7px; color: var(--text2); }
.badge {
  background: var(--bg3); border: 1px solid var(--border2);
  padding: 2px 9px; border-radius: 10px; font-size: 0.72em; color: var(--teal);
}

/* ── THREAT CARDS ── */
.threats-list { display: flex; flex-direction: column; gap: 10px; }
.threat-card {
  background: linear-gradient(135deg, #F0FDF8, #ECFDF5);
  border: 1.5px solid #60A5C8;
  border-radius: 13px; padding: 15px 19px;
  border-left: 3px solid transparent;
  transition: all 0.2s; cursor: pointer;
}
.threat-card:hover {
  transform: translateX(4px);
  border-color: var(--border2);
  box-shadow: 0 6px 24px rgba(0,0,0,0.35);
}
.threat-card.critical { border-left-color: var(--red); }
.threat-card.high     { border-left-color: var(--orange); }
.threat-card.medium   { border-left-color: var(--yellow); }
.threat-card.low      { border-left-color: var(--sky); }
.threat-card.info     { border-left-color: var(--muted); }

.threat-header { display: flex; align-items: center; gap: 9px; margin-bottom: 8px; }
.severity-badge {
  font-size: 0.63em; font-weight: 700; letter-spacing: 1px;
  padding: 3px 9px; border-radius: 6px; text-transform: uppercase;
}
.severity-badge.critical { background: rgba(251,113,133,0.12); color: var(--red); border: 1px solid rgba(251,113,133,0.2); }
.severity-badge.high     { background: rgba(251,146,60,0.12);  color: var(--orange); border: 1px solid rgba(251,146,60,0.2); }
.severity-badge.medium   { background: rgba(252,211,77,0.12);  color: var(--yellow); border: 1px solid rgba(252,211,77,0.2); }
.severity-badge.low      { background: rgba(56,189,248,0.12);  color: var(--sky); border: 1px solid rgba(56,189,248,0.2); }
.severity-badge.info     { background: rgba(94,143,175,0.12);  color: var(--muted); border: 1px solid rgba(94,143,175,0.2); }

.threat-title { font-size: 0.87em; font-weight: 600; color: var(--text); }
.threat-location {
  font-size: 0.71em; color: var(--muted); margin-bottom: 8px;
  font-family: 'Courier New', monospace;
}
.threat-evidence {
  background: #ECFDF5; border: 1px solid rgba(13,148,136,0.15);
  border-radius: 8px; padding: 8px 12px;
  font-family: 'Courier New', monospace; font-size: 0.75em;
  color: var(--muted); word-break: break-all;
}
.threat-ai {
  margin-top: 10px; padding: 11px 15px;
  background: rgba(45,212,191,0.05);
  border: 1px solid rgba(45,212,191,0.12);
  border-radius: 10px; font-size: 0.8em; color: var(--text2); line-height: 1.7;
  display: none;
}
.threat-ai.visible { display: block; }
.threat-ai-label {
  font-size: 0.7em; font-weight: 700; color: var(--teal);
  text-transform: uppercase; letter-spacing: 1.2px; margin-bottom: 7px;
}
.threat-rec { margin-top: 8px; font-size: 0.78em; color: var(--muted); }
.risk-score-badge {
  margin-left: auto;
  background: rgba(45,212,191,0.1); border: 1px solid var(--border2);
  color: var(--teal); font-size: 0.68em; font-weight: 700;
  padding: 3px 9px; border-radius: 6px;
}

/* ── EMPTY STATE ── */
.empty-state { text-align: center; padding: 56px 20px; color: var(--muted); }
.empty-state .icon { font-size: 2.6em; margin-bottom: 14px; opacity: 0.4; }
.empty-state p { font-size: 0.84em; line-height: 1.8; }
.empty-state strong { color: var(--teal); }

/* ── HISTORY TABLE ── */
.history-table { width: 100%; border-collapse: collapse; }
.history-table th {
  text-align: left; font-size: 0.67em; font-weight: 700; color: var(--muted);
  text-transform: uppercase; letter-spacing: 1.5px;
  padding: 10px 14px; border-bottom: 1px solid var(--border);
}
.history-table td {
  padding: 13px 14px; border-bottom: 1px solid var(--border);
  font-size: 0.82em; vertical-align: middle; color: var(--text2);
}
.history-table tr:hover td { background: rgba(45,212,191,0.03); cursor: pointer; }
.history-table tr.selected td { background: rgba(45,212,191,0.06); }
.sev-pills { display: flex; gap: 5px; flex-wrap: wrap; }
.sev-pill {
  font-size: 0.67em; font-weight: 700; padding: 2px 7px; border-radius: 5px;
}
.sev-pill.critical { background: rgba(251,113,133,0.12); color: var(--red); }
.sev-pill.high     { background: rgba(251,146,60,0.12);  color: var(--orange); }
.sev-pill.medium   { background: rgba(252,211,77,0.12);  color: var(--yellow); }
.sev-pill.low      { background: rgba(56,189,248,0.12);  color: var(--sky); }
.scanner-badge {
  font-size: 0.7em; padding: 3px 9px; border-radius: 6px; font-weight: 600;
  background: var(--bg3); border: 1px solid var(--border);
}
.scanner-badge.multi_scanner { border-color: var(--border2); color: var(--teal); }
.scanner-badge.data_scanner  { border-color: rgba(96,165,250,0.2); color: var(--blue); }
.scanner-badge.k8s_scanner   { border-color: rgba(52,211,153,0.2); color: var(--green); }

/* ── TOAST ── */
.toast {
  position: fixed; bottom: 22px; right: 22px; z-index: 999;
  background: #FFFFFF; border: 1px solid var(--border2);
  border-radius: 13px; padding: 13px 18px;
  font-size: 0.81em; max-width: 300px;
  transform: translateY(80px); opacity: 0;
  transition: all 0.3s cubic-bezier(.4,0,.2,1);
  box-shadow: 0 8px 32px rgba(0,0,0,0.5);
}
.toast.show { transform: translateY(0); opacity: 1; }
.toast.success { border-left: 3px solid var(--teal); }
.toast.error   { border-left: 3px solid var(--red); }
</style>
</head>
<body>

<nav>
  <div class="nav-logo">
    <svg width="28" height="28" viewBox="0 0 64 64">
      <polygon points="32,4 52,15 52,37 32,48 12,37 12,15" fill="none" stroke="#2DD4BF" stroke-width="2"/>
      <polygon points="32,10 47,19 47,35 32,44 17,35 17,19" fill="#112033"/>
      <text x="32" y="38" text-anchor="middle" font-family="Inter,sans-serif" font-size="19" font-weight="800" fill="#2DD4BF">K</text>
    </svg>
    <span class="logo-text">KUBE<span>FORGE</span></span>
  </div>
  <div class="nav-right">
    <span class="version-badge" id="versionLabel">v0.1.0</span>
    <div class="status-pill"><div class="status-dot"></div><span id="statusText">System Online</span></div>
  </div>
</nav>

<div class="layout">
  <aside>
    <div class="sidebar-section">
      <div class="sidebar-label">Main</div>
      <div class="sidebar-item active" onclick="showScreen('dashboard',this)">Dashboard</div>
      <div class="sidebar-item" onclick="showScreen('history',this)">Scan History</div>
      <div class="sidebar-item" onclick="showScreen('threats',this)">Threats</div>
    </div>
    <div class="sidebar-section" style="margin-top:8px;">
      <div class="sidebar-label">Scanners</div>
      <div class="sidebar-item">Data & Secrets</div>
      <div class="sidebar-item">Kubernetes</div>
      <div class="sidebar-item">Docker</div>
      <div class="sidebar-item">Dependencies</div>
    </div>
    <div class="sidebar-section" style="margin-top:8px;">
      <div class="sidebar-label">Settings</div>
      <div class="sidebar-item" onclick="showScreen('settings',this);loadSettings()">Config & Alerts</div>
    </div>
  </aside>

  <main>

    <!-- DASHBOARD -->
    <div id="screen-dashboard" class="screen active">

      <div class="stats-grid">
        <div class="stat-card critical">
          <div class="stat-label">Critical</div>
          <div class="stat-value" id="countCritical">—</div>
          <div class="stat-sub">Immediate action</div>
        </div>
        <div class="stat-card high">
          <div class="stat-label">High</div>
          <div class="stat-value" id="countHigh">—</div>
          <div class="stat-sub">Within 24h</div>
        </div>
        <div class="stat-card medium">
          <div class="stat-label">Medium</div>
          <div class="stat-value" id="countMedium">—</div>
          <div class="stat-sub">Review this week</div>
        </div>
        <div class="stat-card safe">
          <div class="stat-label">Files Scanned</div>
          <div class="stat-value" id="countFiles">—</div>
          <div class="stat-sub" id="scanDuration">Run a scan</div>
        </div>
      </div>

      <div id="riskScoreBar">
        <div style="flex:1;">
          <div class="risk-title">Overall Risk Score</div>
          <div class="risk-label-text" id="riskLabel">—</div>
        </div>
        <div class="risk-number" id="riskValue">—</div>
        <div class="risk-track"><div class="risk-fill" id="riskBar"></div></div>
      </div>

      <div class="scan-bar">
        <div class="scan-bar-top">
          <div>
            <div class="scan-bar-title">🔍 Security Scanner</div>
            <div class="scan-bar-sub" id="lastScanText">No scan has been run yet</div>
          </div>
          <button class="btn-scan" id="scanBtn" onclick="triggerScan()">
            <span class="spinner" id="scanSpinner"></span>
            <span id="scanBtnText">▶ Run Scan</span>
          </button>
        </div>
        <div class="path-row">
          <input class="path-input" id="pathInput" type="text" placeholder="Add path to scan, e.g. /Users/me/projects"/>
          <button class="btn-secondary" onclick="addPath()">+ Add</button>
        </div>
        <div class="paths-list" id="pathsList"></div>
      </div>

      <div id="exportBar">
        <span>Export last scan:</span>
        <button class="btn-secondary" onclick="exportCSV()">⬇ CSV</button>
        <button class="btn-secondary" onclick="exportReport()">📄 PDF Report</button>
      </div>

      <div class="progress-wrap" id="progressWrap">
        <div class="progress-label">Scanning files...</div>
        <div class="progress-bar"><div class="progress-fill"></div></div>
      </div>

      <!-- GITHUB SCAN -->
      <div class="scan-bar" style="margin-bottom:14px;">
        <div class="scan-bar-top" style="margin-bottom:0;">
          <div>
            <div class="scan-bar-title">GitHub Repository Scanner</div>
            <div class="scan-bar-sub">Scan any public GitHub repo for secrets and misconfigs</div>
          </div>
        </div>
        <div class="path-row" style="margin-top:12px;">
          <input class="path-input" id="githubUrl" type="text" placeholder="https://github.com/owner/repo"/>
          <button class="btn-scan" onclick="scanGitHub()" style="padding:9px 18px;">Scan Repo</button>
        </div>
      </div>

      <div class="section-header">
        <div class="section-title">⚠️ Detected Threats <span class="badge" id="threatCount">0</span></div>
        <div style="display:flex;gap:8px;align-items:center;">
          <input id="searchInput" oninput="renderThreatsFiltered()" type="text"
            class="path-input" style="width:180px;padding:6px 11px;font-family:inherit;"
            placeholder="Search threats..."/>
          <select id="filterSev" onchange="renderThreatsFiltered()"
            style="background:var(--bg4);border:1.5px solid #60A5C8;border-radius:8px;
            color:var(--text);padding:6px 10px;font-family:inherit;font-size:0.8em;cursor:pointer;">
            <option value="all">All</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>
      <div id="threatsContainer">
        <div class="empty-state">
          <div class="icon">🛡️</div>
          <p>No threats detected yet.<br>Add a path and click <strong>Run Scan</strong>.</p>
        </div>
      </div>
    </div>

    <!-- HISTORY -->
    <div id="screen-history" class="screen">
      <div class="section-header" style="margin-bottom:18px;">
        <div class="section-title">📋 Scan History</div>
        <button class="btn-secondary" onclick="loadHistory()">↻ Refresh</button>
      </div>
      <div id="historyContainer">
        <div class="empty-state"><div class="icon">📋</div><p>Loading...</p></div>
      </div>
      <div id="historyDetail" style="display:none;margin-top:22px;">
        <div class="section-header">
          <div class="section-title">⚠️ Threats — <span id="detailScanId" style="font-family:monospace;font-size:0.85em;color:var(--muted);"></span></div>
        </div>
        <div id="historyThreats"></div>
      </div>
    </div>

    <!-- THREATS -->
    <div id="screen-threats" class="screen">
      <div class="section-header" style="margin-bottom:18px;">
        <div class="section-title">⚠️ All Threats — Latest Scan</div>
      </div>
      <div id="allThreatsContainer">
        <div class="empty-state"><div class="icon">⚠️</div><p>Run a scan first.</p></div>
      </div>
    </div>

    <!-- SETTINGS -->
    <div id="screen-settings" class="screen">
      <div class="section-header" style="margin-bottom:20px;">
        <div class="section-title">⚙️ Settings</div>
      </div>
      <div style="display:flex;flex-direction:column;gap:14px;max-width:560px;">

        <div class="scan-bar">
          <div class="scan-bar-title" style="margin-bottom:12px;">Auto-Scan Interval</div>
          <div class="path-row">
            <select id="settingInterval" class="path-input" style="font-family:inherit;">
              <option value="900">Every 15 minutes</option>
              <option value="1800">Every 30 minutes</option>
              <option value="3600" selected>Every 1 hour</option>
              <option value="21600">Every 6 hours</option>
              <option value="86400">Every 24 hours</option>
            </select>
          </div>
        </div>

        <div class="scan-bar">
          <div class="scan-bar-title" style="margin-bottom:4px;">Slack Webhook URL</div>
          <div class="scan-bar-sub" style="margin-bottom:12px;">Receive alerts when critical threats are found</div>
          <input id="settingSlack" class="path-input" type="text" placeholder="https://hooks.slack.com/services/..."/>
        </div>

        <div class="scan-bar">
          <div class="scan-bar-title" style="margin-bottom:4px;">GitHub Token</div>
          <div class="scan-bar-sub" style="margin-bottom:12px;">For scanning private repositories</div>
          <input id="settingGithubToken" class="path-input" type="password" placeholder="ghp_..."/>
        </div>

        <div class="scan-bar">
          <div class="scan-bar-title" style="margin-bottom:4px;">Network Scan Hosts</div>
          <div class="scan-bar-sub" style="margin-bottom:12px;">Comma-separated hosts to scan for open ports</div>
          <input id="settingHosts" class="path-input" type="text" placeholder="localhost, 10.0.0.1, myserver.com"/>
        </div>

        <button class="btn-scan" onclick="saveSettings()" style="align-self:flex-start;">
          💾 Save Settings
        </button>
      </div>
    </div>

  </main>
</div>

<div class="toast" id="toast"></div>

<script>
const API = '';
let scanPollingInterval = null;
let scanPaths = [];

function showScreen(name, el) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.sidebar-item').forEach(s => s.classList.remove('active'));
  document.getElementById('screen-' + name).classList.add('active');
  if (el) el.classList.add('active');
  if (name === 'history') loadHistory();
  if (name === 'threats') loadAllThreats();
}

function addPath() {
  const input = document.getElementById('pathInput');
  const val = input.value.trim();
  if (!val || scanPaths.includes(val)) return;
  scanPaths.push(val);
  renderPaths();
  input.value = '';
}
document.getElementById('pathInput').addEventListener('keydown', e => { if (e.key==='Enter') addPath(); });
function removePath(path) { scanPaths = scanPaths.filter(p => p !== path); renderPaths(); }
function renderPaths() {
  document.getElementById('pathsList').innerHTML = scanPaths.map(p =>
    `<span class="path-tag" onclick="removePath('${escHtml(p)}')" title="Remove">📁 ${escHtml(p)} ×</span>`
  ).join('');
}

async function init() {
  try {
    const data = await (await fetch(`${API}/health`)).json();
    document.getElementById('versionLabel').textContent = `v${data.version}`;
  } catch(e) { document.getElementById('statusText').textContent = 'Offline'; }
  loadLatestScan();
}

async function triggerScan() {
  const btn = document.getElementById('scanBtn');
  btn.disabled = true;
  document.getElementById('scanSpinner').style.display = 'block';
  document.getElementById('scanBtnText').textContent = 'Scanning...';
  document.getElementById('progressWrap').style.display = 'block';
  document.getElementById('lastScanText').textContent = 'Scan in progress...';
  const body = { enrich_with_ai: true };
  if (scanPaths.length) body.paths = scanPaths;
  try {
    await fetch(`${API}/api/v1/scan`, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body) });
    showToast('Scan started...', 'success');
    scanPollingInterval = setInterval(pollScanResult, 1500);
  } catch(e) { showToast('Failed to start scan', 'error'); resetScanBtn(); }
}

async function pollScanResult() {
  try {
    const res = await fetch(`${API}/api/v1/scan/latest`);
    if (!res.ok) return;
    const summary = await res.json();
    const age = (Date.now() - new Date(summary.finished_at + 'Z').getTime()) / 1000;
    if (age < 10) { clearInterval(scanPollingInterval); await renderResults(summary); resetScanBtn(); }
  } catch(e) {}
}

async function loadLatestScan() {
  try {
    const res = await fetch(`${API}/api/v1/scan/latest`);
    if (!res.ok) return;
    await renderResults(await res.json());
  } catch(e) {}
}

async function renderResults(summary) {
  const sev = summary.threats_by_severity || {};
  document.getElementById('countCritical').textContent = sev.critical || 0;
  document.getElementById('countHigh').textContent     = sev.high     || 0;
  document.getElementById('countMedium').textContent   = sev.medium   || 0;
  document.getElementById('countFiles').textContent    = summary.total_files_scanned;
  document.getElementById('scanDuration').textContent  = `Took ${summary.duration_seconds}s`;
  document.getElementById('threatCount').textContent   = summary.total_threats_found;
  const dt = new Date(summary.finished_at + 'Z');
  document.getElementById('lastScanText').textContent = `Last scan: ${dt.toLocaleTimeString()} — ${summary.total_threats_found} threats`;
  document.getElementById('scanMeta').textContent = `${summary.scan_id.slice(0,8)}...  ·  ${summary.total_files_scanned} files`;

  const raw = (sev.critical||0)*10 + (sev.high||0)*5 + (sev.medium||0)*2 + (sev.low||0);
  const score = Math.min(100, raw);
  const color = score>=60 ? 'var(--red)' : score>=30 ? 'var(--orange)' : score>=10 ? 'var(--yellow)' : 'var(--teal)';
  const label = score>=60 ? 'High Risk — Immediate attention required'
              : score>=30 ? 'Medium Risk — Review findings soon'
              : score>=10 ? 'Low Risk — Monitor regularly'
              : 'Minimal Risk — Environment looks clean ✓';
  const bar = document.getElementById('riskScoreBar');
  bar.style.display = 'flex';
  document.getElementById('riskValue').textContent = score;
  document.getElementById('riskValue').style.color = color;
  document.getElementById('riskBar').style.width = score + '%';
  document.getElementById('riskBar').style.background = color;
  document.getElementById('riskLabel').textContent = label;

  window._currentScanId = summary.scan_id;
  document.getElementById('exportBar').style.display = 'flex';

  const tData = await (await fetch(`${API}/api/v1/scan/latest/threats`)).json();
  _allThreats = tData.threats || [];
  renderThreats(_allThreats, 'threatsContainer');
  document.getElementById('progressWrap').style.display = 'none';
  showToast(`Scan complete — ${summary.total_threats_found} threats found`, 'success');

  // Browser notification for critical threats
  const critCount = sev.critical || 0;
  if (critCount > 0) {
    sendNotification('KubeForge — Critical Threats Found',
      `${critCount} critical threat${critCount>1?'s':''} detected! Open dashboard to review.`);
  }
}

async function loadHistory() {
  document.getElementById('historyContainer').innerHTML = '<div class="empty-state"><div class="icon">⏳</div><p>Loading...</p></div>';
  document.getElementById('historyDetail').style.display = 'none';
  try {
    const data = await (await fetch(`${API}/api/v1/scans`)).json();
    renderHistory(data.scans || []);
  } catch(e) {
    document.getElementById('historyContainer').innerHTML = '<div class="empty-state"><div class="icon">📋</div><p>No scan history yet.</p></div>';
  }
}

function renderHistory(scans) {
  if (!scans.length) {
    document.getElementById('historyContainer').innerHTML = '<div class="empty-state"><div class="icon">📋</div><p>No scans yet.</p></div>';
    return;
  }
  const rows = scans.map(s => {
    const sev = s.threats_by_severity || {};
    const pills = ['critical','high','medium','low'].filter(k=>sev[k])
      .map(k=>`<span class="sev-pill ${k}">${k[0].toUpperCase()} ${sev[k]}</span>`).join('');
    const dt = new Date(s.finished_at + 'Z').toLocaleString();
    return `<tr onclick="loadHistoryDetail('${s.scan_id}',this)">
      <td style="font-family:monospace;color:var(--muted);font-size:0.77em">${s.scan_id.slice(0,12)}...</td>
      <td>${dt}</td>
      <td><span class="scanner-badge ${s.scanner_name}">${s.scanner_name}</span></td>
      <td>${s.total_files_scanned}</td>
      <td style="font-weight:600;color:var(--text)">${s.total_threats_found}</td>
      <td><div class="sev-pills">${pills||'<span style="color:var(--muted);font-size:0.78em">none</span>'}</div></td>
      <td style="color:var(--muted);font-size:0.78em">${s.duration_seconds}s</td>
    </tr>`;
  }).join('');
  document.getElementById('historyContainer').innerHTML = `
    <table class="history-table">
      <thead><tr><th>Scan ID</th><th>Date</th><th>Scanner</th><th>Files</th><th>Threats</th><th>By Severity</th><th>Duration</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

async function loadHistoryDetail(scanId, row) {
  document.querySelectorAll('.history-table tr').forEach(r => r.classList.remove('selected'));
  row.classList.add('selected');
  document.getElementById('detailScanId').textContent = scanId.slice(0,12) + '...';
  document.getElementById('historyDetail').style.display = 'block';
  const container = document.getElementById('historyThreats');
  container.innerHTML = '<div class="empty-state"><div class="icon">⏳</div><p>Loading...</p></div>';
  try {
    const data = await (await fetch(`${API}/api/v1/scans/${scanId}/threats`)).json();
    renderThreats(data.threats || [], 'historyThreats');
  } catch(e) {
    container.innerHTML = '<div class="empty-state"><div class="icon">❌</div><p>Failed to load.</p></div>';
  }
}

async function loadAllThreats() {
  try {
    const data = await (await fetch(`${API}/api/v1/scan/latest/threats`)).json();
    renderThreats(data.threats || [], 'allThreatsContainer');
  } catch(e) {
    document.getElementById('allThreatsContainer').innerHTML = '<div class="empty-state"><div class="icon">⚠️</div><p>Run a scan first.</p></div>';
  }
}

function renderThreats(threats, containerId) {
  const container = document.getElementById(containerId);
  if (!threats.length) {
    container.innerHTML = '<div class="empty-state"><div class="icon">✅</div><p>No threats detected.</p></div>';
    return;
  }
  const order = {critical:0,high:1,medium:2,low:3,info:4};
  threats.sort((a,b) => (order[a.severity]||9)-(order[b.severity]||9));
  container.innerHTML = '<div class="threats-list">' + threats.map(t => threatCard(t)).join('') + '</div>';
}

function threatCard(t) {
  const ai = t.ai_summary ? `
    <div class="threat-ai visible">
      <div class="threat-ai-label">🤖 AI Analysis</div>
      <div>${escHtml(t.ai_summary)}</div>
      ${t.ai_recommendation ? `<div class="threat-rec">💡 ${escHtml(t.ai_recommendation)}</div>` : ''}
    </div>` : '';
  const risk = t.ai_risk_score ? `<span class="risk-score-badge">Risk ${t.ai_risk_score}/10</span>` : '';
  return `<div class="threat-card ${t.severity}" onclick="toggleAI(this)">
    <div class="threat-header">
      <span class="severity-badge ${t.severity}">${t.severity}</span>
      <span class="threat-title">${escHtml(t.title)}</span>
      ${risk}
    </div>
    <div class="threat-location">📍 ${escHtml(t.location)}</div>
    <div class="threat-evidence">${escHtml(t.raw_evidence)}</div>
    ${ai}
  </div>`;
}

function toggleAI(card) { const ai = card.querySelector('.threat-ai'); if(ai) ai.classList.toggle('visible'); }
function resetScanBtn() {
  document.getElementById('scanBtn').disabled = false;
  document.getElementById('scanSpinner').style.display = 'none';
  document.getElementById('scanBtnText').textContent = '▶ Run Scan';
}
function showToast(msg, type='success') {
  const t = document.getElementById('toast');
  t.textContent = msg; t.className = `toast ${type} show`;
  setTimeout(() => t.classList.remove('show'), 3500);
}
function escHtml(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function exportCSV() { if(window._currentScanId) window.location.href=`/api/v1/scans/${window._currentScanId}/export/csv`; }
function exportReport() { if(window._currentScanId) window.open(`/api/v1/scans/${window._currentScanId}/export/report`,'_blank'); }

// ── BROWSER NOTIFICATIONS ──
async function requestNotifications() {
  if (!('Notification' in window)) return;
  if (Notification.permission === 'default') {
    await Notification.requestPermission();
  }
}
function sendNotification(title, body) {
  if (Notification.permission === 'granted') {
    new Notification(title, { body, icon: '' });
  }
}

// ── SEARCH & FILTER ──
let _allThreats = [];
function renderThreatsFiltered() {
  const q = (document.getElementById('searchInput')?.value || '').toLowerCase();
  const sev = document.getElementById('filterSev')?.value || 'all';
  const filtered = _allThreats.filter(t => {
    const matchSev = sev === 'all' || t.severity === sev;
    const matchQ   = !q || t.title.toLowerCase().includes(q) || t.location.toLowerCase().includes(q);
    return matchSev && matchQ;
  });
  renderThreats(filtered, 'threatsContainer');
  document.getElementById('threatCount').textContent = filtered.length;
}

// ── SCAN GITHUB ──
async function scanGitHub() {
  const url = document.getElementById('githubUrl')?.value?.trim();
  if (!url) { showToast('Enter a GitHub repo URL', 'error'); return; }
  try {
    await fetch(`${API}/api/v1/scan/github`, {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ repo_url: url, enrich_with_ai: true }),
    });
    showToast('GitHub scan started — cloning repo...', 'success');
    document.getElementById('progressWrap').style.display = 'block';
    scanPollingInterval = setInterval(pollScanResult, 2000);
  } catch(e) { showToast('Failed to start GitHub scan', 'error'); }
}

// ── SETTINGS ──
function saveSettings() {
  const interval = document.getElementById('settingInterval')?.value;
  const slack    = document.getElementById('settingSlack')?.value;
  localStorage.setItem('kf_interval', interval);
  localStorage.setItem('kf_slack', slack);
  showToast('Settings saved locally', 'success');
}
function loadSettings() {
  const interval = localStorage.getItem('kf_interval') || '3600';
  const slack    = localStorage.getItem('kf_slack') || '';
  if (document.getElementById('settingInterval')) document.getElementById('settingInterval').value = interval;
  if (document.getElementById('settingSlack'))    document.getElementById('settingSlack').value = slack;
}

// ── DIFF ──
let _diffScanA = null;
function selectDiffScan(scanId, label) {
  if (!_diffScanA) {
    _diffScanA = scanId;
    showToast(`Scan A selected: ${scanId.slice(0,8)}... — now select Scan B`, 'success');
    document.querySelectorAll('.history-table tr').forEach(r => r.classList.remove('diff-a'));
    event.currentTarget.closest('tr').classList.add('diff-a');
  } else if (_diffScanA !== scanId) {
    runDiff(_diffScanA, scanId);
    _diffScanA = null;
  }
}

async function runDiff(scanA, scanB) {
  try {
    const data = await (await fetch(`${API}/api/v1/scans/${scanA}/diff/${scanB}`)).json();
    const container = document.getElementById('historyThreats');
    document.getElementById('historyDetail').style.display = 'block';
    document.getElementById('detailScanId').textContent = `Diff: ${scanA.slice(0,8)} → ${scanB.slice(0,8)}`;

    container.innerHTML = `
      <div style="display:flex;gap:12px;margin-bottom:16px;">
        <div style="flex:1;background:#FFF5F5;border:1.5px solid #FB7185;border-radius:12px;padding:14px;">
          <div style="font-size:0.7em;font-weight:700;color:#E11D48;letter-spacing:1px;margin-bottom:8px;">🆕 NEW THREATS (${data.new_count})</div>
          ${data.new.length ? '<div class="threats-list">' + data.new.map(t=>threatCard(t)).join('') + '</div>'
            : '<p style="color:#aaa;font-size:0.82em">No new threats</p>'}
        </div>
        <div style="flex:1;background:#F0FFF4;border:1.5px solid #34D399;border-radius:12px;padding:14px;">
          <div style="font-size:0.7em;font-weight:700;color:#059669;letter-spacing:1px;margin-bottom:8px;">✅ RESOLVED (${data.resolved_count})</div>
          ${data.resolved.length ? '<div class="threats-list">' + data.resolved.map(t=>threatCard(t)).join('') + '</div>'
            : '<p style="color:#aaa;font-size:0.82em">No resolved threats</p>'}
        </div>
      </div>`;
  } catch(e) { showToast('Diff failed', 'error'); }
}

init();
requestNotifications();
</script>
</body>
</html>
"""

@router.get("/", response_class=HTMLResponse, include_in_schema=False)
async def dashboard():
    return HTMLResponse(content=DASHBOARD_HTML)


# ════════════════════════════════════════════════════════
# FILE: tests/test_scanner.py
# ════════════════════════════════════════════════════════

"""
tests/test_scanner.py
──────────────────────
Unit tests for the DataScanner.
Tests run against a temporary directory with synthetic files —
no real filesystem access needed.
"""

import pytest
import asyncio
import tempfile
import os
from pathlib import Path

from kubeforge.scanner.data_scanner import DataScanner
from kubeforge.models.threat import Severity, ThreatCategory


def write_temp_file(dir_path: str, filename: str, content: str) -> str:
    """Helper: create a temp file with given content."""
    path = os.path.join(dir_path, filename)
    Path(path).write_text(content)
    return path


@pytest.mark.asyncio
async def test_detects_aws_key():
    with tempfile.TemporaryDirectory() as tmpdir:
        write_temp_file(tmpdir, "config.py", 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"')
        scanner = DataScanner(target_paths=[tmpdir])
        summary = await scanner.run()

    assert summary.total_threats_found >= 1
    severities = [e.severity for e in summary.events]
    assert Severity.CRITICAL in severities


@pytest.mark.asyncio
async def test_detects_password():
    with tempfile.TemporaryDirectory() as tmpdir:
        write_temp_file(tmpdir, "settings.yml", "database:\n  password: supersecret123")
        scanner = DataScanner(target_paths=[tmpdir])
        summary = await scanner.run()

    assert summary.total_threats_found >= 1
    categories = [e.category for e in summary.events]
    assert ThreatCategory.SENSITIVE_DATA_EXPOSED in categories


@pytest.mark.asyncio
async def test_detects_private_key():
    with tempfile.TemporaryDirectory() as tmpdir:
        write_temp_file(
            tmpdir, "key.pem",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
        )
        scanner = DataScanner(target_paths=[tmpdir])
        summary = await scanner.run()

    assert summary.total_threats_found >= 1
    assert any(e.severity == Severity.CRITICAL for e in summary.events)


@pytest.mark.asyncio
async def test_clean_file_no_threats():
    with tempfile.TemporaryDirectory() as tmpdir:
        write_temp_file(tmpdir, "clean.py", "def hello():\n    return 'Hello, World!'")
        scanner = DataScanner(target_paths=[tmpdir])
        summary = await scanner.run()

    assert summary.total_threats_found == 0


@pytest.mark.asyncio
async def test_skips_nonexistent_path():
    scanner = DataScanner(target_paths=["/nonexistent/path/xyz"])
    summary = await scanner.run()
    assert summary.total_files_scanned == 0


@pytest.mark.asyncio
async def test_scan_summary_counts():
    with tempfile.TemporaryDirectory() as tmpdir:
        write_temp_file(tmpdir, "a.env", 'API_KEY="abc123secretkey456789"')
        write_temp_file(tmpdir, "b.py",  'password = "hunter2"')
        scanner = DataScanner(target_paths=[tmpdir])
        summary = await scanner.run()

    assert summary.total_files_scanned == 2
    assert summary.total_threats_found >= 2
    assert len(summary.events) == summary.total_threats_found

