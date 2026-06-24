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
