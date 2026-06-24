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
