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
