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
