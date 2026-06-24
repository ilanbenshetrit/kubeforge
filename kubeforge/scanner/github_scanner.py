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
