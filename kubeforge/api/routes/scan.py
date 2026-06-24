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
