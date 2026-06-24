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
