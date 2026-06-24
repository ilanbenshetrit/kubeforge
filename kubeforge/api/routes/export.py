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
