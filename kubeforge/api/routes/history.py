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
