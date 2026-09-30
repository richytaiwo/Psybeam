import os
from datetime import datetime
from typing import Optional

import pandas as pd
from fastapi import FastAPI, UploadFile, File, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.database.db import get_db, init_db
from backend.database import models
from backend.detection import engine as detection_engine
from backend.config import DEFAULT_DETECTION_CONFIG, CORS_ALLOW_ORIGINS


# Create the FastAPI app
app = FastAPI(
    title="Psybeam Security Monitor",
    version="1.0.1"
)


# Allow the dashboard to communicate with the API
app.add_middleware(
    CORSMiddleware,
    # Which sites can call this API
    allow_origins=CORS_ALLOW_ORIGINS,
    # Allow GET, POST, etc from those sites
    allow_methods=["*"],
    # Allow any request headers
    allow_headers=["*"],
)


# Find the sample log file
SAMPLE_LOG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "sample_logs",
    "auth.log"
)


# Create the database when the API starts
@app.on_event("startup")
def on_startup():
    init_db()


# Analysis


@app.post("/api/analyze/sample")
def analyze_sample(db: Session = Depends(get_db)):
    # Analyze the sample log file

    # Make sure the sample log exists
    if not os.path.exists(SAMPLE_LOG_PATH):
        raise HTTPException(
            404,
            "Sample log not found. Run sample_logs/generate_sample_logs.py first."
        )

    # Run the analysis
    run = detection_engine.analyze_file(
        db,
        SAMPLE_LOG_PATH,
        DEFAULT_DETECTION_CONFIG
    )

    # Give back the run ID so the dashboard can look up this run's data
    return {
        "run_id": run.id,
        "status": "complete"
    }


@app.post("/api/analyze/upload")
async def analyze_upload(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    # Analyze a log file uploaded by the user

    # Read the uploaded file
    raw = await file.read()

    # Turn the raw bytes into text
    try:
        text = raw.decode("utf-8", errors="ignore")
    except Exception:
        raise HTTPException(
            400,
            "Could not read uploaded file as text."
        )

    # Run the analysis
    run = detection_engine.analyze_text(
        db,
        text,
        file.filename,
        DEFAULT_DETECTION_CONFIG
    )

    return {
        "run_id": run.id,
        "status": "complete"
    }


# Analysis runs


@app.get("/api/runs")
def list_runs(db: Session = Depends(get_db)):
    # Get all previous analysis runs, newest first
    runs = (
        db.query(models.AnalysisRun)
        .order_by(models.AnalysisRun.id.desc())
        .all()
    )

    # Turn each database row into plain JSON-friendly data
    return [_run_to_dict(r) for r in runs]


def _latest_run_id(db: Session) -> Optional[int]:
    # Get the most recent analysis
    row = (
        db.query(models.AnalysisRun)
        .order_by(models.AnalysisRun.id.desc())
        .first()
    )

    # No analysis yet means no ID to return
    return row.id if row else None


def _resolve_run_id(
    db: Session,
    run_id: Optional[int]
) -> Optional[int]:

    # Use the requested run or fall back to the latest one
    return run_id if run_id is not None else _latest_run_id(db)


def _run_to_dict(r: models.AnalysisRun) -> dict:
    # Convert a database record into a response for the dashboard
    return {
        "run_id": r.id,
        "source_filename": r.source_filename,
        # dates need to become strings for JSON
        "started_at": (
            r.started_at.isoformat()
            if r.started_at else None
        ),
        "events_analysed": r.events_analysed,
        "suspicious_events": r.suspicious_events,
        "critical_alerts": r.critical_alerts,
        "threat_level": r.threat_level,
    }


# Dashboard stats


@app.get("/api/stats")
def get_stats(
    run_id: Optional[int] = None,
    db: Session = Depends(get_db)
):
    rid = _resolve_run_id(db, run_id)

    # Return empty stats if there are no analyses
    if rid is None:
        return {
            "system_status": "NO DATA",
            "threat_level": "LOW",
            "events_analysed": 0,
            "suspicious_events": 0,
            "critical_alerts": 0,
            "run_id": None,
        }

    run = db.query(models.AnalysisRun).get(rid)

    # Medium and below still counts as protected
    system_status = (
        "PROTECTED"
        if run.threat_level in ("LOW", "MEDIUM")
        else "AT RISK"
    )

    return {
        "system_status": system_status,
        "threat_level": run.threat_level,
        "events_analysed": run.events_analysed,
        "suspicious_events": run.suspicious_events,
        "critical_alerts": run.critical_alerts,
        "run_id": run.id,
    }


# Incident details


def _incident_to_dict(i: models.Incident) -> dict:
    # Convert an incident database record into dashboard data
    return {
        "id": i.id,
        "ip": i.ip,
        "country": i.country,
        "is_internal": i.is_internal,
        "primary_rule": i.primary_rule,
        # stored as a comma-separated string in the DB
        "rules_hit": (
            i.rules_hit.split(",")
            if i.rules_hit else []
        ),
        # also comma-separated in the DB
        "targeted_users": (
            i.targeted_users.split(",")
            if i.targeted_users else []
        ),
        "attempts": i.attempts,
        "window_start": (
            i.window_start.isoformat()
            if i.window_start else None
        ),
        "window_end": (
            i.window_end.isoformat()
            if i.window_end else None
        ),
        "duration_seconds": i.duration_seconds,
        "anomaly_score": i.anomaly_score,
        "risk_score": i.risk_score,
        "severity": i.severity,
        # also comma-separated in the DB
        "recommended_actions": (
            i.recommended_actions.split(",")
            if i.recommended_actions else []
        ),
        "detail": i.detail,
    }


@app.get("/api/incidents")
def get_incidents(
    run_id: Optional[int] = None,
    severity: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    rid = _resolve_run_id(db, run_id)

    # Nothing to return if no analysis has been run
    if rid is None:
        return []

    # Get incidents for this analysis
    q = (
        db.query(models.Incident)
        .filter(models.Incident.run_id == rid)
    )

    # Only show a specific severity if requested
    if severity:
        q = q.filter(models.Incident.severity == severity)

    # Show highest risk incidents first, capped at limit
    q = (
        q.order_by(models.Incident.risk_score.desc())
        .limit(limit)
    )

    return [_incident_to_dict(i) for i in q.all()]


@app.get("/api/incidents/latest")
def get_latest_incident(
    run_id: Optional[int] = None,
    db: Session = Depends(get_db)
):
    rid = _resolve_run_id(db, run_id)

    if rid is None:
        return None

    # Powers the "latest incident" card on the dashboard
    i = (
        db.query(models.Incident)
        .filter(models.Incident.run_id == rid)
        .order_by(models.Incident.risk_score.desc())
        .first()
    )

    return _incident_to_dict(i) if i else None


# Dashboard charts


@app.get("/api/severity-distribution")
def severity_distribution(
    run_id: Optional[int] = None,
    db: Session = Depends(get_db)
):
    rid = _resolve_run_id(db, run_id)

    if rid is None:
        return []

    # One row per severity, with a count
    rows = (
        db.query(
            models.Incident.severity,
            func.count(models.Incident.id)
        )
        .filter(models.Incident.run_id == rid)
        .group_by(models.Incident.severity)
        .all()
    )

    # Turn the raw tuples into named fields
    return [
        {"severity": s, "count": c}
        for s, c in rows
    ]


@app.get("/api/top-ips")
def top_ips(
    run_id: Optional[int] = None,
    limit: int = 10,
    db: Session = Depends(get_db)
):
    rid = _resolve_run_id(db, run_id)

    if rid is None:
        return []

    # Get the IPs with the highest risk scores
    rows = (
        db.query(models.Incident)
        .filter(models.Incident.run_id == rid)
        .order_by(models.Incident.risk_score.desc())
        .limit(limit)
        .all()
    )

    # Only the fields the chart actually needs
    return [
        {
            "ip": i.ip,
            "country": i.country,
            "attempts": i.attempts,
            "risk_score": i.risk_score,
            "severity": i.severity
        }
        for i in rows
    ]


@app.get("/api/failed-vs-success")
def failed_vs_success(
    run_id: Optional[int] = None,
    db: Session = Depends(get_db)
):
    rid = _resolve_run_id(db, run_id)

    # Zeros so the chart still renders with no data
    if rid is None:
        return {
            "failed": 0,
            "invalid_user": 0,
            "accepted": 0
        }

    # One row per event type with  count
    rows = (
        db.query(
            models.Event.event_type,
            func.count(models.Event.id)
        )
        .filter(models.Event.run_id == rid)
        .group_by(models.Event.event_type)
        .all()
    )

    # Turn the rows into a simple lookup
    counts = {t: c for t, c in rows}

    # Default to 0 if that event type never happened
    return {
        "failed": counts.get("failed_login", 0),
        "invalid_user": counts.get("invalid_user", 0),
        "accepted": counts.get("accepted_login", 0),
    }


@app.get("/api/timeline")
def timeline(
    run_id: Optional[int] = None,
    db: Session = Depends(get_db)
):
    # Return a timeline of events for the dashboard chart

    rid = _resolve_run_id(db, run_id)

    if rid is None:
        return []

    # Get all events from the selected analysis
    events = (
        db.query(models.Event)
        .filter(models.Event.run_id == rid)
        .all()
    )

    if not events:
        return []

    # Put the events into a DataFrame so we can group them easily
    df = pd.DataFrame([
        {
            "timestamp": e.timestamp,
            "event_type": e.event_type
        }
        for e in events
    ])

    # Round each timestamp down to the start of its hour
    df["bucket"] = df["timestamp"].dt.floor("h")

    # One row per hour, one column per event type
    pivot = df.pivot_table(
        index="bucket",
        columns="event_type",
        aggfunc="size",
        fill_value=0
    )

    result = []

    # Build the shape the chart expects
    for bucket, row in pivot.iterrows():
        result.append({
            "timestamp": bucket.isoformat(),
            # invalid_user counts as failed too
            "failed": (
                int(row.get("failed_login", 0))
                + int(row.get("invalid_user", 0))
            ),
            "accepted": int(
                row.get("accepted_login", 0)
            ),
        })

    return result


@app.get("/api/affected-accounts")
def affected_accounts(
    run_id: Optional[int] = None,
    db: Session = Depends(get_db)
):
    rid = _resolve_run_id(db, run_id)

    if rid is None:
        return []

    # Get all incidents for this analysis
    rows = (
        db.query(models.Incident)
        .filter(models.Incident.run_id == rid)
        .all()
    )

    # Running total of attempts per targeted username
    tally: dict[str, int] = {}

    # One incident can target more than one username
    for r in rows:
        users = (
            r.targeted_users.split(",")
            if r.targeted_users else []
        )

        # Skip empty strings from the split
        for u in users:
            if u:
                tally[u] = tally.get(u, 0) + r.attempts

    # Most attacked account first
    return [
        {"user": u, "attempts": c}
        for u, c in sorted(
            tally.items(),
            key=lambda x: -x[1]
        )
    ]


# API Checks


@app.get("/api/health")
def health():
    # Check that  API is running
    return {
        "status": "ok",
        "time": datetime.utcnow().isoformat()
    }