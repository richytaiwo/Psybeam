from datetime import datetime
import pandas as pd
from sqlalchemy.orm import Session

from backend.parsers.log_parser import parse_log_file, parse_log_text
from backend.detection.rules import run_all_rules
from backend.detection.anomaly import run_anomaly_detection
from backend.detection.risk import build_incidents, overall_threat_level
from backend.database import models
from backend.notifications.discord import maybe_notify_discord


def _persist(
    db: Session,
    df: pd.DataFrame,
    incidents: list[dict],
    source_filename: str | None
) -> models.AnalysisRun:

    # Create a record for this analysis
    run = models.AnalysisRun(
        source_filename=source_filename,
        started_at=datetime.utcnow(),
        events_analysed=len(df),
        suspicious_events=sum(i["attempts"] for i in incidents),
        critical_alerts=sum(
            1 for i in incidents
            if i["severity"] == "critical"
        ),
        threat_level=overall_threat_level(incidents),
    )

    db.add(run)

    # Get the ID for this analysis
    db.flush()

    # Save the log events to the database
    event_rows = df.to_dict("records") if not df.empty else []

    for row in event_rows:
        db.add(models.Event(
            run_id=run.id,
            timestamp=row["timestamp"],
            event_type=row["event_type"],
            user=row["user"],
            ip=row["ip"],
            port=row.get("port"),
            host=row.get("host"),
            raw=row.get("raw"),
        ))

    # Save the security incidents
    for inc in incidents:
        db.add(models.Incident(
            run_id=run.id,
            ip=inc["ip"],
            country=inc["country"],
            is_internal=inc["is_internal"],
            primary_rule=inc["primary_rule"],
            rules_hit=",".join(inc["rules_hit"]),
            targeted_users=",".join(inc["targeted_users"]),
            attempts=inc["attempts"],
            window_start=inc["window_start"],
            window_end=inc["window_end"],
            duration_seconds=inc["duration_seconds"],
            anomaly_score=inc["anomaly_score"],
            risk_score=inc["risk_score"],
            severity=inc["severity"],
            recommended_actions=",".join(inc["recommended_actions"]),
            detail=inc["detail"],
        ))

    # Save everything to the database
    db.commit()
    db.refresh(run)

    return run


def analyze_file(
    db: Session,
    path: str,
    config: dict | None = None
) -> models.AnalysisRun:

    # Parse the log file
    df = parse_log_file(path)

    return _analyze_dataframe(
        db,
        df,
        config,
        source_filename=path
    )


def analyze_text(
    db: Session,
    text: str,
    filename: str | None,
    config: dict | None = None
) -> models.AnalysisRun:

    # Parse the log text
    df = parse_log_text(text)

    return _analyze_dataframe(
        db,
        df,
        config,
        source_filename=filename
    )


def _analyze_dataframe(
    db: Session,
    df: pd.DataFrame,
    config: dict | None,
    source_filename: str | None
) -> models.AnalysisRun:

    # Run the detection rules
    signals = run_all_rules(df, config)

    # Check for unusual IP behaviour
    anomaly_df = run_anomaly_detection(df)

    # Combine everything into incidents
    incidents = build_incidents(
        signals,
        anomaly_df
    )

    # Save the results
    run = _persist(
        db,
        df,
        incidents,
        source_filename
    )

    # Send a Discord alert for critical incidents
    critical = [
        i for i in incidents
        if i["severity"] == "critical"
    ]

    if critical:
        maybe_notify_discord(critical[0])

    return run