from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, Text
from backend.database.db import Base


# Stores information about each time Psybeam analyses a log file
class AnalysisRun(Base):
    __tablename__ = "analysis_runs"

    id = Column(Integer, primary_key=True, index=True)
    source_filename = Column(String, nullable=True)
    started_at = Column(DateTime)

    # Store basic results from the analysis
    events_analysed = Column(Integer, default=0)
    suspicious_events = Column(Integer, default=0)
    critical_alerts = Column(Integer, default=0)
    threat_level = Column(String, default="LOW")


# Stores each login event found in a log file
class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, index=True)
    timestamp = Column(DateTime, index=True)
    event_type = Column(String, index=True)
    user = Column(String, index=True)
    ip = Column(String, index=True)
    port = Column(Integer, nullable=True)
    host = Column(String, nullable=True)

    # Keep the original log line for reference
    raw = Column(Text, nullable=True)


# Stores security incidents found by Psybeam
class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, index=True)

    # Basic information about the source
    ip = Column(String, index=True)
    country = Column(String, nullable=True)
    is_internal = Column(Boolean, default=False)

    # Information about what triggered the incident
    primary_rule = Column(String, index=True)
    rules_hit = Column(String)
    targeted_users = Column(String)

    attempts = Column(Integer, default=0)

    # When the suspicious activity happened
    window_start = Column(DateTime)
    window_end = Column(DateTime)
    duration_seconds = Column(Float)

    # Scores from the detection system
    anomaly_score = Column(Float, default=0.0)
    risk_score = Column(Float, index=True)
    severity = Column(String, index=True)

    # Store actions and extra information about the incident
    recommended_actions = Column(Text)
    detail = Column(Text)