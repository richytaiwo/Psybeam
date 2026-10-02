import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pandas as pd
from datetime import datetime, timedelta

from backend.detection.anomaly import build_ip_features, run_anomaly_detection
from backend.detection.risk import build_incidents, severity_for_score


# Check IP features are being created correctly
def test_build_ip_features_shape():
    start = datetime(2026, 1, 1, 9, 0, 0)

    # Create 10 normal login events from one IP
    rows = [
        {
            "timestamp": start + timedelta(minutes=i),
            "event_type": "accepted_login",
            "user": "jsmith",
            "ip": "10.0.0.5",
            "port": 1000 + i,
            "host": "h",
            "raw": ""
        }
        for i in range(10)
    ]

    df = pd.DataFrame(rows)
    features = build_ip_features(df)

    # One row because as only one IP
    assert len(features) == 1
    assert features.iloc[0]["ip"] == "10.0.0.5"
    assert features.iloc[0]["total_events"] == 10


# Check that Isolation Forest can spot an weird IP
def test_run_anomaly_detection_flags_outlier_ip():
    start = datetime(2026, 1, 1, 9, 0, 0)
    rows = []

    # Create normal daytime activity for 10 different IPs
    for n in range(10):
        for i in range(5):
            rows.append({
                "timestamp": start + timedelta(minutes=i * 3),
                "event_type": "accepted_login",
                "user": "jsmith",
                "ip": f"10.0.0.{n}",
                "port": 1000 + i,
                "host": "h",
                "raw": ""
            })

    # Create one suspicious IP with lots of failed logins at night with many different usernames
    burst_start = datetime(2026, 1, 1, 2, 0, 0)

    for i in range(40):
        rows.append({
            "timestamp": burst_start + timedelta(seconds=i * 2),
            "event_type": "failed_login",
            "user": f"user{i}",
            "ip": "66.66.66.66",
            "port": 2000 + i,
            "host": "h",
            "raw": ""
        })

    df = pd.DataFrame(rows)

    # Run anomaly detector
    result = run_anomaly_detection(df, contamination=0.15)

    # Compare the suspicious IP with normal IP
    outlier_row = result[result.ip == "66.66.66.66"].iloc[0]
    normal_row = result[result.ip == "10.0.0.0"].iloc[0]

    # Suspicious IP should have a higher anomaly score
    assert outlier_row["anomaly_score"] > normal_row["anomaly_score"]


# Check risk scores are changed into the right severity
def test_severity_bands():
    assert severity_for_score(10) == "informational"
    assert severity_for_score(30) == "low"
    assert severity_for_score(60) == "high"
    assert severity_for_score(90) == "critical"


# Check multiple alerts from the same IP become one incident
def test_build_incidents_groups_by_ip():
    start = datetime(2026, 1, 1, 3, 0, 0)

    # Two different detection rules triggered by the same IP
    signals = [
        {
            "rule": "brute_force",
            "ip": "1.1.1.1",
            "user": "admin",
            "window_start": start,
            "window_end": start + timedelta(minutes=2),
            "count": 10,
            "detail": "10 failed attempts"
        },
        {
            "rule": "odd_hours",
            "ip": "1.1.1.1",
            "user": "admin",
            "window_start": start,
            "window_end": start,
            "count": 1,
            "detail": "odd hour login"
        }
    ]

    incidents = build_incidents(signals, pd.DataFrame())

    # Both alerts should be one incident
    assert len(incidents) == 1
    assert incidents[0]["ip"] == "1.1.1.1"

    # Make sure both detection rules were recorded
    assert set(incidents[0]["rules_hit"]) == {"brute_force", "odd_hours"}

    # Incident should have a risk score
    assert incidents[0]["risk_score"] > 0