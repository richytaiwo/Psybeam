import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest

from .geoip import is_private

# Features used by the anomaly detection model
FEATURE_COLUMNS = [
    "total_events", "failed_ratio", "distinct_users", "distinct_ports",
    "avg_hour", "night_ratio", "events_per_minute_peak", "is_internal",
]


def build_ip_features(df: pd.DataFrame) -> pd.DataFrame:
    # Return an empty DataFrame if there are no events
    if df.empty:
        return pd.DataFrame(columns=["ip"] + FEATURE_COLUMNS)

    rows = []

    # Build features for each IP address
    for ip, group in df.groupby("ip"):
        total = len(group)

        # Count failed login attempts
        failed = (
            group.event_type.isin(["failed_login", "invalid_user"])
        ).sum()

        # Count logins that happened between midnight and 6am
        night = (
            (group.timestamp.dt.hour >= 0) &
            (group.timestamp.dt.hour < 6)
        ).sum()

        # Find the highest number of events in 60 seconds
        ts_sorted = group.timestamp.sort_values().reset_index(drop=True)

        peak = 1
        j = 0

        for i in range(len(ts_sorted)):
            while ts_sorted[i] - ts_sorted[j] > pd.Timedelta(seconds=60):
                j += 1

            peak = max(peak, i - j + 1)

        rows.append({
            "ip": ip,
            "total_events": total,
            "failed_ratio": failed / total if total else 0,
            "distinct_users": group.user.nunique(),
            "distinct_ports": group.port.nunique(),
            "avg_hour": group.timestamp.dt.hour.mean(),
            "night_ratio": night / total if total else 0,
            "events_per_minute_peak": peak,

            # Mark private IP addresses as internal
            "is_internal": 1 if is_private(ip) else 0,
        })

    return pd.DataFrame(rows)


def score_anomalies(
    feature_df: pd.DataFrame,
    contamination: float = 0.15,
    random_state: int = 42
) -> pd.DataFrame:
    # Add anomaly scores to ip feature data

    result = feature_df.copy()

    # Not enough data to train the model
    if len(result) < 3:
        result["anomaly_score"] = 0.0
        result["is_anomaly"] = False
        return result

    # Get the features used by the model
    X = result[FEATURE_COLUMNS].fillna(0).to_numpy()

    # Create and train the Isolation Forest model
    model = IsolationForest(
        contamination=contamination,
        random_state=random_state
    )

    model.fit(X)

    # Convert the model scores so higher means more suspicious
    raw_scores = -model.score_samples(X)

    # Convert the scores to a 0 to 100 range
    lo, hi = raw_scores.min(), raw_scores.max()

    if hi > lo:
        normalised = (raw_scores - lo) / (hi - lo) * 100
    else:
        normalised = np.zeros_like(raw_scores)

    result["anomaly_score"] = normalised.round(1)

    # Isolation Forest uses -1 for anomalies
    result["is_anomaly"] = model.predict(X) == -1

    return result


def run_anomaly_detection(
    df: pd.DataFrame,
    contamination: float = 0.15
) -> pd.DataFrame:
    # Build the features and run the anomaly model
    features = build_ip_features(df)

    return score_anomalies(
        features,
        contamination=contamination
    )