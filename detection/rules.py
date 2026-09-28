import pandas as pd

def detect_bruteforce(df: pd.DataFrame, window_minutes: int = 5, threshold: int = 5):
    # Flags a single IP attempting the same username many times in a short
    signals = []

    # Only look at failed login attempts
    failed = df[df.event_type.isin(["failed_login", "invalid_user"])].copy()
    if failed.empty:
        return signals

    # Check each IP and user combination
    for (ip, user), group in failed.groupby(["ip", "user"]):
        group = group.sort_values("timestamp")
        times = group["timestamp"].tolist()
        window = pd.Timedelta(minutes=window_minutes)

        start_idx = 0
        for end_idx in range(len(times)):
            # Move the start of the window forward when needed
            while times[end_idx] - times[start_idx] > window:
                start_idx += 1

            count = end_idx - start_idx + 1

            # Check if enough failed attempts happened
            if count >= threshold:
                signals.append({
                    "rule": "brute_force",
                    "ip": ip,
                    "user": user,
                    "window_start": times[start_idx],
                    "window_end": times[end_idx],
                    "count": count,
                    "detail": f"{count} failed attempts against '{user}' "
                              f"in {window_minutes}m from {ip}",
                })
                break
    return signals


def detect_credential_stuffing(df: pd.DataFrame, window_minutes: int = 15,
                                distinct_user_threshold: int = 5):
    
    # Flags a single IP attempting many different usernames in a short
    signals = []

    # Only look at failed login attempts
    failed = df[df.event_type.isin(["failed_login", "invalid_user"])].copy()
    if failed.empty:
        return signals

    # Check each IP separately
    for ip, group in failed.groupby("ip"):
        group = group.sort_values("timestamp")
        times = group["timestamp"].tolist()
        users = group["user"].tolist()
        window = pd.Timedelta(minutes=window_minutes)

        start_idx = 0
        for end_idx in range(len(times)):
            # Move the start of the window forward when needed
            while times[end_idx] - times[start_idx] > window:
                start_idx += 1

            # Count how many different usernames were tried
            distinct_users = set(users[start_idx:end_idx + 1])

            # Check if enough different usernames were tried
            if len(distinct_users) >= distinct_user_threshold:
                signals.append({
                    "rule": "credential_stuffing",
                    "ip": ip,
                    "user": None,
                    "window_start": times[start_idx],
                    "window_end": times[end_idx],
                    "count": len(distinct_users),
                    "detail": f"{len(distinct_users)} distinct usernames tried "
                              f"from {ip} in {window_minutes}m",
                })
                break
    return signals


def detect_odd_hours(df: pd.DataFrame, start_hour: int = 6, end_hour: int = 22):
    
    # Flags logins outside of normal business hours
    signals = []

    # Find logins outside normal hours
    outside = df[
        (df.timestamp.dt.hour < start_hour) |
        (df.timestamp.dt.hour >= end_hour)
    ]

    # Check each IP, user and event type
    for (ip, user, event_type), group in outside.groupby(
        ["ip", "user", "event_type"]
    ):
        signals.append({
            "rule": "odd_hours",
            "ip": ip,
            "user": user,
            "window_start": group.timestamp.min(),
            "window_end": group.timestamp.max(),
            "count": len(group),
            "detail": f"{len(group)} {event_type.replace('_', ' ')} event(s) for "
                      f"'{user}' outside {start_hour:02d}:00-{end_hour:02d}:00 from {ip}",
        })
    return signals


def detect_successful_after_failures(df: pd.DataFrame, min_prior_failures: int = 5,
                                      window_minutes: int = 20):
    
    # Flags a successful login after many failed attempts from the same IP, bruteforce worked
    signals = []

    # Check each IP separately
    for ip, group in df.groupby("ip"):
        group = group.sort_values("timestamp")
        window = pd.Timedelta(minutes=window_minutes)
        rows = group.to_dict("records")

        for i, row in enumerate(rows):
            # Only check successful logins
            if row["event_type"] != "accepted_login":
                continue

            # Find recent failed attempts before the successful login
            prior_failures = [
                r for r in rows[:i]
                if r["event_type"] in ("failed_login", "invalid_user")
                and row["timestamp"] - r["timestamp"] <= window
            ]

            # Flag the login if there were enough failed attempts
            if len(prior_failures) >= min_prior_failures:
                signals.append({
                    "rule": "compromise_suspected",
                    "ip": ip,
                    "user": row["user"],
                    "window_start": prior_failures[0]["timestamp"],
                    "window_end": row["timestamp"],
                    "count": len(prior_failures) + 1,
                    "detail": f"Login to '{row['user']}' succeeded from {ip} after "
                              f"{len(prior_failures)} failed attempts",
                })
    return signals


def run_all_rules(df: pd.DataFrame, config: dict | None = None):
    cfg = config or {}
    signals = []

    # Run the brute force detector
    signals += detect_bruteforce(
        df,
        window_minutes=cfg.get("bruteforce_window_minutes", 5),
        threshold=cfg.get("bruteforce_threshold", 5),
    )

    # Run the credential stuffing detector
    signals += detect_credential_stuffing(
        df,
        window_minutes=cfg.get("stuffing_window_minutes", 15),
        distinct_user_threshold=cfg.get("stuffing_distinct_users", 5),
    )

    # Run the odd hours detector
    signals += detect_odd_hours(
        df,
        start_hour=cfg.get("business_start_hour", 6),
        end_hour=cfg.get("business_end_hour", 22),
    )

    # Check for a successful login after multiple failures
    signals += detect_successful_after_failures(
        df,
        min_prior_failures=cfg.get("compromise_min_failures", 5),
        window_minutes=cfg.get("compromise_window_minutes", 20),
    )

    # Return all detected signals
    return signals