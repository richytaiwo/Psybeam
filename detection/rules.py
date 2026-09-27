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

