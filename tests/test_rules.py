import sys, os

# Lets Python find the backend folder when running this test 
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pandas as pd
from datetime import datetime, timedelta

from backend.detection.rules import (
    detect_bruteforce,
    detect_credential_stuffing,
    detect_odd_hours,
    detect_successful_after_failures,
)


# Turn test data into a df, which is what the detection rules expect.
def make_df(rows):
    return pd.DataFrame(rows)


def test_detect_bruteforce_flags_fast_repeated_failures():
    start = datetime(2026, 1, 1, 3, 0, 0)

    # Create 6 failed logins from the same IP and user, 5 seconds apart to look like brute force.
    rows = [
        {
            "timestamp": start + timedelta(seconds=i * 5),
            "event_type": "failed_login",
            "user": "admin",
            "ip": "1.2.3.4",
            "port": 100 + i,
            "host": "h",
            "raw": "",
        }
        for i in range(6)
    ]

    signals = detect_bruteforce(
        make_df(rows),
        window_minutes=5,
        threshold=5
    )

    # Expect detector to find one attack.
    assert len(signals) == 1

    # Check was correctly identified as brute force.
    assert signals[0]["rule"] == "brute_force"

    # Check the correct IP was detected.
    assert signals[0]["ip"] == "1.2.3.4"

    # 5 attempts should have been detected.
    assert signals[0]["count"] >= 5


def test_detect_bruteforce_ignores_sparse_failures():
    start = datetime(2026, 1, 1, 3, 0, 0)

    # 30 minutes apart so should not count as failures in a 5 minute window.
    rows = [
        {
            "timestamp": start + timedelta(minutes=i * 30),
            "event_type": "failed_login",
            "user": "admin",
            "ip": "1.2.3.4",
            "port": 100 + i,
            "host": "h",
            "raw": "",
        }
        for i in range(6)
    ]

    signals = detect_bruteforce(
        make_df(rows),
        window_minutes=5,
        threshold=5
    )

    # No attack should be detected.
    assert signals == []


def test_detect_credential_stuffing():
    start = datetime(2026, 1, 1, 3, 0, 0)

    # Same IP tries 6 different usernames which should look like cred stuffing.
    rows = [
        {
            "timestamp": start + timedelta(seconds=i * 10),
            "event_type": "invalid_user",
            "user": f"user{i}",
            "ip": "9.9.9.9",
            "port": 100,
            "host": "h",
            "raw": "",
        }
        for i in range(6)
    ]

    signals = detect_credential_stuffing(
        make_df(rows),
        window_minutes=15,
        distinct_user_threshold=5
    )

    assert len(signals) == 1
    assert signals[0]["rule"] == "credential_stuffing"


def test_detect_odd_hours_flags_night_login():
    # Login at 3 AM should be flagged as outside normal hours.
    rows = [{
        "timestamp": datetime(2026, 1, 1, 3, 0, 0),
        "event_type": "accepted_login",
        "user": "root",
        "ip": "1.1.1.1",
        "port": 1,
        "host": "h",
        "raw": "",
    }]

    signals = detect_odd_hours(
        make_df(rows),
        start_hour=6,
        end_hour=22
    )

    assert len(signals) == 1


def test_detect_odd_hours_ignores_daytime_login():
    # Login at 2 PM is inside normal hours, so  should be ignored.
    rows = [{
        "timestamp": datetime(2026, 1, 1, 14, 0, 0),
        "event_type": "accepted_login",
        "user": "root",
        "ip": "1.1.1.1",
        "port": 1,
        "host": "h",
        "raw": "",
    }]

    signals = detect_odd_hours(
        make_df(rows),
        start_hour=6,
        end_hour=22
    )

    # No suspicious activity should be returned.
    assert signals == []


def test_detect_successful_after_failures():
    start = datetime(2026, 1, 1, 3, 0, 0)

    # Create 6 failed attempts against the deploy account.
    rows = [
        {
            "timestamp": start + timedelta(seconds=i * 10),
            "event_type": "failed_login",
            "user": "deploy",
            "ip": "1.1.1.1",
            "port": 1,
            "host": "h",
            "raw": "",
        }
        for i in range(6)
    ]

    # The attacker then successfully logs in, serious as attack may have worked.
    rows.append({
        "timestamp": start + timedelta(seconds=70),
        "event_type": "accepted_login",
        "user": "deploy",
        "ip": "1.1.1.1",
        "port": 1,
        "host": "h",
        "raw": "",
    })

    signals = detect_successful_after_failures(
        make_df(rows),
        min_prior_failures=5,
        window_minutes=20
    )

    assert len(signals) == 1

    # Make sure Psybeam calls it a potential compromise.
    assert signals[0]["rule"] == "compromise_suspected"