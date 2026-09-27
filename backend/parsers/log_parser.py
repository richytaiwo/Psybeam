import re
from datetime import datetime
import pandas as pd

# Match the start of the log line
SYSLOG_PREFIX = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<msg>.*)$"
)

# Check for different types of login events
PATTERNS = [
    ("failed_login", re.compile(
        r"^Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
    )),
    ("invalid_user", re.compile(
        r"^Invalid user (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
    )),
    ("accepted_login", re.compile(
        r"^Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
    )),
]

def parse_line(line: str, assumed_year: int):
    # Match the log line
    m = SYSLOG_PREFIX.match(line.strip())
    if not m:
        return None

    # Add the year to the timestamp
    ts_str = f"{assumed_year} {m.group('month')} {m.group('day')} {m.group('time')}"

    try:
        ts = datetime.strptime(ts_str, "%Y %b %d %H:%M:%S")
    except ValueError:
        return None

    msg = m.group("msg")

    # Check what type of login event it is
    for event_type, pattern in PATTERNS:
        pm = pattern.match(msg)

        if pm:
            gd = pm.groupdict()

            # Store the event details
            return {
                "timestamp": ts,
                "event_type": event_type,
                "user": gd.get("user"),
                "ip": gd.get("ip"),
                "port": int(gd["port"]) if gd.get("port") else None,
                "host": m.group("host"),
                "raw": line.strip(),
            }

    return None


def parse_log_file(path: str, assumed_year: int = None) -> pd.DataFrame:
    """Parse a log file into a DataFrame."""

    if assumed_year is None:
        assumed_year = datetime.now().year

    records = []

    # Read each line in the log
    with open(path, "r", errors="ignore") as f:
        for line in f:
            rec = parse_line(line, assumed_year)

            if rec:
                records.append(rec)

    # Return an empty DataFrame if nothing was found
    if not records:
        return pd.DataFrame(
            columns=[
                "timestamp",
                "event_type",
                "user",
                "ip",
                "port",
                "host",
                "raw"
            ]
        )

    df = pd.DataFrame(records)

    # Sort the events by time
    df.sort_values("timestamp", inplace=True)
    df.reset_index(drop=True, inplace=True)

    return df


def parse_log_text(text: str, assumed_year: int = None) -> pd.DataFrame:
    """Parse log text into a DataFrame."""

    if assumed_year is None:
        assumed_year = datetime.now().year

    records = []

    # Check each line in the text
    for line in text.splitlines():
        rec = parse_line(line, assumed_year)

        if rec:
            records.append(rec)

    # Return an empty DataFrame if nothing was found
    if not records:
        return pd.DataFrame(
            columns=[
                "timestamp",
                "event_type",
                "user",
                "ip",
                "port",
                "host",
                "raw"
            ]
        )

    df = pd.DataFrame(records)

    # Sort the events by time
    df.sort_values("timestamp", inplace=True)
    df.reset_index(drop=True, inplace=True)

    return df