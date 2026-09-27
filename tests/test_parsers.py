import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.parsers.log_parser import parse_line, parse_log_text


def test_parse_failed_password():
    line = "Sep 20 04:29:00 host sshd[123]: Failed password for admin from 1.2.3.4 port 51422 ssh2"
    rec = parse_line(line, assumed_year=2026)
    assert rec is not None
    assert rec["event_type"] == "failed_login"
    assert rec["user"] == "admin"
    assert rec["ip"] == "1.2.3.4"
    assert rec["port"] == 51422


def test_parse_failed_password_invalid_user():
    line = "Sep 20 04:29:00 host sshd[123]: Failed password for invalid user bob from 5.6.7.8 port 40000 ssh2"
    rec = parse_line(line, assumed_year=2026)
    assert rec["event_type"] == "failed_login"
    assert rec["user"] == "bob"


def test_parse_invalid_user():
    line = "Sep 20 04:29:00 host sshd[123]: Invalid user ghost from 9.9.9.9 port 22000"
    rec = parse_line(line, assumed_year=2026)
    assert rec["event_type"] == "invalid_user"
    assert rec["user"] == "ghost"


def test_parse_accepted():
    line = "Sep 20 04:29:00 host sshd[123]: Accepted password for jsmith from 10.0.0.5 port 51000 ssh2"
    rec = parse_line(line, assumed_year=2026)
    assert rec["event_type"] == "accepted_login"


def test_parse_unrecognised_line_returns_none():
    assert parse_line("this is not a log line", 2026) is None


def test_parse_log_text_multi_line():
    text = "\n".join([
        "Sep 20 04:29:00 host sshd[1]: Failed password for admin from 1.2.3.4 port 1 ssh2",
        "Sep 20 04:29:05 host sshd[2]: Accepted password for admin from 1.2.3.4 port 2 ssh2",
        "garbage line that should be skipped",
    ])
    df = parse_log_text(text, assumed_year=2026)
    assert len(df) == 2
    assert list(df.event_type) == ["failed_login", "accepted_login"]
