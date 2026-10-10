import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from log_correlator.parser import parse_auth_line, load_events

SAMPLE_DIR = Path(__file__).parent.parent / "data" / "sample_logs"


def test_parse_ssh_failed_password():
    line = "2026-08-30T03:14:02+00:00 web01 sshd[1204]: Failed password for invalid user admin from 203.0.113.45 port 51422 ssh2"
    evt, reason = parse_auth_line(line)
    assert reason is None
    assert evt.event_type == "ssh_failed_password"
    assert evt.user == "admin"
    assert evt.src_ip == "203.0.113.45"
    assert evt.dst_port == 51422
    assert evt.timestamp == datetime.fromisoformat("2026-08-30T03:14:02+00:00")


def test_parse_ssh_accepted_password_valid_user_no_invalid_prefix():
    line = "2026-08-30T03:14:52+00:00 web01 sshd[1211]: Accepted password for root from 203.0.113.45 port 51478 ssh2"
    evt, reason = parse_auth_line(line)
    assert reason is None
    assert evt.event_type == "ssh_accepted_password"
    assert evt.user == "root"


def test_parse_sudo_auth_failure():
    line = (
        "2026-08-30T03:25:00+00:00 web01 sudo: pam_unix(sudo:auth): authentication failure; "
        "logname=hans uid=1000 euid=0 tty=/dev/pts/0 ruser=hans rhost=  user=hans"
    )
    evt, reason = parse_auth_line(line)
    assert reason is None
    assert evt.event_type == "sudo_auth_failure"
    assert evt.user == "hans"


def test_parse_sudo_command():
    line = "2026-08-30T03:25:31+00:00 web01 sudo: hans : TTY=pts/0 ; PWD=/home/hans ; USER=root ; COMMAND=/usr/sbin/useradd -m svc-backup"
    evt, reason = parse_auth_line(line)
    assert reason is None
    assert evt.event_type == "sudo_command"
    assert evt.user == "hans"
    assert "useradd" in evt.fields["command"]


def test_parse_line_without_timestamp_is_skipped():
    evt, reason = parse_auth_line("not a real log line at all")
    assert evt is None
    assert reason == "no-timestamp"


def test_parse_blank_line_is_skipped_silently():
    evt, reason = parse_auth_line("\n")
    assert evt is None
    assert reason == "blank"


def test_load_events_merges_and_sorts_both_sources():
    events, skipped = load_events(
        str(SAMPLE_DIR / "auth.log"),
        str(SAMPLE_DIR / "firewall.csv"),
    )
    assert len(events) > 0
    timestamps = [e.timestamp for e in events]
    assert timestamps == sorted(timestamps)
    sources = {e.source for e in events}
    assert sources == {"auth", "firewall"}
