"""Parsers that normalize raw log lines into Event objects.

Two source formats are supported out of the box:

* Auth logs (rsyslog/sshd/sudo style), one line per event:
    2026-08-30T03:14:02+00:00 web01 sshd[1204]: Failed password for invalid user admin from 203.0.113.45 port 51422 ssh2

* Firewall/netflow logs, CSV with header:
    timestamp,src_ip,dst_ip,dst_port,protocol,action,bytes

Both parsers are intentionally forgiving: a malformed line is skipped
rather than raising, and skipped-line counts are returned to the caller
so bad input is visible without crashing a run.
"""
from __future__ import annotations

import csv
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Tuple

ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")


@dataclass
class Event:
    """A single normalized log event."""

    timestamp: datetime
    source: str          # "auth" or "firewall"
    event_type: str       # e.g. "ssh_failed_password", "ssh_accepted_password",
                           # "sudo_auth_failure", "sudo_command", "firewall_flow"
    host: str = ""
    user: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int = 0
    protocol: str = ""
    action: str = ""
    bytes: int = 0
    raw: str = ""
    fields: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = dict(self.__dict__)
        d["timestamp"] = self.timestamp.isoformat()
        return d


_SSH_FAILED_RE = re.compile(
    r"sshd\[\d+\]: Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)"
)
_SSH_ACCEPTED_RE = re.compile(
    r"sshd\[\d+\]: Accepted password for (?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)"
)
_SUDO_FAIL_RE = re.compile(
    r"sudo:.*pam_unix\(sudo:auth\): authentication failure;.*logname=(?P<logname>\S*)"
    r".*\buser=(?P<user>\S+)"
)
_SUDO_CMD_RE = re.compile(
    r"sudo:\s+(?P<user>\S+)\s*:.*COMMAND=(?P<command>.+)$"
)
_HOST_RE = re.compile(r"^(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<rest>.+)$")


def parse_auth_line(line: str) -> Tuple[Event, None] | Tuple[None, str]:
    """Parse one auth-log line. Returns (Event, None) or (None, reason)."""
    line = line.rstrip("\n")
    if not line.strip():
        return None, "blank"
    m = _HOST_RE.match(line)
    if not m or not ISO_RE.match(m.group("ts")):
        return None, "no-timestamp"
    ts_raw, host, rest = m.group("ts"), m.group("host"), m.group("rest")
    try:
        ts = datetime.fromisoformat(ts_raw)
    except ValueError:
        return None, "bad-timestamp"

    fm = _SSH_FAILED_RE.search(rest)
    if fm:
        return Event(
            timestamp=ts, source="auth", event_type="ssh_failed_password",
            host=host, user=fm.group("user"), src_ip=fm.group("ip"),
            dst_port=int(fm.group("port")), raw=line,
        ), None

    am = _SSH_ACCEPTED_RE.search(rest)
    if am:
        return Event(
            timestamp=ts, source="auth", event_type="ssh_accepted_password",
            host=host, user=am.group("user"), src_ip=am.group("ip"),
            dst_port=int(am.group("port")), raw=line,
        ), None

    sf = _SUDO_FAIL_RE.search(rest)
    if sf:
        return Event(
            timestamp=ts, source="auth", event_type="sudo_auth_failure",
            host=host, user=sf.group("user") or sf.group("logname"), raw=line,
        ), None

    sc = _SUDO_CMD_RE.search(rest)
    if sc:
        return Event(
            timestamp=ts, source="auth", event_type="sudo_command",
            host=host, user=sc.group("user"), raw=line,
            fields={"command": sc.group("command")},
        ), None

    return None, "unmatched"


def parse_auth_log(path: str) -> Tuple[List[Event], Dict[str, int]]:
    events: List[Event] = []
    skipped: Dict[str, int] = {}
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            evt, reason = parse_auth_line(line)
            if evt is not None:
                events.append(evt)
            elif reason and reason != "blank":
                skipped[reason] = skipped.get(reason, 0) + 1
    return events, skipped


def parse_firewall_log(path: str) -> Tuple[List[Event], Dict[str, int]]:
    events: List[Event] = []
    skipped: Dict[str, int] = {}
    with open(path, "r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        required = {"timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "action", "bytes"}
        if not required.issubset(set(reader.fieldnames or [])):
            raise ValueError(
                f"firewall log missing required columns: {required - set(reader.fieldnames or [])}"
            )
        for row in reader:
            try:
                ts = datetime.fromisoformat(row["timestamp"])
                events.append(Event(
                    timestamp=ts, source="firewall", event_type="firewall_flow",
                    src_ip=row["src_ip"], dst_ip=row["dst_ip"],
                    dst_port=int(row["dst_port"]), protocol=row["protocol"],
                    action=row["action"], bytes=int(row["bytes"]),
                    raw=",".join(row.values()),
                ))
            except (ValueError, KeyError):
                skipped["bad-row"] = skipped.get("bad-row", 0) + 1
    return events, skipped


def load_events(auth_path: str | None, firewall_path: str | None) -> Tuple[List[Event], Dict[str, int]]:
    """Load and merge events from both sources, sorted by timestamp."""
    all_events: List[Event] = []
    all_skipped: Dict[str, int] = {}

    if auth_path:
        evts, skipped = parse_auth_log(auth_path)
        all_events.extend(evts)
        for k, v in skipped.items():
            all_skipped[k] = all_skipped.get(k, 0) + v

    if firewall_path:
        evts, skipped = parse_firewall_log(firewall_path)
        all_events.extend(evts)
        for k, v in skipped.items():
            all_skipped[k] = all_skipped.get(k, 0) + v

    all_events.sort(key=lambda e: e.timestamp)
    return all_events, all_skipped
