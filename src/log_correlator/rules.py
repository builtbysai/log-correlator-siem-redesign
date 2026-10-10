"""Detection rules that turn sequences of Events into Incidents.

Each rule is a small, independently testable function with the signature
``rule(events: List[Event]) -> List[Incident]``. Rules never mutate the
input list. Keeping each rule self-contained (rather than one large
stateful loop) makes it straightforward to add, disable, or unit-test a
single detection without touching the others.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Dict, List

from .parser import Event

SEVERITY_ORDER = {"critical": 3, "high": 2, "medium": 1, "low": 0}


@dataclass
class Incident:
    rule_id: str
    mitre_id: str
    mitre_tactic: str
    mitre_technique: str
    severity: str
    title: str
    description: str
    entities: Dict[str, str]
    evidence: List[Event] = field(default_factory=list)
    recommended_action: str = ""

    @property
    def first_seen(self):
        return min(e.timestamp for e in self.evidence)

    @property
    def last_seen(self):
        return max(e.timestamp for e in self.evidence)


_RFC1918_NETS = tuple(
    ipaddress.ip_network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


def _is_internal(ip: str) -> bool:
    """True for RFC1918 private-network addresses (our stand-in for "on our
    LAN"). Deliberately narrower than ipaddress.is_private, which also
    classifies RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24,
    203.0.113.0/24) as private — those ranges are used throughout this
    project's sample data to represent external/attacker addresses, so
    treating them as "internal" would silently defeat the exfiltration
    rule below.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _RFC1918_NETS)


def rule_brute_force_ssh(
    events: List[Event],
    threshold: int = 5,
    window: timedelta = timedelta(minutes=2),
) -> List[Incident]:
    """R001 - T1110.001 Brute Force: Password Guessing.

    Flags a source IP that racks up ``threshold`` or more failed SSH
    password attempts inside a rolling ``window``.
    """
    fails = [e for e in events if e.event_type == "ssh_failed_password"]
    by_ip: Dict[str, List[Event]] = {}
    for e in fails:
        by_ip.setdefault(e.src_ip, []).append(e)

    incidents: List[Incident] = []
    for ip, evts in by_ip.items():
        evts.sort(key=lambda e: e.timestamp)
        start = 0
        for end in range(len(evts)):
            while evts[end].timestamp - evts[start].timestamp > window:
                start += 1
            burst = evts[start:end + 1]
            if len(burst) >= threshold:
                users = sorted({e.user for e in burst})
                incidents.append(Incident(
                    rule_id="R001",
                    mitre_id="T1110.001",
                    mitre_tactic="Credential Access",
                    mitre_technique="Brute Force: Password Guessing",
                    severity="high",
                    title=f"SSH brute force from {ip}",
                    description=(
                        f"{len(burst)} failed SSH password attempts from {ip} within "
                        f"{int(window.total_seconds())}s, targeting user(s): {', '.join(users)}."
                    ),
                    entities={"src_ip": ip, "users": ", ".join(users)},
                    evidence=burst,
                    recommended_action=(
                        "Block or rate-limit the source IP, confirm targeted accounts were not "
                        "compromised, and review fail2ban / SSH key-only auth policy."
                    ),
                ))
                start = end + 1  # avoid overlapping duplicate incidents for the same burst
    return _dedupe_by_window(incidents)


def rule_valid_account_after_brute_force(
    events: List[Event],
    brute_force_incidents: List[Incident],
    window: timedelta = timedelta(minutes=5),
) -> List[Incident]:
    """R002 - T1078 Valid Accounts.

    Flags a successful SSH login from an IP that had a brute-force
    incident shortly beforehand, i.e. the guessing likely succeeded.
    """
    accepted = [e for e in events if e.event_type == "ssh_accepted_password"]
    incidents: List[Incident] = []
    for bf in brute_force_incidents:
        ip = bf.entities["src_ip"]
        for e in accepted:
            if e.src_ip == ip and bf.first_seen <= e.timestamp <= bf.last_seen + window:
                incidents.append(Incident(
                    rule_id="R002",
                    mitre_id="T1078",
                    mitre_tactic="Initial Access / Persistence",
                    mitre_technique="Valid Accounts",
                    severity="critical",
                    title=f"Successful login from {ip} following brute force",
                    description=(
                        f"User '{e.user}' successfully authenticated from {ip} at {e.timestamp.isoformat()}, "
                        f"within {int(window.total_seconds())}s of a brute-force burst from the same IP. "
                        "The account should be treated as potentially compromised."
                    ),
                    entities={"src_ip": ip, "user": e.user},
                    evidence=[*bf.evidence, e],
                    recommended_action=(
                        "Force a password reset for the account, invalidate active sessions, and "
                        "review actions taken by this login for further lateral movement."
                    ),
                ))
    return incidents


def rule_sudo_escalation(
    events: List[Event],
    window: timedelta = timedelta(minutes=10),
) -> List[Incident]:
    """R003 - T1548.003 Abuse Elevation Control Mechanism: Sudo and Sudo Caching.

    Flags a sudo authentication failure followed by a successful sudo
    command from the same user shortly after — a plausible privilege
    escalation attempt (mistyped/guessed password, then success).
    """
    by_user_fail: Dict[str, List[Event]] = {}
    for e in events:
        if e.event_type == "sudo_auth_failure":
            by_user_fail.setdefault(e.user, []).append(e)

    incidents: List[Incident] = []
    for e in events:
        if e.event_type != "sudo_command":
            continue
        fails = [f for f in by_user_fail.get(e.user, []) if e.timestamp - window <= f.timestamp < e.timestamp]
        if fails:
            incidents.append(Incident(
                rule_id="R003",
                mitre_id="T1548.003",
                mitre_tactic="Privilege Escalation",
                mitre_technique="Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
                severity="medium",
                title=f"Sudo failure(s) then success for user '{e.user}'",
                description=(
                    f"User '{e.user}' had {len(fails)} sudo authentication failure(s) followed by a "
                    f"successful command ('{e.fields.get('command', '?')}') within "
                    f"{int(window.total_seconds())}s."
                ),
                entities={"user": e.user},
                evidence=[*fails, e],
                recommended_action=(
                    "Confirm the command was authorized by the account owner; if not, treat the "
                    "session as compromised and audit sudoers configuration."
                ),
            ))
    return incidents


def rule_port_scan(
    events: List[Event],
    distinct_ports_threshold: int = 10,
    window: timedelta = timedelta(seconds=60),
) -> List[Incident]:
    """R004 - T1046 Network Service Discovery.

    Flags a source IP that touches many distinct destination ports on the
    same destination host within a short window (classic port-scan shape).
    """
    flows = [e for e in events if e.event_type == "firewall_flow"]
    by_pair: Dict[tuple, List[Event]] = {}
    for e in flows:
        by_pair.setdefault((e.src_ip, e.dst_ip), []).append(e)

    incidents: List[Incident] = []
    for (src, dst), evts in by_pair.items():
        evts.sort(key=lambda e: e.timestamp)
        start = 0
        for end in range(len(evts)):
            while evts[end].timestamp - evts[start].timestamp > window:
                start += 1
            burst = evts[start:end + 1]
            ports = {b.dst_port for b in burst}
            if len(ports) >= distinct_ports_threshold:
                incidents.append(Incident(
                    rule_id="R004",
                    mitre_id="T1046",
                    mitre_tactic="Discovery",
                    mitre_technique="Network Service Discovery",
                    severity="medium",
                    title=f"Possible port scan: {src} -> {dst}",
                    description=(
                        f"{src} probed {len(ports)} distinct ports on {dst} within "
                        f"{int(window.total_seconds())}s (ports: {sorted(ports)})."
                    ),
                    entities={"src_ip": src, "dst_ip": dst},
                    evidence=burst,
                    recommended_action=(
                        "Verify whether this is an authorized vulnerability scan; if not, block the "
                        "source at the perimeter and review what, if anything, responded."
                    ),
                ))
                start = end + 1
    return _dedupe_by_window(incidents)


def rule_possible_exfiltration(
    events: List[Event],
    bytes_threshold: int = 50_000_000,
) -> List[Incident]:
    """R005 - T1041 Exfiltration Over C2 Channel (approximated).

    Flags large outbound flows (private -> public IP) above a byte
    threshold, with extra weight given to flows outside 06:00-20:00.
    """
    flows = [e for e in events if e.event_type == "firewall_flow"]
    incidents: List[Incident] = []
    for e in flows:
        if e.action != "ALLOW":
            continue
        if not (_is_internal(e.src_ip) and not _is_internal(e.dst_ip)):
            continue
        if e.bytes < bytes_threshold:
            continue
        after_hours = e.timestamp.hour < 6 or e.timestamp.hour >= 20
        incidents.append(Incident(
            rule_id="R005",
            mitre_id="T1041",
            mitre_tactic="Exfiltration",
            mitre_technique="Exfiltration Over C2 Channel",
            severity="critical" if after_hours else "high",
            title=f"Large outbound transfer {e.src_ip} -> {e.dst_ip}",
            description=(
                f"{e.bytes:,} bytes sent from internal host {e.src_ip} to external host {e.dst_ip} "
                f"over {e.protocol}/{e.dst_port} at {e.timestamp.isoformat()}"
                + (" (outside business hours)." if after_hours else ".")
            ),
            entities={"src_ip": e.src_ip, "dst_ip": e.dst_ip},
            evidence=[e],
            recommended_action=(
                "Confirm the transfer was expected (backup job, approved sync). If not, isolate the "
                "host and inspect for exfiltration tooling or a compromised process."
            ),
        ))
    return incidents


def _dedupe_by_window(incidents: List[Incident]) -> List[Incident]:
    """Collapse incidents that share a rule_id + entity set and overlapping
    evidence windows down to the widest one, so a slow-growing burst isn't
    reported as N nearly-identical incidents."""
    if not incidents:
        return incidents
    incidents = sorted(incidents, key=lambda i: (tuple(sorted(i.entities.items())), i.first_seen))
    result: List[Incident] = []
    for inc in incidents:
        if result:
            prev = result[-1]
            same_entities = prev.entities == inc.entities and prev.rule_id == inc.rule_id
            if same_entities and inc.first_seen <= prev.last_seen:
                if len(inc.evidence) > len(prev.evidence):
                    result[-1] = inc
                continue
        result.append(inc)
    return result


DEFAULT_RULES = (
    "rule_brute_force_ssh",
    "rule_valid_account_after_brute_force",
    "rule_sudo_escalation",
    "rule_port_scan",
    "rule_possible_exfiltration",
)
