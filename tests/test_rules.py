import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from log_correlator.parser import Event
from log_correlator.rules import (
    rule_brute_force_ssh,
    rule_valid_account_after_brute_force,
    rule_sudo_escalation,
    rule_port_scan,
    rule_possible_exfiltration,
)

T0 = datetime.fromisoformat("2026-08-30T03:00:00+00:00")


def _ssh_fail(offset_s, ip="203.0.113.45", user="root"):
    return Event(timestamp=T0 + timedelta(seconds=offset_s), source="auth",
                 event_type="ssh_failed_password", src_ip=ip, user=user, raw="failx")


def _ssh_ok(offset_s, ip="203.0.113.45", user="root"):
    return Event(timestamp=T0 + timedelta(seconds=offset_s), source="auth",
                 event_type="ssh_accepted_password", src_ip=ip, user=user, raw="okx")


def test_brute_force_triggers_at_threshold():
    events = [_ssh_fail(i * 10) for i in range(5)]  # 5 fails across 40s, under 2min window
    incidents = rule_brute_force_ssh(events, threshold=5)
    assert len(incidents) == 1
    assert incidents[0].mitre_id == "T1110.001"
    assert incidents[0].entities["src_ip"] == "203.0.113.45"


def test_brute_force_does_not_trigger_below_threshold():
    events = [_ssh_fail(i * 10) for i in range(4)]
    incidents = rule_brute_force_ssh(events, threshold=5)
    assert incidents == []


def test_brute_force_ignores_attempts_outside_window():
    # 3 fails now, 3 fails 10 minutes later: neither burst alone hits threshold=5
    events = [_ssh_fail(i * 5) for i in range(3)]
    events += [_ssh_fail(600 + i * 5) for i in range(3)]
    incidents = rule_brute_force_ssh(events, threshold=5, window=timedelta(minutes=2))
    assert incidents == []


def test_brute_force_separates_different_source_ips():
    events = [_ssh_fail(i * 5, ip="203.0.113.45") for i in range(5)]
    events += [_ssh_fail(i * 5, ip="198.51.100.7") for i in range(5)]
    incidents = rule_brute_force_ssh(events, threshold=5)
    ips = {i.entities["src_ip"] for i in incidents}
    assert ips == {"203.0.113.45", "198.51.100.7"}


def test_valid_account_after_brute_force_links_success():
    fails = [_ssh_fail(i * 10) for i in range(5)]
    bf = rule_brute_force_ssh(fails, threshold=5)
    assert len(bf) == 1
    success = _ssh_ok(45)  # success shortly after the brute-force burst
    incidents = rule_valid_account_after_brute_force(fails + [success], bf)
    assert len(incidents) == 1
    assert incidents[0].mitre_id == "T1078"
    assert incidents[0].severity == "critical"


def test_valid_account_rule_ignores_unrelated_success():
    fails = [_ssh_fail(i * 10) for i in range(5)]
    bf = rule_brute_force_ssh(fails, threshold=5)
    unrelated_success = _ssh_ok(45, ip="192.0.2.99")
    incidents = rule_valid_account_after_brute_force(fails + [unrelated_success], bf)
    assert incidents == []


def test_sudo_escalation_requires_prior_failure():
    fail = Event(timestamp=T0, source="auth", event_type="sudo_auth_failure", user="hans", raw="f")
    cmd = Event(timestamp=T0 + timedelta(seconds=30), source="auth", event_type="sudo_command",
                user="hans", raw="c", fields={"command": "/usr/sbin/useradd -m svc-backup"})
    incidents = rule_sudo_escalation([fail, cmd])
    assert len(incidents) == 1
    assert incidents[0].mitre_id == "T1548.003"


def test_sudo_escalation_no_incident_without_prior_failure():
    cmd = Event(timestamp=T0, source="auth", event_type="sudo_command", user="hans",
                raw="c", fields={"command": "/bin/systemctl restart nginx"})
    incidents = rule_sudo_escalation([cmd])
    assert incidents == []


def _flow(offset_s, src="203.0.113.45", dst="10.0.0.5", port=22, action="ALLOW", nbytes=60):
    return Event(timestamp=T0 + timedelta(seconds=offset_s), source="firewall",
                 event_type="firewall_flow", src_ip=src, dst_ip=dst, dst_port=port,
                 protocol="tcp", action=action, bytes=nbytes, raw="flow")


def test_port_scan_triggers_on_many_distinct_ports():
    events = [_flow(i * 2, port=1000 + i) for i in range(10)]
    incidents = rule_port_scan(events, distinct_ports_threshold=10, window=timedelta(seconds=60))
    assert len(incidents) == 1
    assert incidents[0].mitre_id == "T1046"


def test_port_scan_does_not_trigger_on_repeated_same_port():
    events = [_flow(i * 2, port=443) for i in range(10)]
    incidents = rule_port_scan(events, distinct_ports_threshold=10, window=timedelta(seconds=60))
    assert incidents == []


def test_exfiltration_flags_large_outbound_transfer():
    flow = _flow(0, src="10.0.0.14", dst="198.51.100.200", port=443, nbytes=75_000_000)
    incidents = rule_possible_exfiltration([flow], bytes_threshold=50_000_000)
    assert len(incidents) == 1
    assert incidents[0].mitre_id == "T1041"


def test_exfiltration_ignores_internal_to_internal_transfer():
    flow = _flow(0, src="10.0.0.14", dst="10.0.0.5", port=443, nbytes=75_000_000)
    incidents = rule_possible_exfiltration([flow], bytes_threshold=50_000_000)
    assert incidents == []


def test_exfiltration_ignores_small_transfers():
    flow = _flow(0, src="10.0.0.14", dst="198.51.100.200", port=443, nbytes=1000)
    incidents = rule_possible_exfiltration([flow], bytes_threshold=50_000_000)
    assert incidents == []
