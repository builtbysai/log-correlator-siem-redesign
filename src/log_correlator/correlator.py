"""Top-level orchestration: run the rule set over a batch of events and
return a sorted, deduplicated list of Incidents plus summary stats.
"""
from __future__ import annotations

from typing import Dict, List

from .parser import Event
from .rules import (
    Incident,
    SEVERITY_ORDER,
    rule_brute_force_ssh,
    rule_possible_exfiltration,
    rule_port_scan,
    rule_sudo_escalation,
    rule_valid_account_after_brute_force,
)


def run_correlation(events: List[Event]) -> List[Incident]:
    """Run every detection rule and return incidents sorted by severity
    (critical first) then by first-seen time."""
    incidents: List[Incident] = []

    brute_force = rule_brute_force_ssh(events)
    incidents.extend(brute_force)
    incidents.extend(rule_valid_account_after_brute_force(events, brute_force))
    incidents.extend(rule_sudo_escalation(events))
    incidents.extend(rule_port_scan(events))
    incidents.extend(rule_possible_exfiltration(events))

    incidents.sort(key=lambda i: (-SEVERITY_ORDER[i.severity], i.first_seen))
    return incidents


def summarize(events: List[Event], incidents: List[Incident]) -> Dict:
    by_severity: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_technique: Dict[str, Dict] = {}
    for inc in incidents:
        by_severity[inc.severity] += 1
        key = inc.mitre_id
        if key not in by_technique:
            by_technique[key] = {
                "mitre_id": inc.mitre_id,
                "technique": inc.mitre_technique,
                "tactic": inc.mitre_tactic,
                "count": 0,
            }
        by_technique[key]["count"] += 1

    span = None
    if events:
        span = (min(e.timestamp for e in events), max(e.timestamp for e in events))

    return {
        "total_events": len(events),
        "total_incidents": len(incidents),
        "by_severity": by_severity,
        "by_technique": sorted(by_technique.values(), key=lambda t: -t["count"]),
        "time_span": span,
    }
