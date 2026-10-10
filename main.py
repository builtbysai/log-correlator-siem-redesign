#!/usr/bin/env python3
"""CLI entry point for log-correlator-siem.

Example:
    python main.py \
        --auth data/sample_logs/auth.log \
        --firewall data/sample_logs/firewall.csv \
        --out output/dashboard.html
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from log_correlator.correlator import run_correlation, summarize  # noqa: E402
from log_correlator.dashboard import render_dashboard  # noqa: E402
from log_correlator.parser import load_events  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="Correlate auth + firewall logs into MITRE ATT&CK-mapped incidents.")
    ap.add_argument("--auth", help="Path to an auth log (sshd/sudo style).")
    ap.add_argument("--firewall", help="Path to a firewall CSV log.")
    ap.add_argument("--out", default="output/dashboard.html", help="Where to write the HTML dashboard.")
    ap.add_argument("--json", help="Optional: also write incidents as JSON to this path.")
    ap.add_argument("--title", default="Log Correlator - Incident Dashboard", help="Dashboard title.")
    args = ap.parse_args()

    if not args.auth and not args.firewall:
        ap.error("provide at least one of --auth or --firewall")

    events, skipped = load_events(args.auth, args.firewall)
    if skipped:
        print(f"[warn] skipped lines: {skipped}", file=sys.stderr)

    incidents = run_correlation(events)
    summary = summarize(events, incidents)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    html_doc = render_dashboard(events, incidents, summary, title=args.title)
    out_path.write_text(html_doc, encoding="utf-8")

    print(f"Ingested {summary['total_events']} events -> {summary['total_incidents']} incidents")
    for sev, count in summary["by_severity"].items():
        if count:
            print(f"  {sev:8s} {count}")
    print(f"Dashboard written to {out_path}")

    if args.json:
        json_path = Path(args.json)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        payload = [
            {
                "rule_id": i.rule_id,
                "mitre_id": i.mitre_id,
                "mitre_tactic": i.mitre_tactic,
                "mitre_technique": i.mitre_technique,
                "severity": i.severity,
                "title": i.title,
                "description": i.description,
                "entities": i.entities,
                "first_seen": i.first_seen.isoformat(),
                "last_seen": i.last_seen.isoformat(),
                "recommended_action": i.recommended_action,
            }
            for i in incidents
        ]
        json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"Incidents JSON written to {json_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
