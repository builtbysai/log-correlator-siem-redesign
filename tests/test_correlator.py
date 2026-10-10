import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from log_correlator.correlator import run_correlation, summarize
from log_correlator.parser import load_events
from log_correlator.dashboard import render_dashboard

SAMPLE_DIR = Path(__file__).parent.parent / "data" / "sample_logs"


def _load():
    return load_events(str(SAMPLE_DIR / "auth.log"), str(SAMPLE_DIR / "firewall.csv"))


def test_sample_data_produces_expected_technique_mix():
    events, skipped = _load()
    assert skipped == {}
    incidents = run_correlation(events)
    mitre_ids = {i.mitre_id for i in incidents}
    # The bundled sample data is hand-crafted to exercise every rule at least once.
    assert {"T1110.001", "T1078", "T1548.003", "T1046", "T1041"}.issubset(mitre_ids)


def test_incidents_sorted_critical_first():
    events, _ = _load()
    incidents = run_correlation(events)
    severities = [i.severity for i in incidents]
    order = {"critical": 3, "high": 2, "medium": 1, "low": 0}
    ranks = [order[s] for s in severities]
    assert ranks == sorted(ranks, reverse=True)


def test_summarize_counts_match_incident_list():
    events, _ = _load()
    incidents = run_correlation(events)
    summary = summarize(events, incidents)
    assert summary["total_incidents"] == len(incidents)
    assert sum(summary["by_severity"].values()) == len(incidents)
    assert summary["total_events"] == len(events)


def test_dashboard_renders_valid_self_contained_html():
    events, _ = _load()
    incidents = run_correlation(events)
    summary = summarize(events, incidents)
    doc = render_dashboard(events, incidents, summary, title="Test Dashboard")
    assert doc.startswith("<!doctype html>")
    assert "</html>" in doc
    assert "<script src=" not in doc  # no external script tags
    assert 'href="http' not in doc.replace('href="https://github.com/builtbysai', "")
    for inc in incidents:
        assert inc.mitre_id in doc


def test_empty_input_produces_zero_incidents_not_a_crash():
    incidents = run_correlation([])
    summary = summarize([], incidents)
    assert incidents == []
    assert summary["total_incidents"] == 0
    doc = render_dashboard([], incidents, summary)
    assert "No incidents detected" in doc
