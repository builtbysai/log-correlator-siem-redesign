"""Render a self-contained HTML dashboard for a correlation run.

No external assets, no build step, no network calls at render time -
open the output file straight in a browser.
"""
from __future__ import annotations

import html
from datetime import datetime
from typing import Dict, List

from .parser import Event
from .rules import Incident

SEVERITY_COLOR = {
    "critical": "#ff5d7a",
    "high": "#ff9d4d",
    "medium": "#f5d76e",
    "low": "#6fd8a8",
}


def _esc(s) -> str:
    return html.escape(str(s), quote=True)


def _incident_card(inc: Incident, idx: int) -> str:
    color = SEVERITY_COLOR[inc.severity]
    evidence_rows = "\n".join(
        f'<tr><td>{_esc(e.timestamp.isoformat())}</td><td>{_esc(e.source)}</td>'
        f'<td>{_esc(e.event_type)}</td><td class="mono">{_esc(e.raw)}</td></tr>'
        for e in inc.evidence
    )
    entity_pills = "".join(
        f'<span class="pill">{_esc(k)}: {_esc(v)}</span>' for k, v in inc.entities.items()
    )
    return f"""
    <div class="incident" style="--sev-color:{color}">
      <div class="incident-head" onclick="this.parentElement.classList.toggle('open')">
        <span class="sev-dot" style="background:{color}"></span>
        <span class="incident-title">{_esc(inc.title)}</span>
        <span class="mitre-tag">{_esc(inc.mitre_id)} &middot; {_esc(inc.mitre_technique)}</span>
        <span class="chev">&#9662;</span>
      </div>
      <div class="incident-body">
        <p>{_esc(inc.description)}</p>
        <div class="pills">{entity_pills}</div>
        <p class="rec"><strong>Recommended action:</strong> {_esc(inc.recommended_action)}</p>
        <table class="evidence">
          <thead><tr><th>Timestamp</th><th>Source</th><th>Event</th><th>Raw</th></tr></thead>
          <tbody>{evidence_rows}</tbody>
        </table>
      </div>
    </div>"""


def _matrix(by_technique: List[Dict]) -> str:
    if not by_technique:
        return '<p class="muted">No techniques triggered in this run.</p>'
    cells = "".join(
        f'<div class="mx-cell"><div class="mx-id">{_esc(t["mitre_id"])}</div>'
        f'<div class="mx-name">{_esc(t["technique"])}</div>'
        f'<div class="mx-tactic">{_esc(t["tactic"])}</div>'
        f'<div class="mx-count">&times;{t["count"]}</div></div>'
        for t in by_technique
    )
    return f'<div class="matrix">{cells}</div>'


def render_dashboard(events: List[Event], incidents: List[Incident], summary: Dict, title: str = "Log Correlator") -> str:
    span = summary.get("time_span")
    span_str = f"{span[0].isoformat()} &rarr; {span[1].isoformat()}" if span else "n/a"
    sev = summary["by_severity"]
    cards = "\n".join(_incident_card(inc, i) for i, inc in enumerate(incidents)) or '<p class="muted">No incidents detected. Clean run.</p>'
    matrix_html = _matrix(summary["by_technique"])
    generated = datetime.now().isoformat(timespec="seconds")

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(title)}</title>
<style>
  :root {{
    --bg:#0a0e12; --panel:#11161c; --panel2:#161d25; --border:#232c36;
    --text:#e7edf3; --muted:#8695a7; --accent:#5eead4;
  }}
  * {{ box-sizing:border-box; }}
  body {{
    margin:0; background:var(--bg); color:var(--text);
    font:15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, sans-serif;
  }}
  header {{
    padding:32px clamp(16px,4vw,48px); border-bottom:1px solid var(--border);
    display:flex; flex-wrap:wrap; gap:24px; align-items:baseline; justify-content:space-between;
  }}
  header h1 {{ margin:0; font-size:22px; letter-spacing:-0.01em; }}
  header .sub {{ color:var(--muted); font-size:13px; }}
  main {{ padding:24px clamp(16px,4vw,48px) 64px; max-width:1100px; margin:0 auto; }}
  .stats {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:12px; margin-bottom:32px; }}
  .stat {{ background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:16px; }}
  .stat .num {{ font-size:28px; font-weight:700; }}
  .stat .label {{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.06em; }}
  .stat.critical .num {{ color:{SEVERITY_COLOR['critical']}; }}
  .stat.high .num {{ color:{SEVERITY_COLOR['high']}; }}
  .stat.medium .num {{ color:{SEVERITY_COLOR['medium']}; }}
  .stat.low .num {{ color:{SEVERITY_COLOR['low']}; }}
  h2 {{ font-size:15px; text-transform:uppercase; letter-spacing:.08em; color:var(--muted); margin:36px 0 14px; }}
  .matrix {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(190px,1fr)); gap:10px; }}
  .mx-cell {{ background:var(--panel); border:1px solid var(--border); border-left:3px solid var(--accent); border-radius:8px; padding:12px; }}
  .mx-id {{ color:var(--accent); font-size:12px; font-family:ui-monospace,monospace; }}
  .mx-name {{ font-size:13px; margin-top:2px; }}
  .mx-tactic {{ color:var(--muted); font-size:11px; margin-top:4px; }}
  .mx-count {{ color:var(--muted); font-size:11px; margin-top:6px; }}
  .incident {{ background:var(--panel); border:1px solid var(--border); border-left:3px solid var(--sev-color,var(--accent));
               border-radius:10px; margin-bottom:10px; overflow:hidden; }}
  .incident-head {{ display:flex; align-items:center; gap:10px; padding:14px 16px; cursor:pointer; }}
  .sev-dot {{ width:9px; height:9px; border-radius:50%; flex:none; }}
  .incident-title {{ font-weight:600; flex:1; min-width:180px; }}
  .mitre-tag {{ color:var(--muted); font-size:12px; font-family:ui-monospace,monospace; }}
  .chev {{ color:var(--muted); transition:transform .2s ease; }}
  .incident.open .chev {{ transform:rotate(180deg); }}
  .incident-body {{ display:none; padding:0 16px 18px; border-top:1px solid var(--border); }}
  .incident.open .incident-body {{ display:block; padding-top:14px; }}
  .pills {{ display:flex; flex-wrap:wrap; gap:6px; margin:10px 0; }}
  .pill {{ background:var(--panel2); border:1px solid var(--border); border-radius:999px; padding:3px 10px; font-size:12px; color:var(--muted); }}
  .rec {{ font-size:13px; color:var(--muted); }}
  table.evidence {{ width:100%; border-collapse:collapse; margin-top:10px; font-size:12px; }}
  table.evidence th {{ text-align:left; color:var(--muted); font-weight:600; padding:6px 8px; border-bottom:1px solid var(--border); }}
  table.evidence td {{ padding:6px 8px; border-bottom:1px solid var(--border); vertical-align:top; }}
  .mono, td.mono {{ font-family:ui-monospace,monospace; word-break:break-all; }}
  .muted {{ color:var(--muted); }}
  footer {{ text-align:center; color:var(--muted); font-size:12px; padding:24px; }}
</style>
</head>
<body>
<header>
  <div>
    <h1>{_esc(title)}</h1>
    <div class="sub">Generated {_esc(generated)} &middot; event window {span_str}</div>
  </div>
  <div class="sub">log-correlator-siem &middot; local, dependency-free correlation engine</div>
</header>
<main>
  <div class="stats">
    <div class="stat"><div class="num">{summary['total_events']}</div><div class="label">Events ingested</div></div>
    <div class="stat"><div class="num">{summary['total_incidents']}</div><div class="label">Incidents</div></div>
    <div class="stat critical"><div class="num">{sev['critical']}</div><div class="label">Critical</div></div>
    <div class="stat high"><div class="num">{sev['high']}</div><div class="label">High</div></div>
    <div class="stat medium"><div class="num">{sev['medium']}</div><div class="label">Medium</div></div>
    <div class="stat low"><div class="num">{sev['low']}</div><div class="label">Low</div></div>
  </div>

  <h2>MITRE ATT&amp;CK techniques observed</h2>
  {matrix_html}

  <h2>Incidents</h2>
  {cards}
</main>
<footer>Built by Hans Sai &middot; <a href="https://github.com/builtbysai/log-correlator-siem" style="color:var(--accent)">github.com/builtbysai/log-correlator-siem</a></footer>
</body>
</html>
"""
