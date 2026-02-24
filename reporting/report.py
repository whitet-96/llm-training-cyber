"""Standalone HTML report generator for the cybersecurity CVE curation pipeline.

Reads data/scored/cves_scored.jsonl and produces a single self-contained HTML
report at docs/sample_report.html using Plotly graph_objects. All chart data
is embedded inline; the CDN link is included once for Plotly JS so the file
needs only a browser (no local server).
"""

import json
import os
from datetime import datetime, timezone

import plotly.graph_objects as go

from config import SCORED_PATH, PIPELINE_VERSION, QUALITY_THRESHOLD

REPORT_OUTPUT = "docs/sample_report.html"

# Colour palette — consistent with Project 1 dashboard
COLOUR_RELEVANCE = "#2dd4bf"      # teal
COLOUR_COMPLETENESS = "#fbbf24"   # amber/yellow
COLOUR_CREDIBILITY = "#a78bfa"    # purple
COLOUR_CLARITY = "#fb7185"        # salmon/coral

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
SEVERITY_COLOURS = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#ca8a04",
    "LOW":      "#16a34a",
    "UNKNOWN":  "#6b7280",
}

CSS = """
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #0f172a;
    color: #e2e8f0;
    padding: 2rem;
  }
  .header {
    text-align: center;
    margin-bottom: 2.5rem;
    border-bottom: 1px solid #334155;
    padding-bottom: 1.5rem;
  }
  .header h1 { font-size: 2rem; font-weight: 700; color: #f1f5f9; }
  .header .subtitle { color: #94a3b8; margin-top: 0.4rem; font-size: 0.95rem; }
  .stats-bar {
    display: flex;
    gap: 1rem;
    justify-content: center;
    margin-top: 1.2rem;
    flex-wrap: wrap;
  }
  .stat-card {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 0.75rem 1.5rem;
    text-align: center;
    min-width: 140px;
  }
  .stat-card .value { font-size: 1.6rem; font-weight: 700; color: #38bdf8; }
  .stat-card .label { font-size: 0.75rem; color: #94a3b8; margin-top: 0.2rem; text-transform: uppercase; letter-spacing: 0.05em; }
  .section {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 10px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
  }
  .section h2 { font-size: 1.1rem; font-weight: 600; color: #cbd5e1; margin-bottom: 1rem; }
  table { width: 100%; border-collapse: collapse; font-size: 0.82rem; }
  thead tr { background: #0f172a; }
  th { padding: 0.6rem 0.75rem; text-align: left; color: #94a3b8; font-weight: 500; border-bottom: 1px solid #334155; }
  td { padding: 0.55rem 0.75rem; border-bottom: 1px solid #1e293b; color: #cbd5e1; }
  tr.ready { background: rgba(34, 197, 94, 0.08); }
  tr:hover { background: #263347; }
  .badge {
    display: inline-block;
    padding: 0.15rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
  }
  .badge-yes { background: rgba(34,197,94,0.2); color: #4ade80; }
  .badge-no  { background: rgba(239,68,68,0.2); color: #f87171; }
  .footer { text-align: center; color: #475569; font-size: 0.8rem; margin-top: 2rem; }
</style>
"""


def _load_records(scored_path: str) -> list:
    records = []
    with open(scored_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def _chart_html(fig, include_js: bool) -> str:
    js_mode = "cdn" if include_js else False
    return fig.to_html(full_html=False, include_plotlyjs=js_mode, config={"responsive": True})


# ── Section 1: Training Readiness Donut ─────────────────────────────────────

def _donut_chart(records: list) -> str:
    ready = sum(1 for r in records if r.get("composite_score", 0) >= QUALITY_THRESHOLD)
    review = sum(1 for r in records if 0.40 <= r.get("composite_score", 0) < QUALITY_THRESHOLD)
    rejected = sum(1 for r in records if r.get("composite_score", 0) < 0.40)
    total = len(records)

    labels = ["Training Ready", "Review Queue", "Rejected"]
    values = [ready, review, rejected]
    colours = ["#22c55e", "#f59e0b", "#ef4444"]
    pcts = [f"{v/total*100:.1f}%" if total else "0%" for v in values]
    text = [f"{v} ({p})" for v, p in zip(values, pcts)]

    fig = go.Figure(go.Pie(
        labels=labels,
        values=values,
        hole=0.55,
        marker_colors=colours,
        text=text,
        textinfo="label+text",
        hovertemplate="%{label}: %{value} records<extra></extra>",
    ))
    fig.update_layout(
        paper_bgcolor="#1e293b",
        plot_bgcolor="#1e293b",
        font_color="#cbd5e1",
        legend=dict(orientation="h", yanchor="bottom", y=-0.15, xanchor="center", x=0.5),
        margin=dict(t=20, b=20, l=20, r=20),
        height=340,
        annotations=[dict(text=f"<b>{total}</b><br>total", x=0.5, y=0.5,
                          font_size=16, font_color="#f1f5f9", showarrow=False)],
    )
    return _chart_html(fig, include_js=True)


# ── Section 2: Composite Score Histogram ────────────────────────────────────

def _histogram(records: list) -> str:
    scores = [r.get("composite_score", 0) for r in records]

    fig = go.Figure()
    fig.add_trace(go.Histogram(
        x=scores,
        xbins=dict(start=0.0, end=1.01, size=0.05),
        marker_color="#38bdf8",
        marker_line_color="#0f172a",
        marker_line_width=1,
        opacity=0.85,
        name="Records",
    ))
    fig.add_vline(
        x=QUALITY_THRESHOLD,
        line_dash="dash",
        line_color="#f59e0b",
        line_width=2,
        annotation_text=f"Threshold ({QUALITY_THRESHOLD})",
        annotation_position="top right",
        annotation_font_color="#f59e0b",
    )
    fig.update_layout(
        paper_bgcolor="#1e293b",
        plot_bgcolor="#0f172a",
        font_color="#cbd5e1",
        xaxis=dict(title="Composite Score", range=[0, 1], gridcolor="#334155"),
        yaxis=dict(title="Record Count", gridcolor="#334155"),
        margin=dict(t=20, b=40, l=50, r=20),
        height=320,
        showlegend=False,
        bargap=0.05,
    )
    return _chart_html(fig, include_js=False)


# ── Section 3: Dimension Score Box Plot ─────────────────────────────────────

def _box_plot(records: list) -> str:
    dims = [
        ("relevance_score",           "Relevance",    COLOUR_RELEVANCE),
        ("completeness_score",        "Completeness", COLOUR_COMPLETENESS),
        ("source_credibility_score",  "Credibility",  COLOUR_CREDIBILITY),
        ("clarity_score",             "Clarity",      COLOUR_CLARITY),
    ]

    fig = go.Figure()
    for field, label, colour in dims:
        vals = [r.get(field, 0) for r in records]
        fig.add_trace(go.Box(
            y=vals,
            name=label,
            marker_color=colour,
            line_color=colour,
            boxmean=True,
            hovertemplate=f"<b>{label}</b><br>Value: %{{y:.3f}}<extra></extra>",
        ))
    fig.update_layout(
        paper_bgcolor="#1e293b",
        plot_bgcolor="#0f172a",
        font_color="#cbd5e1",
        yaxis=dict(title="Score", range=[0, 1.05], gridcolor="#334155"),
        xaxis=dict(gridcolor="#334155"),
        margin=dict(t=20, b=40, l=50, r=20),
        height=340,
        showlegend=False,
    )
    return _chart_html(fig, include_js=False)


# ── Section 4: Severity Distribution ────────────────────────────────────────

def _severity_bar(records: list) -> str:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for r in records:
        sev = (r.get("severity") or "UNKNOWN").upper()
        if sev not in counts:
            sev = "UNKNOWN"
        counts[sev] += 1

    labels = SEVERITY_ORDER
    values = [counts[s] for s in labels]
    colours = [SEVERITY_COLOURS[s] for s in labels]

    fig = go.Figure(go.Bar(
        x=values,
        y=labels,
        orientation="h",
        marker_color=colours,
        text=values,
        textposition="outside",
        hovertemplate="%{y}: %{x} records<extra></extra>",
    ))
    fig.update_layout(
        paper_bgcolor="#1e293b",
        plot_bgcolor="#0f172a",
        font_color="#cbd5e1",
        xaxis=dict(title="Record Count", gridcolor="#334155"),
        yaxis=dict(autorange="reversed"),
        margin=dict(t=20, b=40, l=100, r=60),
        height=280,
        showlegend=False,
    )
    return _chart_html(fig, include_js=False)


# ── Section 5: Top 20 Table ──────────────────────────────────────────────────

def _top20_table(records: list) -> str:
    top20 = sorted(records, key=lambda r: r.get("composite_score", 0), reverse=True)[:20]

    def fmt(v):
        return f"{v:.3f}" if isinstance(v, float) else (str(v) if v is not None else "—")

    rows = []
    for r in top20:
        ready = r.get("training_ready", False)
        badge = '<span class="badge badge-yes">Yes</span>' if ready else '<span class="badge badge-no">No</span>'
        row_class = ' class="ready"' if ready else ""
        sev = r.get("severity") or "—"
        cvss = fmt(r.get("cvss_score"))
        rows.append(
            f'<tr{row_class}>'
            f'<td>{r.get("cve_id","")}</td>'
            f'<td>{sev}</td>'
            f'<td>{cvss}</td>'
            f'<td>{fmt(r.get("composite_score"))}</td>'
            f'<td>{fmt(r.get("relevance_score"))}</td>'
            f'<td>{fmt(r.get("completeness_score"))}</td>'
            f'<td>{fmt(r.get("clarity_score"))}</td>'
            f'<td>{badge}</td>'
            f'</tr>'
        )

    header = (
        "<table><thead><tr>"
        "<th>CVE ID</th><th>Severity</th><th>CVSS</th><th>Composite</th>"
        "<th>Relevance</th><th>Completeness</th><th>Clarity</th><th>Training Ready</th>"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )
    return header


# ── Section 6: Dimension Heatmap (top 50) ───────────────────────────────────

def _heatmap(records: list) -> str:
    top50 = sorted(records, key=lambda r: r.get("composite_score", 0), reverse=True)[:50]

    dim_fields = ["relevance_score", "completeness_score", "source_credibility_score", "clarity_score"]
    dim_labels = ["Relevance", "Completeness", "Credibility", "Clarity"]
    cve_ids = [r.get("cve_id", "") for r in top50]

    z = [[r.get(f, 0) for f in dim_fields] for r in top50]

    fig = go.Figure(go.Heatmap(
        z=z,
        x=dim_labels,
        y=cve_ids,
        colorscale=[
            [0.0, "#ef4444"],
            [0.5, "#f59e0b"],
            [1.0, "#22c55e"],
        ],
        zmin=0,
        zmax=1,
        hovertemplate="CVE: %{y}<br>%{x}: %{z:.3f}<extra></extra>",
        colorbar=dict(
            title=dict(text="Score", font=dict(color="#cbd5e1")),
            tickfont=dict(color="#cbd5e1"),
        ),
    ))
    fig.update_layout(
        paper_bgcolor="#1e293b",
        plot_bgcolor="#1e293b",
        font_color="#cbd5e1",
        xaxis=dict(side="top"),
        yaxis=dict(autorange="reversed", tickfont=dict(size=9)),
        margin=dict(t=40, b=20, l=160, r=20),
        height=max(400, len(top50) * 14),
    )
    return _chart_html(fig, include_js=False)


# ── Main assembly ────────────────────────────────────────────────────────────

def generate_report(
    scored_path: str = SCORED_PATH,
    output_path: str = REPORT_OUTPUT,
) -> None:
    """Generate a standalone HTML curation report from the scored JSONL."""
    if not os.path.exists(scored_path):
        raise FileNotFoundError(f"Scored data not found at '{scored_path}'. Run --stage score first.")

    records = _load_records(scored_path)
    if not records:
        raise ValueError(f"No records found in '{scored_path}'.")

    total = len(records)
    ready_count = sum(1 for r in records if r.get("training_ready"))
    pass_rate = ready_count / total * 100 if total else 0.0
    avg_composite = sum(r.get("composite_score", 0) for r in records) / total if total else 0.0
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    print(f"[Report] Generating report for {total} records ...")

    donut_html     = _donut_chart(records)     # first chart — includes plotlyjs cdn
    histogram_html = _histogram(records)
    boxplot_html   = _box_plot(records)
    severity_html  = _severity_bar(records)
    table_html     = _top20_table(records)
    heatmap_html   = _heatmap(records)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Cybersecurity Training Data — Curation Report</title>
  {CSS}
</head>
<body>

<div class="header">
  <h1>Cybersecurity Training Data &mdash; Curation Report</h1>
  <div class="subtitle">Pipeline {PIPELINE_VERSION} &nbsp;&bull;&nbsp; Generated {generated_at}</div>
  <div class="stats-bar">
    <div class="stat-card">
      <div class="value">{total:,}</div>
      <div class="label">Total Records</div>
    </div>
    <div class="stat-card">
      <div class="value">{ready_count:,}</div>
      <div class="label">Training Ready</div>
    </div>
    <div class="stat-card">
      <div class="value">{pass_rate:.1f}%</div>
      <div class="label">Pass Rate</div>
    </div>
    <div class="stat-card">
      <div class="value">{avg_composite:.3f}</div>
      <div class="label">Avg Composite</div>
    </div>
  </div>
</div>

<div class="section">
  <h2>1. Training Readiness Breakdown</h2>
  {donut_html}
</div>

<div class="section">
  <h2>2. Composite Score Distribution</h2>
  {histogram_html}
</div>

<div class="section">
  <h2>3. Score Breakdown by Dimension</h2>
  {boxplot_html}
</div>

<div class="section">
  <h2>4. Severity Distribution</h2>
  {severity_html}
</div>

<div class="section">
  <h2>5. Top 20 Training-Ready Records</h2>
  {table_html}
</div>

<div class="section">
  <h2>6. Dimension Score Heatmap (Top 50 Records)</h2>
  {heatmap_html}
</div>

<div class="footer">
  Generated by cyb-dq-curation {PIPELINE_VERSION} &nbsp;&bull;&nbsp; NVD + HuggingFace CVE sources
</div>

</body>
</html>"""

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[Report] Report saved to: {output_path}")
