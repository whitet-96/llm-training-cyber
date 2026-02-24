"""Standalone HTML report generator for the cybersecurity CVE curation pipeline.

Reads data/scored/cves_scored.jsonl and produces a single self-contained HTML
report at docs/sample_report.html using Plotly graph_objects. All chart data
is embedded inline; the CDN link is included once for Plotly JS so the file
needs only a browser (no local server).
"""

import json
import os
import statistics
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
    font-family: system-ui, -apple-system, 'Segoe UI', sans-serif;
    background: #0f172a;
    color: #e2e8f0;
  }

  /* ── Top gradient colour bar ── */
  .top-bar {
    height: 4px;
    background: linear-gradient(to right, #2dd4bf, #fbbf24, #a78bfa, #fb7185);
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    z-index: 1000;
  }

  /* ── Sticky navigation header ── */
  .sticky-nav {
    position: sticky;
    top: 4px;
    z-index: 999;
    background: rgba(15, 23, 42, 0.96);
    backdrop-filter: blur(8px);
    border-bottom: 1px solid #334155;
    padding: 0.6rem 2rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .sticky-nav .nav-title {
    font-size: 0.9rem;
    font-weight: 600;
    color: #f1f5f9;
    letter-spacing: 0.01em;
  }
  .sticky-nav .nav-meta {
    font-size: 0.78rem;
    color: #64748b;
  }

  /* ── Content wrapper ── */
  .content-wrapper {
    max-width: 1200px;
    margin: 0 auto;
    padding: 2rem 2rem 3rem;
  }

  /* ── Page header ── */
  .header {
    text-align: center;
    margin-bottom: 2rem;
    padding-top: 1.5rem;
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
  .stat-card .label { font-size: 0.75rem; color: #94a3b8; margin-top: 0.2rem;
                      text-transform: uppercase; letter-spacing: 0.05em; }

  /* ── Executive summary panel ── */
  .exec-summary {
    background: #f8f9fa;
    border: 1px solid #dee2e6;
    border-radius: 6px;
    padding: 1.25rem 1.5rem;
    margin-bottom: 1.5rem;
    font-size: 0.95rem;
    line-height: 1.7;
    color: #212529;
  }
  .exec-summary h3 {
    font-size: 1rem;
    font-weight: 700;
    color: #1a202c;
    margin-bottom: 0.75rem;
    letter-spacing: 0.01em;
  }
  .exec-summary p + p { margin-top: 0.75rem; }

  /* ── Methodology panel ── */
  .methodology-panel {
    background: #f8f9fa;
    border: 1px solid #dee2e6;
    border-radius: 6px;
    padding: 1.25rem 1.5rem;
    margin-bottom: 1.5rem;
    color: #212529;
  }
  .methodology-panel h3 {
    font-size: 1rem;
    font-weight: 700;
    color: #1a202c;
    margin-bottom: 0.5rem;
  }
  .methodology-panel .intro {
    font-size: 0.9rem;
    color: #495057;
    margin-bottom: 1rem;
    line-height: 1.6;
  }
  .dim-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0.75rem;
  }
  @media (max-width: 700px) { .dim-grid { grid-template-columns: 1fr; } }
  .dim-card {
    background: #fff;
    border: 1px solid #dee2e6;
    border-radius: 6px;
    padding: 0.9rem 1rem 0.9rem 1rem;
    font-size: 0.875rem;
    line-height: 1.6;
    color: #343a40;
  }
  .dim-card h4 {
    font-size: 0.9rem;
    font-weight: 700;
    margin-bottom: 0.5rem;
  }
  .dim-card .signals {
    margin-top: 0.6rem;
    font-size: 0.8rem;
    color: #6c757d;
  }
  .dim-card .signals strong { color: #495057; }
  .dim-relevance   { border-left: 4px solid #2dd4bf; }
  .dim-completeness { border-left: 4px solid #fbbf24; }
  .dim-credibility  { border-left: 4px solid #a78bfa; }
  .dim-clarity      { border-left: 4px solid #fb7185; }
  .dim-relevance   h4 { color: #0f766e; }
  .dim-completeness h4 { color: #92400e; }
  .dim-credibility  h4 { color: #5b21b6; }
  .dim-clarity      h4 { color: #be185d; }

  /* ── Chart sections ── */
  .section {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 10px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
  }
  .section h2 {
    font-size: 1.3rem;
    font-weight: 600;
    color: #f1f5f9;
    border-bottom: 2px solid #334155;
    padding-bottom: 0.5rem;
    margin-bottom: 1rem;
    margin-top: 0;
  }

  /* ── Chart description text ── */
  .chart-desc {
    font-size: 0.875rem;
    color: #6c757d;
    line-height: 1.65;
    margin-top: 1rem;
    padding: 0 0.25rem;
  }

  /* ── Interpretation callout ── */
  .callout {
    background: #e8f4f8;
    border-left: 4px solid #17a2b8;
    border-radius: 0 4px 4px 0;
    padding: 0.7rem 1rem;
    margin-top: 0.85rem;
    font-size: 0.875rem;
    color: #0c4a5e;
    line-height: 1.6;
  }
  .callout strong { color: #0a3d4f; }

  /* ── Table styles ── */
  table { width: 100%; border-collapse: collapse; font-size: 0.82rem; }
  thead tr { background: #0f172a; }
  th { padding: 0.6rem 0.75rem; text-align: left; color: #94a3b8;
       font-weight: 500; border-bottom: 1px solid #334155; }
  td { padding: 0.55rem 0.75rem; border-bottom: 1px solid #1e293b; color: #cbd5e1; }
  tr.ready { background: rgba(34, 197, 94, 0.08); }
  tr:hover { background: #263347; }
  .badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px;
           font-size: 0.75rem; font-weight: 600; }
  .badge-yes { background: rgba(34,197,94,0.2); color: #4ade80; }
  .badge-no  { background: rgba(239,68,68,0.2); color: #f87171; }

  /* ── What Happens Next ── */
  .next-section {
    margin-bottom: 1.5rem;
  }
  .next-section h2 {
    font-size: 1.3rem;
    font-weight: 600;
    color: #f1f5f9;
    border-bottom: 2px solid #334155;
    padding-bottom: 0.5rem;
    margin-bottom: 1rem;
  }
  .next-grid {
    display: flex;
    gap: 1rem;
    flex-wrap: wrap;
  }
  .next-card {
    flex: 1;
    min-width: 200px;
    background: #fff;
    border-radius: 6px;
    padding: 1rem 1.1rem;
    font-size: 0.875rem;
    line-height: 1.65;
    color: #343a40;
  }
  .next-card h4 {
    font-size: 0.85rem;
    font-weight: 700;
    font-family: 'Courier New', Courier, monospace;
    margin-bottom: 0.6rem;
    color: #1a202c;
  }
  .next-card-green  { border-top: 4px solid #28a745; }
  .next-card-amber  { border-top: 4px solid #ffc107; }
  .next-card-blue   { border-top: 4px solid #17a2b8; }

  /* ── Footer ── */
  .footer { text-align: center; color: #475569; font-size: 0.8rem;
            margin-top: 2rem; padding-bottom: 1rem; }
</style>
"""


# ── Data helpers ─────────────────────────────────────────────────────────────

def _load_records(scored_path: str) -> list:
    records = []
    with open(scored_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def _compute_stats(records: list) -> dict:
    """Compute all dynamic values used in callouts."""
    total = len(records)
    if not total:
        return {}

    scores = [r.get("composite_score", 0.0) for r in records]
    ready_count = sum(1 for r in records if r.get("training_ready"))

    median_score = statistics.median(scores)

    cred_scores = sorted(r.get("source_credibility_score", 0.0) for r in records)
    n = len(cred_scores)
    q1 = statistics.median(cred_scores[: n // 2])
    q3 = statistics.median(cred_scores[(n + 1) // 2 :])
    source_cred_iqr = q3 - q1

    sev_counts: dict = {}
    for r in records:
        sev = (r.get("severity") or "UNKNOWN").upper()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
    top_severity = max(sev_counts, key=sev_counts.get)
    top_severity_pct = sev_counts[top_severity] / total * 100

    top20 = sorted(records, key=lambda r: r.get("composite_score", 0), reverse=True)[:20]
    top20_avg = sum(r.get("composite_score", 0) for r in top20) / len(top20) if top20 else 0.0
    top20_nvd_pct = (
        sum(1 for r in top20 if r.get("source") == "nvd") / len(top20) * 100
        if top20
        else 0.0
    )

    return {
        "total":            total,
        "ready_count":      ready_count,
        "pass_rate":        ready_count / total * 100,
        "avg_composite":    sum(scores) / total,
        "median_score":     median_score,
        "source_cred_iqr":  source_cred_iqr,
        "top_severity":     top_severity,
        "top_severity_pct": top_severity_pct,
        "top20_avg":        top20_avg,
        "top20_nvd_pct":    top20_nvd_pct,
    }


def _chart_html(fig, include_js: bool) -> str:
    js_mode = "cdn" if include_js else False
    return fig.to_html(full_html=False, include_plotlyjs=js_mode, config={"responsive": True})


# ── Section 1: Training Readiness Donut ─────────────────────────────────────

def _donut_chart(records: list) -> str:
    ready    = sum(1 for r in records if r.get("composite_score", 0) >= QUALITY_THRESHOLD)
    review   = sum(1 for r in records if 0.40 <= r.get("composite_score", 0) < QUALITY_THRESHOLD)
    rejected = sum(1 for r in records if r.get("composite_score", 0) < 0.40)
    total    = len(records)

    labels  = ["Training Ready", "Review Queue", "Rejected"]
    values  = [ready, review, rejected]
    colours = ["#22c55e", "#f59e0b", "#ef4444"]
    pcts    = [f"{v/total*100:.1f}%" if total else "0%" for v in values]
    text    = [f"{v} ({p})" for v, p in zip(values, pcts)]

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
        ("relevance_score",          "Relevance",   COLOUR_RELEVANCE),
        ("completeness_score",       "Completeness",COLOUR_COMPLETENESS),
        ("source_credibility_score", "Credibility", COLOUR_CREDIBILITY),
        ("clarity_score",            "Clarity",     COLOUR_CLARITY),
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

    labels  = SEVERITY_ORDER
    values  = [counts[s] for s in labels]
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
        ready      = r.get("training_ready", False)
        badge      = '<span class="badge badge-yes">Yes</span>' if ready else '<span class="badge badge-no">No</span>'
        row_class  = ' class="ready"' if ready else ""
        sev        = r.get("severity") or "—"
        cvss       = fmt(r.get("cvss_score"))
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

    return (
        "<table><thead><tr>"
        "<th>CVE ID</th><th>Severity</th><th>CVSS</th><th>Composite</th>"
        "<th>Relevance</th><th>Completeness</th><th>Clarity</th><th>Training Ready</th>"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


# ── Section 6: Dimension Heatmap (top 50) ───────────────────────────────────

def _heatmap(records: list) -> str:
    top50      = sorted(records, key=lambda r: r.get("composite_score", 0), reverse=True)[:50]
    dim_fields = ["relevance_score", "completeness_score", "source_credibility_score", "clarity_score"]
    dim_labels = ["Relevance", "Completeness", "Credibility", "Clarity"]
    cve_ids    = [r.get("cve_id", "") for r in top50]
    z          = [[r.get(f, 0) for f in dim_fields] for r in top50]

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


# ── Content helpers ───────────────────────────────────────────────────────────

def _exec_summary_html() -> str:
    return """
<div class="exec-summary">
  <h3>About This Report</h3>
  <p>This report summarises the output of the Cybersecurity Dataset Curation Pipeline,
  a multi-stage data pipeline that ingests CVE (Common Vulnerabilities and Exposures)
  records from the National Vulnerability Database (NVD) and applies domain-specific
  quality scoring to identify records suitable for use as LLM training data.</p>
  <p>Each CVE record is scored across four quality dimensions &mdash; Relevance, Completeness,
  Source Credibility, and Clarity &mdash; and assigned a composite quality score between 0.0
  and 1.0. Records scoring 0.60 or above are classified as Training Ready. Records
  between 0.40 and 0.59 enter a human Review Queue. Records below 0.40 are Rejected.</p>
  <p>The scored dataset is curated source material, not training data directly. Downstream
  processes convert high-quality records into instruction-following pairs, preference
  pairs for RLHF, or classification examples depending on the training objective.</p>
</div>
"""


def _methodology_panel_html() -> str:
    return f"""
<div class="methodology-panel">
  <h3>Scoring Methodology</h3>
  <p class="intro">Each record is evaluated across four dimensions. Scores are combined
  into a weighted composite score (0.0&ndash;1.0). The quality threshold is {QUALITY_THRESHOLD}.</p>
  <div class="dim-grid">

    <div class="dim-card dim-relevance">
      <h4>Relevance &nbsp;<span style="font-weight:400;color:#6c757d;">[35%]</span></h4>
      <p>Measures how security-relevant the record is as training data. Cybersecurity LLMs
      need exposure to high-severity, well-categorised vulnerabilities to learn accurate
      threat representations. Records covering critical or high-severity issues with
      recognised weakness classifications are weighted most highly.</p>
      <p class="signals"><strong>Signals used:</strong> CVSS base score tier, CWE ID presence,
      security keyword density (exploit, injection, overflow, privilege escalation, RCE, XSS, SQLi, etc.)</p>
    </div>

    <div class="dim-card dim-completeness">
      <h4>Completeness &nbsp;<span style="font-weight:400;color:#6c757d;">[25%]</span></h4>
      <p>Measures how fully populated the record is across all structured fields. Incomplete
      records &mdash; those missing a CVSS score, severity rating, or weakness classification &mdash;
      provide weaker training signal because the model cannot learn the relationships
      between vulnerability characteristics. A fully populated record teaches severity
      assessment; a partial one does not.</p>
      <p class="signals"><strong>Signals used:</strong> Presence of description, CVSS score,
      severity band, CWE IDs, published date</p>
    </div>

    <div class="dim-card dim-credibility">
      <h4>Source Credibility &nbsp;<span style="font-weight:400;color:#6c757d;">[25%]</span></h4>
      <p>Measures the authority and verifiability of the record&rsquo;s origin. NVD records are
      maintained by NIST and undergo formal review before publication, making them the
      gold standard for CVE data. Secondary aggregators may lag, omit fields, or introduce
      normalisation errors. Source credibility is weighted equally with completeness because
      authoritative sourcing is non-negotiable for safety-critical training data.</p>
      <p class="signals"><strong>Signals used:</strong> Data source (NVD=1.0, HuggingFace mirror=0.6),
      CVSS score presence as a proxy for formal assessment</p>
    </div>

    <div class="dim-card dim-clarity">
      <h4>Clarity &nbsp;<span style="font-weight:400;color:#6c757d;">[15%]</span></h4>
      <p>Measures description readability and usability as training text. NVD descriptions
      vary significantly in length and quality: some are concise and precise, others are
      truncated, garbled, or contain placeholder text. Placeholder entries
      (<code>** RESERVED **</code>, <code>** REJECT **</code>) indicate CVE IDs that were reserved but never
      formally assigned or were retracted &mdash; these are hard-excluded regardless of composite score.</p>
      <p class="signals"><strong>Signals used:</strong> Description character length
      (optimal 100&ndash;1000 chars), placeholder text detection</p>
    </div>

  </div>
</div>
"""


def _what_happens_next_html() -> str:
    return """
<div class="next-section">
  <h2>What Happens Next</h2>
  <div class="next-grid">

    <div class="next-card next-card-green">
      <h4>training_final.jsonl</h4>
      <p>Records passing the 0.60 threshold, stratified-sampled for severity
      balance, and decontaminated against the training cutoff date. These are
      promoted to the downstream formatting stage where they are converted into
      instruction-following pairs or RLHF preference pairs depending on the
      training objective.</p>
    </div>

    <div class="next-card next-card-amber">
      <h4>review_queue.jsonl</h4>
      <p>Records scoring 0.40&ndash;0.59. These are not automatically excluded &mdash;
      they are surfaced for human annotator review. A borderline record with a
      complete CVSS entry and CWE classification may be worth including despite
      a low clarity score. Human review at this tier is where annotation budget
      has the highest marginal impact on dataset quality.</p>
    </div>

    <div class="next-card next-card-blue">
      <h4>flagged_contamination.jsonl</h4>
      <p>Records published after the training data cutoff date (default:
      2024-08-01). These are isolated rather than discarded &mdash; they may be
      valuable for fine-tuning or evaluation but must not be mixed with
      pre-training data without careful tracking to avoid benchmark contamination.</p>
    </div>

  </div>
</div>
"""


# ── Main assembly ─────────────────────────────────────────────────────────────

def generate_report(
    scored_path: str = SCORED_PATH,
    output_path: str = REPORT_OUTPUT,
) -> None:
    """Generate a standalone HTML curation report from the scored JSONL."""
    if not os.path.exists(scored_path):
        raise FileNotFoundError(
            f"Scored data not found at '{scored_path}'. Run --stage score first."
        )

    records = _load_records(scored_path)
    if not records:
        raise ValueError(f"No records found in '{scored_path}'.")

    st           = _compute_stats(records)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    print(f"[Report] Generating report for {st['total']} records ...")

    # ── Charts (unchanged logic) ──────────────────────────────────────────────
    donut_html     = _donut_chart(records)   # first — includes plotlyjs cdn
    histogram_html = _histogram(records)
    boxplot_html   = _box_plot(records)
    severity_html  = _severity_bar(records)
    table_html     = _top20_table(records)
    heatmap_html   = _heatmap(records)

    # ── Dynamic callout strings ───────────────────────────────────────────────
    below_above    = "below" if st["median_score"] < QUALITY_THRESHOLD else "above"

    callout_s1 = (
        f"<strong>Key insight:</strong> {st['pass_rate']:.1f}% of ingested records meet the "
        f"training-ready threshold &mdash; consistent with NVD&rsquo;s inclusion of reserved "
        f"and incomplete entries in its public feed."
    )
    callout_s2 = (
        f"<strong>Key insight:</strong> The median composite score is {st['median_score']:.2f}, "
        f"with the majority of records clustering <em>{below_above}</em> the 0.60 threshold."
    )
    callout_s3 = (
        f"<strong>Key insight:</strong> Source Credibility shows the lowest variance "
        f"(IQR: {st['source_cred_iqr']:.2f}), reflecting that source authority is binary "
        f"(NVD vs. aggregator) rather than a continuous signal."
    )
    callout_s4 = (
        f"<strong>Key insight:</strong> {st['top_severity']} severity records account for the "
        f"largest share of the dataset ({st['top_severity_pct']:.1f}%). Stratified sampling "
        f"in the filter stage corrects for this imbalance."
    )
    callout_s5 = (
        f"<strong>Key insight:</strong> The top 20 records have an average composite score of "
        f"{st['top20_avg']:.2f}, with {st['top20_nvd_pct']:.0f}% sourced directly from NVD."
    )
    callout_s6 = (
        "<strong>Key insight:</strong> Records scoring below 0.5 on Clarity are highlighted "
        "in the heatmap &mdash; these are candidates for hard exclusion regardless of their "
        "composite score."
    )

    # ── HTML assembly ─────────────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Cybersecurity Training Data &mdash; Curation Report</title>
  {CSS}
</head>
<body>

<div class="top-bar"></div>

<div class="sticky-nav">
  <span class="nav-title">Cybersecurity Training Data &mdash; Curation Report</span>
  <span class="nav-meta">Tom White &nbsp;&bull;&nbsp; Pipeline {PIPELINE_VERSION} &nbsp;&bull;&nbsp; {generated_at}</span>
</div>

<div class="content-wrapper">

  <!-- Page header -->
  <div class="header">
    <h1>Cybersecurity Training Data &mdash; Curation Report</h1>
    <div class="subtitle">Prepared by Tom White &nbsp;&bull;&nbsp; Pipeline {PIPELINE_VERSION} &nbsp;&bull;&nbsp; Generated {generated_at}</div>
    <div class="stats-bar">
      <div class="stat-card">
        <div class="value">{st['total']:,}</div>
        <div class="label">Total Records</div>
      </div>
      <div class="stat-card">
        <div class="value">{st['ready_count']:,}</div>
        <div class="label">Training Ready</div>
      </div>
      <div class="stat-card">
        <div class="value">{st['pass_rate']:.1f}%</div>
        <div class="label">Pass Rate</div>
      </div>
      <div class="stat-card">
        <div class="value">{st['avg_composite']:.3f}</div>
        <div class="label">Avg Composite</div>
      </div>
    </div>
  </div>

  <!-- Executive summary -->
  {_exec_summary_html()}

  <!-- Scoring methodology definitions -->
  {_methodology_panel_html()}

  <!-- Section 1: Training Readiness Breakdown -->
  <div class="section">
    <h2>1. Training Readiness Breakdown</h2>
    {donut_html}
    <p class="chart-desc">The three tiers reflect a deliberate design choice: rather than a binary pass/fail
    threshold, the pipeline surfaces a Review Queue of borderline records for human annotators to inspect.
    In practice, automated scoring cannot perfectly distinguish a 0.58 record from a 0.62 record &mdash;
    the review queue acknowledges this uncertainty rather than hiding it behind a hard cutoff.</p>
    <div class="callout">{callout_s1}</div>
  </div>

  <!-- Section 2: Composite Score Distribution -->
  <div class="section">
    <h2>2. Composite Score Distribution</h2>
    {histogram_html}
    <p class="chart-desc">The distribution shape indicates the overall quality profile of the ingested dataset.
    A concentration of records below 0.40 is expected &mdash; NVD contains a significant proportion of
    placeholder, reserved, and minimally-documented entries. The vertical threshold line marks the
    training-ready boundary at 0.60.</p>
    <div class="callout">{callout_s2}</div>
  </div>

  <!-- Section 3: Score Breakdown by Dimension -->
  <div class="section">
    <h2>3. Score Breakdown by Dimension</h2>
    {boxplot_html}
    <p class="chart-desc">Box plots show the median, interquartile range, and outliers for each scoring
    dimension independently. Source Credibility typically shows the least variance because it is primarily
    determined by data source (NVD vs. HuggingFace). Relevance and Clarity tend to show the widest spread,
    reflecting genuine variation in CVE documentation quality across the dataset.</p>
    <div class="callout">{callout_s3}</div>
  </div>

  <!-- Section 4: Severity Distribution -->
  <div class="section">
    <h2>4. Severity Distribution</h2>
    {severity_html}
    <p class="chart-desc">Severity bands are derived from NVD&rsquo;s CVSS v3.1 base score:
    CRITICAL (&ge;9.0), HIGH (7.0&ndash;8.9), MEDIUM (4.0&ndash;6.9), LOW (&lt;4.0).
    Records without a CVSS score are classified as UNKNOWN. NVD historically skews toward MEDIUM
    severity &mdash; the stratified sampling stage in the filter pipeline corrects for this imbalance
    before training data is assembled.</p>
    <div class="callout">{callout_s4}</div>
  </div>

  <!-- Section 5: Top 20 Training-Ready Records -->
  <div class="section">
    <h2>5. Top 20 Training-Ready Records</h2>
    {table_html}
    <p class="chart-desc">The highest-scoring records by composite score. These represent the most
    complete, credible, and clearly-described vulnerability entries in the dataset. In a production
    pipeline, these would typically be prioritised for human review to validate automated scoring
    before being promoted to the training corpus.</p>
    <div class="callout">{callout_s5}</div>
  </div>

  <!-- Section 6: Dimension Score Heatmap -->
  <div class="section">
    <h2>6. Dimension Score Heatmap (Top 50 Records)</h2>
    {heatmap_html}
    <p class="chart-desc">A per-record view of how scores distribute across dimensions for the top 50
    records. Rows with strong green across all four dimensions are the most balanced and
    highest-confidence training candidates. Rows with a red cell in any dimension &mdash; even if
    composite score is high &mdash; may warrant manual review before inclusion.</p>
    <div class="callout">{callout_s6}</div>
  </div>

  <!-- What Happens Next -->
  {_what_happens_next_html()}

  <div class="footer">
    Generated by cyb-dq-curation {PIPELINE_VERSION} &nbsp;&bull;&nbsp; NVD + HuggingFace CVE sources
  </div>

</div><!-- /content-wrapper -->
</body>
</html>"""

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[Report] Report saved to: {output_path}")
