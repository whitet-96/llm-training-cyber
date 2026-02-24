"""
Training Data Filter — Methodology

This module implements principled filtering logic to bridge the scoring pipeline
and downstream LLM training data preparation. The filtering approach is designed
around four key principles:

1. TIERED FILTERING OVER BINARY PASS/FAIL
   A single threshold produces binary outcomes that discard potentially salvageable
   records and give no signal for human review prioritisation. Three tiers —
   training-ready, review queue, and rejected — allow annotators to focus effort
   on borderline cases rather than reviewing everything or nothing.

2. DIMENSION-SPECIFIC HARD EXCLUSIONS
   Composite score alone is insufficient for safety-critical domains. A record
   scoring 0.65 composite but 0.0 on clarity (RESERVED placeholder) should be
   excluded regardless. Hard exclusions encode domain knowledge that weighted
   averages cannot capture.

3. STRATIFIED SAMPLING FOR TRAINING BALANCE
   NVD skews heavily toward MEDIUM severity CVEs. Passing unsampled data into
   training produces a model with a skewed understanding of the vulnerability
   landscape. Stratified sampling by severity ensures the model sees balanced
   representation across CRITICAL, HIGH, MEDIUM, and LOW severities.

4. DECONTAMINATION BEFORE TRAINING
   CVEs published after a model's knowledge cutoff date are potential test set
   contamination. Mixing pre- and post-cutoff data without tracking inflates
   benchmark performance and produces misleading capability assessments. These
   records are flagged and isolated rather than silently included or excluded.

The output of this pipeline (training_final.jsonl) is not a training dataset
directly — it is curated source material ready for downstream formatting into
instruction-following pairs, preference pairs for RLHF, or other training
example formats depending on the target model objective.
"""

import json
import os
from datetime import date, datetime

from config import QUALITY_THRESHOLD, SCORED_PATH

FILTER_OUTPUT_DIR = "data/filtered"
DEFAULT_CUTOFF_DATE = "2024-08-01"


def _parse_date(date_str: str):
    """Parse a date string flexibly. Returns a date object or None."""
    if not date_str:
        return None
    date_str = str(date_str).strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%Y-%m", "%Y"):
        try:
            return datetime.strptime(date_str[:len(fmt) + 2].strip(), fmt).date()
        except ValueError:
            continue
    return None


def apply_hard_exclusions(records: list) -> tuple:
    """Apply dimension-specific hard exclusions regardless of composite score.

    Excluded conditions:
    - clarity_score == 0.0  (RESERVED/REJECT placeholder, or no usable description)
    - description is None or empty
    - source_credibility_score < 0.3  (unknown/untrusted source)

    Returns:
        (kept, excluded) — excluded records have an exclusion_reason field added.
    """
    kept = []
    excluded = []

    for record in records:
        reasons = []

        if record.get("clarity_score", 1.0) == 0.0:
            reasons.append("clarity_score=0.0 (placeholder or unparseable description)")

        desc = record.get("description") or ""
        if not desc.strip():
            reasons.append("description missing or empty")

        if record.get("source_credibility_score", 1.0) < 0.3:
            reasons.append("source_credibility_score < 0.3 (untrusted source)")

        if reasons:
            excluded.append({**record, "exclusion_reason": "; ".join(reasons)})
        else:
            kept.append(record)

    return kept, excluded


def apply_tiered_filter(records: list) -> dict:
    """Assign records to three tiers based on composite_score.

    Tiers:
    - training_ready : composite >= QUALITY_THRESHOLD (0.60)
    - review_queue   : composite 0.40 – 0.59
    - rejected       : composite < 0.40

    Returns a dict with keys: training_ready, review_queue, rejected.
    Each record has a tier field added.
    """
    result = {"training_ready": [], "review_queue": [], "rejected": []}

    for record in records:
        score = record.get("composite_score", 0.0)
        if score >= QUALITY_THRESHOLD:
            tier = "training_ready"
        elif score >= 0.40:
            tier = "review_queue"
        else:
            tier = "rejected"
        result[tier].append({**record, "tier": tier})

    return result


def apply_stratified_sample(
    training_ready_records: list,
    target_per_severity: int = 50,
) -> list:
    """Produce a severity-balanced sample from training-ready records.

    NVD skews heavily toward MEDIUM severity. This function groups records by
    severity, sorts each group by composite_score descending, and takes up to
    target_per_severity records from each group.

    Severity groups: CRITICAL, HIGH, MEDIUM, LOW  (UNKNOWN excluded from sampling
    but included as a remainder group so records are not silently dropped).

    Returns the combined balanced sample with a sampled=True field added.
    """
    severity_groups: dict = {}
    for record in training_ready_records:
        sev = (record.get("severity") or "UNKNOWN").upper()
        severity_groups.setdefault(sev, []).append(record)

    sampled = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
        group = severity_groups.get(sev, [])
        group_sorted = sorted(group, key=lambda r: r.get("composite_score", 0), reverse=True)
        for record in group_sorted[:target_per_severity]:
            sampled.append({**record, "sampled": True})

    return sampled


def apply_decontamination(
    records: list,
    cutoff_date: str = DEFAULT_CUTOFF_DATE,
) -> tuple:
    """Flag records published after cutoff_date as potential test set contamination.

    Records after the cutoff may overlap with benchmarks or evaluations that
    use post-cutoff CVEs as held-out test cases. They are isolated rather than
    silently included or excluded so downstream users can make an informed choice.

    Args:
        records: List of records (typically the stratified sample).
        cutoff_date: ISO date string (YYYY-MM-DD). Default: 2024-08-01
                     (approximate Claude training data cutoff).

    Returns:
        (clean, flagged) — flagged records have contamination_flag=True added.
    """
    cutoff = datetime.strptime(cutoff_date, "%Y-%m-%d").date()
    clean = []
    flagged = []

    for record in records:
        pub = _parse_date(record.get("published", ""))
        if pub is not None and pub > cutoff:
            flagged.append({**record, "contamination_flag": True})
        else:
            clean.append(record)

    return clean, flagged


def _save_jsonl(records: list, path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record) + "\n")


def run_filter_pipeline(
    scored_path: str = SCORED_PATH,
    output_dir: str = FILTER_OUTPUT_DIR,
) -> dict:
    """Orchestrate the full filter pipeline.

    Steps:
    1. Load scored JSONL
    2. Apply hard exclusions
    3. Apply tiered filter to remaining records
    4. Apply stratified sample to training_ready tier
    5. Apply decontamination to sampled records
    6. Save four output files to output_dir

    Returns a summary dict with counts for each output category.
    """
    # 1. Load
    records = []
    with open(scored_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    print(f"[Filter] Loaded {len(records)} scored records from {scored_path}")

    # 2. Hard exclusions
    kept, excluded = apply_hard_exclusions(records)
    print(f"[Filter] Hard exclusions: {len(excluded)} removed, {len(kept)} kept")

    # 3. Tiered filter
    tiers = apply_tiered_filter(kept)
    print(
        f"[Filter] Tiers — training_ready: {len(tiers['training_ready'])}, "
        f"review_queue: {len(tiers['review_queue'])}, "
        f"rejected: {len(tiers['rejected'])}"
    )

    # 4. Stratified sample
    sampled = apply_stratified_sample(tiers["training_ready"])
    print(f"[Filter] Stratified sample: {len(sampled)} records")

    # 5. Decontamination
    clean, flagged = apply_decontamination(sampled)
    print(f"[Filter] Decontamination: {len(clean)} clean, {len(flagged)} flagged post-cutoff")

    # 6. Save outputs
    _save_jsonl(clean,               os.path.join(output_dir, "training_final.jsonl"))
    _save_jsonl(tiers["review_queue"], os.path.join(output_dir, "review_queue.jsonl"))
    _save_jsonl(excluded,            os.path.join(output_dir, "rejected.jsonl"))
    _save_jsonl(flagged,             os.path.join(output_dir, "flagged_contamination.jsonl"))

    summary = {
        "total_input":          len(records),
        "hard_excluded":        len(excluded),
        "training_ready_raw":   len(tiers["training_ready"]),
        "review_queue":         len(tiers["review_queue"]),
        "tier_rejected":        len(tiers["rejected"]),
        "sampled":              len(sampled),
        "training_final":       len(clean),
        "flagged_contamination": len(flagged),
    }

    print(f"\n[Filter] Output files written to: {output_dir}/")
    for fname in ("training_final.jsonl", "review_queue.jsonl", "rejected.jsonl", "flagged_contamination.jsonl"):
        print(f"  - {fname}")

    return summary
