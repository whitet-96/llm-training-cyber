"""Unit tests for filtering/filter.py — training data filter pipeline."""

import sys
import os
import json
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from filtering.filter import (
    apply_hard_exclusions,
    apply_tiered_filter,
    apply_stratified_sample,
    apply_decontamination,
    run_filter_pipeline,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_record(**kwargs):
    """Return a minimal valid scored record with overridable fields."""
    base = {
        "cve_id": "CVE-2023-00001",
        "description": "A SQL injection vulnerability in ExampleApp allows remote unauthenticated attackers to execute arbitrary SQL commands via a crafted HTTP request.",
        "published": "2023-06-15",
        "cvss_score": 8.1,
        "severity": "HIGH",
        "cwe_ids": ["CWE-89"],
        "source": "nvd",
        "relevance_score": 0.80,
        "completeness_score": 0.90,
        "source_credibility_score": 1.0,
        "clarity_score": 1.0,
        "composite_score": 0.87,
        "training_ready": True,
        "pipeline_version": "v0.1.0",
        "scored_at": "2026-02-24T00:00:00Z",
    }
    base.update(kwargs)
    return base


@pytest.fixture
def good_record():
    return _make_record()


@pytest.fixture
def reserved_record():
    return _make_record(
        cve_id="CVE-2024-99999",
        description="** RESERVED ** This candidate has been reserved.",
        clarity_score=0.0,
        composite_score=0.35,
        training_ready=False,
    )


@pytest.fixture
def empty_desc_record():
    return _make_record(
        cve_id="CVE-2023-00002",
        description="",
        clarity_score=0.0,
        composite_score=0.20,
        training_ready=False,
    )


@pytest.fixture
def low_credibility_record():
    return _make_record(
        cve_id="CVE-2023-00003",
        source="unknown_scraper",
        source_credibility_score=0.2,
        composite_score=0.45,
    )


@pytest.fixture
def review_record():
    """Sits in review queue: composite 0.40–0.59."""
    return _make_record(
        cve_id="CVE-2023-10001",
        composite_score=0.50,
        training_ready=False,
    )


@pytest.fixture
def rejected_record():
    """Below review queue: composite < 0.40."""
    return _make_record(
        cve_id="CVE-2023-20001",
        composite_score=0.30,
        training_ready=False,
    )


@pytest.fixture
def post_cutoff_record():
    return _make_record(
        cve_id="CVE-2025-00001",
        published="2025-01-15",
    )


@pytest.fixture
def pre_cutoff_record():
    return _make_record(
        cve_id="CVE-2023-00010",
        published="2023-01-01",
    )


# ---------------------------------------------------------------------------
# apply_hard_exclusions
# ---------------------------------------------------------------------------

def test_hard_exclusions_removes_reserved(reserved_record):
    """clarity_score=0.0 → excluded."""
    kept, excluded = apply_hard_exclusions([reserved_record])
    assert len(kept) == 0
    assert len(excluded) == 1
    assert "exclusion_reason" in excluded[0]
    assert "clarity_score=0.0" in excluded[0]["exclusion_reason"]


def test_hard_exclusions_removes_empty_description(empty_desc_record):
    """Empty description → excluded."""
    kept, excluded = apply_hard_exclusions([empty_desc_record])
    assert len(kept) == 0
    assert len(excluded) == 1
    assert "description missing or empty" in excluded[0]["exclusion_reason"]


def test_hard_exclusions_removes_low_credibility(low_credibility_record):
    """source_credibility_score < 0.3 → excluded."""
    kept, excluded = apply_hard_exclusions([low_credibility_record])
    assert len(kept) == 0
    assert len(excluded) == 1
    assert "source_credibility_score < 0.3" in excluded[0]["exclusion_reason"]


def test_hard_exclusions_keeps_good_record(good_record):
    """Valid record passes all hard exclusion checks."""
    kept, excluded = apply_hard_exclusions([good_record])
    assert len(kept) == 1
    assert len(excluded) == 0


def test_hard_exclusions_does_not_mutate_original(good_record):
    """Original record dict should not be mutated."""
    original_keys = set(good_record.keys())
    apply_hard_exclusions([good_record])
    assert set(good_record.keys()) == original_keys


# ---------------------------------------------------------------------------
# apply_tiered_filter
# ---------------------------------------------------------------------------

def test_tiered_filter_assigns_training_ready(good_record):
    """composite >= 0.60 → training_ready tier."""
    result = apply_tiered_filter([good_record])
    assert len(result["training_ready"]) == 1
    assert result["training_ready"][0]["tier"] == "training_ready"


def test_tiered_filter_assigns_review_queue(review_record):
    """composite 0.40–0.59 → review_queue tier."""
    result = apply_tiered_filter([review_record])
    assert len(result["review_queue"]) == 1
    assert result["review_queue"][0]["tier"] == "review_queue"


def test_tiered_filter_assigns_rejected(rejected_record):
    """composite < 0.40 → rejected tier."""
    result = apply_tiered_filter([rejected_record])
    assert len(result["rejected"]) == 1
    assert result["rejected"][0]["tier"] == "rejected"


def test_tiered_filter_boundary_values():
    """Test records exactly at the tier boundary scores."""
    at_threshold = _make_record(cve_id="CVE-X-1", composite_score=0.60)
    at_review_low = _make_record(cve_id="CVE-X-2", composite_score=0.40)
    just_below_review = _make_record(cve_id="CVE-X-3", composite_score=0.399)

    result = apply_tiered_filter([at_threshold, at_review_low, just_below_review])
    assert len(result["training_ready"]) == 1
    assert len(result["review_queue"]) == 1
    assert len(result["rejected"]) == 1


# ---------------------------------------------------------------------------
# apply_stratified_sample
# ---------------------------------------------------------------------------

def test_stratified_sample_cap_per_severity():
    """No severity group exceeds target_per_severity."""
    records = [
        _make_record(cve_id=f"CVE-H-{i}", severity="HIGH", composite_score=0.7 + i * 0.001)
        for i in range(100)
    ]
    sampled = apply_stratified_sample(records, target_per_severity=10)
    high_count = sum(1 for r in sampled if r["severity"] == "HIGH")
    assert high_count == 10


def test_stratified_sample_takes_all_when_below_target():
    """If fewer records than target, all are included."""
    records = [
        _make_record(cve_id="CVE-CRIT-1", severity="CRITICAL", composite_score=0.9),
        _make_record(cve_id="CVE-CRIT-2", severity="CRITICAL", composite_score=0.85),
    ]
    sampled = apply_stratified_sample(records, target_per_severity=50)
    crit_count = sum(1 for r in sampled if r["severity"] == "CRITICAL")
    assert crit_count == 2


def test_stratified_sample_sorted_by_composite_desc():
    """Within each severity group, highest composite_score records are sampled first."""
    records = [
        _make_record(cve_id="CVE-M-LOW",  severity="MEDIUM", composite_score=0.61),
        _make_record(cve_id="CVE-M-HIGH", severity="MEDIUM", composite_score=0.95),
        _make_record(cve_id="CVE-M-MID",  severity="MEDIUM", composite_score=0.75),
    ]
    sampled = apply_stratified_sample(records, target_per_severity=2)
    medium_sampled = [r for r in sampled if r["severity"] == "MEDIUM"]
    assert len(medium_sampled) == 2
    scores = [r["composite_score"] for r in medium_sampled]
    assert scores == sorted(scores, reverse=True)


def test_stratified_sample_adds_sampled_field():
    """All returned records should have sampled=True."""
    records = [_make_record(cve_id=f"CVE-{i}", severity="HIGH") for i in range(5)]
    sampled = apply_stratified_sample(records, target_per_severity=10)
    assert all(r.get("sampled") is True for r in sampled)


# ---------------------------------------------------------------------------
# apply_decontamination
# ---------------------------------------------------------------------------

def test_decontamination_flags_post_cutoff(post_cutoff_record):
    """Record published after cutoff → flagged."""
    clean, flagged = apply_decontamination([post_cutoff_record], cutoff_date="2024-08-01")
    assert len(flagged) == 1
    assert flagged[0].get("contamination_flag") is True
    assert len(clean) == 0


def test_decontamination_keeps_pre_cutoff(pre_cutoff_record):
    """Record published before cutoff → clean."""
    clean, flagged = apply_decontamination([pre_cutoff_record], cutoff_date="2024-08-01")
    assert len(clean) == 1
    assert len(flagged) == 0


def test_decontamination_handles_year_only_published():
    """Year-only published strings (from HF source) should parse correctly."""
    record = _make_record(cve_id="CVE-2020-0001", published="2020")
    clean, flagged = apply_decontamination([record], cutoff_date="2024-08-01")
    assert len(clean) == 1
    assert len(flagged) == 0


def test_decontamination_handles_missing_published():
    """Records with no published date → treated as clean (conservative)."""
    record = _make_record(cve_id="CVE-UNKNOWN-1", published="")
    clean, flagged = apply_decontamination([record], cutoff_date="2024-08-01")
    assert len(clean) == 1
    assert len(flagged) == 0


# ---------------------------------------------------------------------------
# run_filter_pipeline (integration)
# ---------------------------------------------------------------------------

def test_run_filter_pipeline_produces_four_output_files():
    """Full pipeline produces all four required output JSONL files."""
    records = [
        _make_record(cve_id=f"CVE-2023-{i:05d}", severity="HIGH", composite_score=0.75)
        for i in range(20)
    ] + [
        _make_record(
            cve_id="CVE-2024-99999",
            description="** RESERVED ** placeholder",
            clarity_score=0.0,
            composite_score=0.10,
            training_ready=False,
        )
    ]

    with tempfile.TemporaryDirectory() as tmpdir:
        scored_path = os.path.join(tmpdir, "scored.jsonl")
        output_dir  = os.path.join(tmpdir, "filtered")

        with open(scored_path, "w") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")

        summary = run_filter_pipeline(scored_path=scored_path, output_dir=output_dir)

        for fname in ("training_final.jsonl", "review_queue.jsonl",
                      "rejected.jsonl", "flagged_contamination.jsonl"):
            assert os.path.exists(os.path.join(output_dir, fname)), f"Missing: {fname}"

        # The RESERVED record should be hard-excluded
        assert summary["hard_excluded"] >= 1
        # The 20 good records should all reach training_ready
        assert summary["training_ready_raw"] == 20
