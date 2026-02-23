"""Unit tests for scoring/score.py — cybersecurity quality scoring pipeline."""

import sys
import os

# Ensure project root is on path so `config` and `scoring` are importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from scoring.score import (
    score_relevance,
    score_completeness,
    score_source_credibility,
    score_clarity,
    compute_composite,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def empty_record():
    """Record with no useful fields."""
    return {
        "cve_id": "CVE-2000-0001",
        "description": "",
        "published": "",
        "last_modified": "",
        "cvss_score": None,
        "severity": None,
        "cwe_ids": [],
        "source": "nvd",
    }


@pytest.fixture
def minimal_record():
    """Record with a short description but no CVSS or CWE."""
    return {
        "cve_id": "CVE-2020-0001",
        "description": "A minor issue exists in software version 1.0.",  # 47 chars — below MIN
        "published": "2020-01-01",
        "last_modified": "",
        "cvss_score": None,
        "severity": None,
        "cwe_ids": [],
        "source": "huggingface",
    }


@pytest.fixture
def high_quality_record():
    """Fully populated, high-quality CVE record."""
    return {
        "cve_id": "CVE-2023-44487",
        "description": (
            "The HTTP/2 protocol allows a denial of service (server resource "
            "consumption) because request cancellation can reset many streams "
            "quickly, as exploited in the wild in August through October 2023. "
            "This vulnerability allows remote code execution via a crafted request."
        ),
        "published": "2023-10-10",
        "last_modified": "2023-11-01",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "cwe_ids": ["CWE-400"],
        "source": "nvd",
    }


@pytest.fixture
def medium_cvss_record():
    """Record with medium CVSS, no CWE."""
    return {
        "cve_id": "CVE-2021-0001",
        "description": "A medium-severity issue that allows bypass of authentication in affected systems through a crafted HTTP request. This affects all versions prior to 2.0.",
        "published": "2021-06-01",
        "last_modified": "",
        "cvss_score": 5.5,
        "severity": "MEDIUM",
        "cwe_ids": [],
        "source": "nvd",
    }


@pytest.fixture
def reserved_record():
    """NVD placeholder record with RESERVED text."""
    return {
        "cve_id": "CVE-2024-99999",
        "description": "** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem.",
        "published": "2024-01-01",
        "last_modified": "",
        "cvss_score": None,
        "severity": None,
        "cwe_ids": [],
        "source": "nvd",
    }


@pytest.fixture
def hf_record_no_cvss():
    """HuggingFace record without CVSS score."""
    return {
        "cve_id": "CVE-2019-0001",
        "description": "A SQL injection vulnerability exists in the login form of ExampleApp 3.x, allowing an unauthenticated attacker to read arbitrary database records.",
        "published": "2019-03-15",
        "last_modified": "",
        "cvss_score": None,
        "severity": "HIGH",
        "cwe_ids": ["CWE-89"],
        "source": "huggingface",
    }


# ---------------------------------------------------------------------------
# score_relevance tests
# ---------------------------------------------------------------------------

def test_relevance_zero_for_empty_record(empty_record):
    """No CVSS, no CWE, no keywords → 0.0."""
    assert score_relevance(empty_record) == 0.0


def test_relevance_high_for_critical_record(high_quality_record):
    """CVSS 9.8 + CWE + keywords → > 0.5."""
    score = score_relevance(high_quality_record)
    assert score > 0.5


def test_relevance_medium_cvss_no_cwe(medium_cvss_record):
    """Medium CVSS (5.5) no CWE, but has 'bypass' and 'authentication' keywords."""
    score = score_relevance(medium_cvss_record)
    # +0.2 (medium CVSS) + 0.0 (no CWE) + keyword hits
    assert score > 0.2


def test_relevance_capped_at_one(high_quality_record):
    """Score should never exceed 1.0."""
    score = score_relevance(high_quality_record)
    assert score <= 1.0


def test_relevance_no_cvss_but_cwe_and_keywords(hf_record_no_cvss):
    """No CVSS but CWE + SQLi keyword → some relevance."""
    score = score_relevance(hf_record_no_cvss)
    assert score >= 0.3


# ---------------------------------------------------------------------------
# score_completeness tests
# ---------------------------------------------------------------------------

def test_completeness_full_record(high_quality_record):
    """Fully populated record → 1.0."""
    score = score_completeness(high_quality_record)
    assert score == 1.0


def test_completeness_missing_cvss_cwe_severity(minimal_record):
    """Record missing cvss, cwe, severity → < 0.5."""
    # minimal_record has no cvss, cwe, severity; description is too short for length bonus
    score = score_completeness(minimal_record)
    assert score < 0.5


def test_completeness_no_description(empty_record):
    """No description → no description bonus."""
    score = score_completeness(empty_record)
    # Only published date is missing too; NVD source but empty record
    assert score == 0.0


def test_completeness_capped_at_one(high_quality_record):
    assert score_completeness(high_quality_record) <= 1.0


# ---------------------------------------------------------------------------
# score_source_credibility tests
# ---------------------------------------------------------------------------

def test_credibility_nvd_returns_one(high_quality_record):
    """NVD source with CVSS → 1.0 (capped)."""
    score = score_source_credibility(high_quality_record)
    assert score == 1.0


def test_credibility_huggingface_no_cvss():
    """HuggingFace source, no CVSS → 0.6."""
    record = {"source": "huggingface", "cvss_score": None}
    assert score_source_credibility(record) == 0.6


def test_credibility_huggingface_with_cvss():
    """HuggingFace source + CVSS → 0.7 (0.6 + 0.1 boost)."""
    record = {"source": "huggingface", "cvss_score": 7.5}
    assert score_source_credibility(record) == 0.7


def test_credibility_unknown_source():
    """Unknown source without CVSS → 0.3."""
    record = {"source": "unknown_scraper", "cvss_score": None}
    assert score_source_credibility(record) == 0.3


# ---------------------------------------------------------------------------
# score_clarity tests
# ---------------------------------------------------------------------------

def test_clarity_reserved_returns_zero(reserved_record):
    """** RESERVED ** placeholder → 0.0."""
    assert score_clarity(reserved_record) == 0.0


def test_clarity_200_chars_returns_one():
    """Description of exactly 200 characters → 1.0."""
    record = {"description": "A" * 200}
    assert score_clarity(record) == 1.0


def test_clarity_short_description():
    """Description under 50 chars → 0.0."""
    record = {"description": "Too short."}
    assert score_clarity(record) == 0.0


def test_clarity_medium_long_description():
    """Description between 1001–2000 chars → 0.7."""
    record = {"description": "X" * 1500}
    assert score_clarity(record) == 0.7


def test_clarity_very_long_description():
    """Description between 2001–5000 chars → 0.4."""
    record = {"description": "X" * 3000}
    assert score_clarity(record) == 0.4


def test_clarity_reject_placeholder():
    """** REJECT ** placeholder → 0.0."""
    record = {"description": "** REJECT ** DO NOT USE THIS CANDIDATE NUMBER."}
    assert score_clarity(record) == 0.0


# ---------------------------------------------------------------------------
# compute_composite tests
# ---------------------------------------------------------------------------

def test_composite_zero_for_missing_description(empty_record):
    """Missing description → composite_score = 0.0."""
    result = compute_composite(empty_record)
    assert result["composite_score"] == 0.0
    assert result["training_ready"] is False


def test_composite_zero_for_short_description(minimal_record):
    """Description below MIN_DESCRIPTION_LENGTH → composite_score = 0.0."""
    # minimal_record description is 47 chars, below the 50-char minimum
    result = compute_composite(minimal_record)
    assert result["composite_score"] == 0.0
    assert result["training_ready"] is False


def test_composite_training_ready_for_high_quality(high_quality_record):
    """High-quality record → training_ready = True."""
    result = compute_composite(high_quality_record)
    assert result["training_ready"] is True
    assert result["composite_score"] >= 0.60


def test_composite_contains_all_dimension_scores(high_quality_record):
    """Result dict contains all expected keys."""
    result = compute_composite(high_quality_record)
    for key in ("relevance_score", "completeness_score", "source_credibility_score",
                "clarity_score", "composite_score", "training_ready"):
        assert key in result


def test_composite_always_between_zero_and_one(high_quality_record, medium_cvss_record, hf_record_no_cvss):
    """composite_score must be in [0.0, 1.0] for any valid input."""
    for record in [high_quality_record, medium_cvss_record, hf_record_no_cvss]:
        result = compute_composite(record)
        assert 0.0 <= result["composite_score"] <= 1.0


def test_composite_reserved_not_training_ready(reserved_record):
    """RESERVED placeholder passes length check but scores low → not training_ready."""
    result = compute_composite(reserved_record)
    # clarity = 0, relevance = 0, completeness low → composite well below 0.60
    assert result["training_ready"] is False
