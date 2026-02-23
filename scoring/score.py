from datetime import datetime, timezone

from config import (
    WEIGHT_RELEVANCE,
    WEIGHT_COMPLETENESS,
    WEIGHT_SOURCE_CREDIBILITY,
    WEIGHT_CLARITY,
    QUALITY_THRESHOLD,
    MIN_DESCRIPTION_LENGTH,
    MAX_DESCRIPTION_LENGTH,
    PIPELINE_VERSION,
)

SECURITY_KEYWORDS = [
    "exploit",
    "vulnerability",
    "injection",
    "overflow",
    "bypass",
    "authentication",
    "privilege",
    "remote code execution",
    "xss",
    "sqli",
    "rce",
    "buffer overflow",
    "use-after-free",
]


def score_relevance(record: dict) -> float:
    """Score 0.0–1.0 measuring security relevance of the record."""
    score = 0.0
    cvss = record.get("cvss_score")
    description = (record.get("description") or "").lower()
    cwe_ids = record.get("cwe_ids") or []

    if cvss is not None:
        if cvss >= 7.0:
            score += 0.4
        elif cvss >= 4.0:
            score += 0.2

    if cwe_ids:
        score += 0.3

    keyword_bonus = 0.0
    for kw in SECURITY_KEYWORDS:
        if kw in description:
            keyword_bonus += 0.1
        if keyword_bonus >= 0.3:
            break
    score += keyword_bonus

    return min(score, 1.0)


def score_completeness(record: dict) -> float:
    """Score 0.0–1.0 measuring how complete the record is for training."""
    score = 0.0
    description = record.get("description") or ""
    desc_len = len(description)

    if description and MIN_DESCRIPTION_LENGTH <= desc_len <= MAX_DESCRIPTION_LENGTH:
        score += 0.4

    if record.get("cvss_score") is not None:
        score += 0.2

    if record.get("severity"):
        score += 0.1

    if record.get("cwe_ids"):
        score += 0.2

    if record.get("published"):
        score += 0.1

    return min(score, 1.0)


def score_source_credibility(record: dict) -> float:
    """Score 0.0–1.0 measuring trustworthiness of the data source."""
    source = (record.get("source") or "").lower()

    if source == "nvd":
        base = 1.0
    elif source == "huggingface":
        base = 0.6
    else:
        base = 0.3

    boost = 0.1 if record.get("cvss_score") is not None else 0.0
    return min(base + boost, 1.0)


def score_clarity(record: dict) -> float:
    """Score 0.0–1.0 measuring description readability."""
    description = record.get("description") or ""
    desc_len = len(description)

    # NVD placeholder text — essentially no useful content
    if "** RESERVED **" in description or "** REJECT **" in description:
        return 0.0

    if 100 <= desc_len <= 1000:
        base = 1.0
    elif (50 <= desc_len < 100) or (1001 <= desc_len <= 2000):
        base = 0.7
    elif 2001 <= desc_len <= 5000:
        base = 0.4
    else:
        base = 0.0

    return max(base, 0.0)


def compute_composite(record: dict) -> dict:
    """Compute weighted composite score with hard-filter gate.

    Returns a dict containing all four dimension scores, composite_score,
    and training_ready boolean.
    """
    description = record.get("description") or ""
    desc_len = len(description)

    # Hard filters: missing or out-of-bounds description → immediate reject
    if not description or not (MIN_DESCRIPTION_LENGTH <= desc_len <= MAX_DESCRIPTION_LENGTH):
        return {
            "relevance_score": 0.0,
            "completeness_score": 0.0,
            "source_credibility_score": 0.0,
            "clarity_score": 0.0,
            "composite_score": 0.0,
            "training_ready": False,
        }

    relevance = score_relevance(record)
    completeness = score_completeness(record)
    credibility = score_source_credibility(record)
    clarity = score_clarity(record)

    composite = (
        WEIGHT_RELEVANCE * relevance
        + WEIGHT_COMPLETENESS * completeness
        + WEIGHT_SOURCE_CREDIBILITY * credibility
        + WEIGHT_CLARITY * clarity
    )
    composite = round(min(max(composite, 0.0), 1.0), 4)

    return {
        "relevance_score": round(relevance, 4),
        "completeness_score": round(completeness, 4),
        "source_credibility_score": round(credibility, 4),
        "clarity_score": round(clarity, 4),
        "composite_score": composite,
        "training_ready": composite >= QUALITY_THRESHOLD,
    }


def score_dataset(records: list) -> list:
    """Run compute_composite on every record and enrich with metadata."""
    scored_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    enriched = []
    for record in records:
        scores = compute_composite(record)
        enriched_record = {**record, **scores, "pipeline_version": PIPELINE_VERSION, "scored_at": scored_at}
        enriched.append(enriched_record)
    return enriched
