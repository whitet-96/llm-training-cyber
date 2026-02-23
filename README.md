# Cybersecurity Dataset Curation Pipeline

A domain-specific curation pipeline for cybersecurity training data, ingesting CVE records from NVD and HuggingFace, applying security-relevant quality scoring, and outputting a curated JSONL dataset with a Data Card.

> **Part of a two-project portfolio demonstrating LLM training data operations across coding and cybersecurity domains. See also: [LLM Data Quality Scoring Pipeline](https://github.com/whitet-96/llm-dq-scoring)**

---

## Why This Project

Cybersecurity data presents unique challenges compared to general code data:

- **Quality signals are domain-inverted**: exploit code and vulnerability descriptions are *valuable* training signal, not rejects. A high-CVSS, well-documented exploit is a gold record — the opposite of most content moderation pipelines.
- **Provenance matters more**: sourcing from authoritative databases (NVD/NIST) vs. scraped forums has significant impact on reliability and legal standing. A CVE from NVD is verifiable; one from a random paste-site is not.
- **Ethical and legal sensitivity**: dataset documentation must carefully address intended use. Vulnerability data can be misused, so the Data Card explicitly scopes acceptable downstream applications.

---

## Pipeline Architecture

```
NVD API      →    Deduplication   →    Relevance (35%)      →    JSONL
HuggingFace  →    Schema Norm.    →    Completeness (25%)   →    Data Card
                                       Source Cred. (25%)
                                       Clarity (15%)
```

---

## Quick Start

```bash
git clone https://github.com/whitet-96/llm-training-cyber.git
cd llm-training-cyber
pip install -r requirements.txt
python main.py --stage all --max-records 500
```

To run only ingestion or scoring independently:

```bash
python main.py --stage ingest --max-records 100
python main.py --stage score --output data/scored/custom_output.jsonl
```

---

## Project Structure

```
cyb-dq-curation/
├── main.py                  # Pipeline entrypoint with argparse
├── config.py                # Thresholds, weights, paths, constants
├── ingestion/
│   └── ingest.py            # NVD API + HuggingFace ingestion
├── scoring/
│   └── score.py             # Domain-specific quality scoring
├── docs/
│   └── DATA_CARD.md         # Dataset documentation
├── data/
│   ├── raw/                 # Raw ingested data (gitignored)
│   └── scored/              # Final scored JSONL output (gitignored)
├── tests/
│   └── test_scoring.py      # pytest unit tests for scoring logic
├── .gitignore
├── requirements.txt
└── README.md
```

---

## Scoring Methodology

| Dimension | Weight | Method |
|---|---|---|
| **Relevance** | 35% | CVSS score severity tier + CWE presence + security keyword density in description |
| **Completeness** | 25% | Presence of description, CVSS score, severity, CWE IDs, published date |
| **Source Credibility** | 25% | Source authority (NVD=1.0, HuggingFace=0.6) + CVSS boost |
| **Clarity** | 15% | Description length bands; penalises NVD placeholder text |

**Quality threshold: 0.60** (vs. 0.70 in the companion coding pipeline)

The lower threshold is intentional: cybersecurity descriptions are structurally sparser than well-documented code. NVD descriptions are authoritative but often terse — penalising them for brevity would discard high-signal records. The threshold is calibrated to retain verified, CVSS-scored records while rejecting placeholder entries and empty stubs.

---

## Output Format

```json
{
  "cve_id": "CVE-2023-44487",
  "description": "The HTTP/2 protocol allows...",
  "published": "2023-10-10",
  "cvss_score": 7.5,
  "severity": "HIGH",
  "cwe_ids": ["CWE-400"],
  "source": "nvd",
  "relevance_score": 0.85,
  "completeness_score": 0.90,
  "source_credibility_score": 1.0,
  "clarity_score": 0.70,
  "composite_score": 0.87,
  "training_ready": true,
  "pipeline_version": "v0.1.0",
  "scored_at": "2026-02-23T12:00:00Z"
}
```

---

## Ethical Considerations

- All data is sourced from public, authoritative databases (NVD/NIST — public domain; HuggingFace mirror — MIT licensed)
- No exploit code or PoC payloads are ingested — descriptions only
- Intended for training models to **understand and explain** vulnerabilities, not to facilitate attacks
- See [docs/DATA_CARD.md](docs/DATA_CARD.md) for full intended use statement

---

## Roadmap

- [ ] Add CWE taxonomy enrichment (map CWE IDs to categories)
- [ ] Extend to NVD CPE data for affected product context
- [ ] Add LLM-based scoring for description quality (as in Project 1)
- [ ] GitHub Actions CI for scheduled weekly NVD pulls
- [ ] Merge with Project 1 into unified multi-domain training data platform
