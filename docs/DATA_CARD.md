# Data Card — Cybersecurity CVE Training Dataset

| Field | Value |
|---|---|
| **Version** | 1.0 |
| **Created** | 2026-02-23 |
| **Pipeline Version** | v0.1.0 |
| **Maintainer** | whitet-96 |

---

## Dataset Summary

This dataset contains cybersecurity Common Vulnerabilities and Exposures (CVE) records sourced from the National Vulnerability Database (NVD) and a HuggingFace mirror dataset. Each record has been scored across four quality dimensions (relevance, completeness, source credibility, clarity) and filtered to a composite quality threshold for training readiness.

The dataset is intended to support training and fine-tuning of language models in the cybersecurity domain — specifically models that explain vulnerabilities, classify severity, or assist with security education.

---

## Source Datasets

| Source | Dataset | License | Authority |
|---|---|---|---|
| NVD CVE 2.0 API | `https://services.nvd.nist.gov/rest/json/cves/2.0` | Public Domain (US Government) | Authoritative — NIST/US Federal |
| HuggingFace | `mrm8488/cve-hf` | MIT | Secondary aggregator — mirrors NVD |

NVD records take precedence in deduplication. When a CVE appears in both sources, the NVD version is retained.

---

## Pipeline Overview

1. **Ingest**: Fetch CVE records from NVD via paginated REST API (6s delay between pages to respect rate limits); load HuggingFace mirror dataset in streaming mode.
2. **Deduplicate**: Merge both sources, deduplicating on `cve_id`. NVD records take precedence.
3. **Hard Filters**: Records with missing descriptions or descriptions outside 50–5,000 character bounds receive `composite_score = 0.0` and `training_ready = False`.
4. **Score**: Apply four-dimension quality scoring with weighted composite calculation.
5. **Output**: Save enriched records as JSONL to `data/scored/cves_scored.jsonl`. Records with `composite_score >= 0.60` are flagged `training_ready = True`.

---

## Quality Scoring Methodology

| Dimension | Weight | Scoring Method |
|---|---|---|
| **Relevance** | 35% | CVSS score tier (HIGH/CRITICAL=+0.4, MEDIUM=+0.2) + CWE presence (+0.3) + security keyword density in description (+0.1 per keyword, capped at +0.3) |
| **Completeness** | 25% | Description passes length bounds (+0.4) + CVSS score present (+0.2) + severity present (+0.1) + CWE IDs present (+0.2) + published date present (+0.1) |
| **Source Credibility** | 25% | NVD=1.0, HuggingFace=0.6, other=0.3; +0.1 boost if CVSS score present (indicates formal assessment) |
| **Clarity** | 15% | Description length: 100–1000 chars=1.0, 50–99 or 1001–2000=0.7, 2001–5000=0.4, out of bounds=0.0; −0.2 penalty for NVD placeholder text |

**Quality threshold**: `composite_score >= 0.60` → `training_ready = True`

---

## Weight Rationale

| Dimension | Weight | Rationale |
|---|---|---|
| **Relevance (35%)** | Highest | The primary purpose of this dataset is security-domain training. A record without clear security signals (CVSS, CWE, keywords) has low utility regardless of other quality factors. |
| **Completeness (25%)** | Second | Structured metadata (CVSS, CWE, dates) enables downstream tasks like severity classification and vulnerability triage. Missing fields reduce training signal richness. |
| **Source Credibility (25%)** | Equal second | Provenance is critical in security data. NVD is a US government authoritative source; secondary aggregators may lag or introduce errors. This weight reflects the real-world importance of sourcing. |
| **Clarity (15%)** | Lowest | NVD descriptions are authoritative but often terse by design. Penalising too heavily for brevity would discard high-signal records. Clarity catches genuine quality issues (placeholders, extreme length) without penalising well-structured short descriptions. |

---

## Dataset Statistics

> Run the pipeline to populate these values.

| Metric | Value |
|---|---|
| Total records ingested | [RUN_PIPELINE] |
| NVD records | [RUN_PIPELINE] |
| HuggingFace records | [RUN_PIPELINE] |
| Records passing hard filters | [RUN_PIPELINE] |
| Records with `training_ready=True` | [RUN_PIPELINE] |
| Training-ready pass rate | [RUN_PIPELINE]% |
| Average composite score | [RUN_PIPELINE] |
| Average relevance score | [RUN_PIPELINE] |
| Average completeness score | [RUN_PIPELINE] |
| Average source credibility score | [RUN_PIPELINE] |
| Average clarity score | [RUN_PIPELINE] |
| Records with CVSS score | [RUN_PIPELINE] |
| Records with CWE IDs | [RUN_PIPELINE] |

---

## Known Limitations

- **NVD descriptions only**: No exploit code, proof-of-concept (PoC) payloads, or patch diffs are ingested. The dataset captures *what* a vulnerability is, not *how* to exploit it.
- **English descriptions only**: NVD stores descriptions in multiple languages; this pipeline extracts English only. Non-English records are excluded.
- **CVSS scores absent on older CVEs**: CVEs published before approximately 2005 may lack CVSS scores. This reduces their relevance and completeness scores even if descriptions are high quality.
- **Rate limiting**: NVD enforces a rate limit of ~5 requests/30 seconds without an API key. The 6-second inter-page sleep means full NVD ingestion of 500 records takes approximately 3–5 minutes, and a full crawl of all NVD records would take significantly longer.
- **HuggingFace dataset lag**: The `mrm8488/cve-hf` mirror may lag NVD by days to weeks. For the most current CVEs, rely on the NVD source.
- **RESERVED/REJECT placeholders**: NVD contains CVE stubs with placeholder text. These are caught by the clarity scorer but will still appear in raw output with `training_ready=False`.

---

## Intended Use

### Suitable for

- Training or fine-tuning language models to **explain** cybersecurity vulnerabilities in plain language
- Security education tools that need structured CVE context
- NLP research on technical security text
- Building retrieval-augmented generation (RAG) systems for vulnerability Q&A
- Understanding CVE structure and CVSS/CWE taxonomy

### Not suitable for

- **Generating exploit code or attack payloads** — this dataset contains descriptions only, and training on it for offensive purposes is explicitly outside scope
- **Attack facilitation or offensive security without authorisation** — any downstream model trained on this data should implement appropriate guardrails
- Any use case that could enable harm to systems, networks, or individuals

---

## Reproducing the Dataset

```bash
git clone https://github.com/whitet-96/llm-training-cyber.git
cd llm-training-cyber
pip install -r requirements.txt
python main.py --stage all --max-records 500
```

Output will be written to `data/scored/cves_scored.jsonl`.

For a smaller test run:

```bash
python main.py --stage all --max-records 100
```
