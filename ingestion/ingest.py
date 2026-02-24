import json
import time
import os
import requests
from datetime import datetime

from config import (
    NVD_API_BASE,
    NVD_RESULTS_PER_PAGE,
    NVD_MAX_RECORDS,
    HF_DATASET,
    RAW_PATH,
)


def _extract_cvss(metrics: dict):
    """Extract CVSS base score and severity, preferring V3.1 over V3.0."""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            return data.get("baseScore"), data.get("baseSeverity")
    return None, None


def _extract_description(descriptions: list) -> str:
    """Return the first English description."""
    for d in descriptions:
        if d.get("lang", "").lower() in ("en", "en-us"):
            return d.get("value", "")
    return ""


def _extract_cwe_ids(weaknesses: list) -> list:
    """Extract CWE ID strings from weaknesses array."""
    cwe_ids = []
    for weakness in weaknesses:
        for desc in weakness.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                cwe_ids.append(val)
    return cwe_ids


def fetch_nvd_cves(max_records: int = NVD_MAX_RECORDS) -> list:
    """Fetch CVE records from the NVD CVE 2.0 REST API.

    Paginates through results with a 6-second sleep between requests to
    respect NVD rate limits. Retries up to 3 times with exponential backoff
    on errors.
    """
    records = []
    start_index = 0
    results_per_page = min(NVD_RESULTS_PER_PAGE, max_records)

    print(f"[NVD] Starting ingestion (max_records={max_records}) ...")

    while len(records) < max_records:
        fetch_count = min(results_per_page, max_records - len(records))
        params = {
            "startIndex": start_index,
            "resultsPerPage": fetch_count,
        }

        response = None
        for attempt in range(3):
            try:
                response = requests.get(NVD_API_BASE, params=params, timeout=30)
                response.raise_for_status()
                break
            except requests.RequestException as exc:
                wait = 2 ** attempt * 6
                print(f"[NVD] Request error (attempt {attempt + 1}/3): {exc}. Retrying in {wait}s ...")
                time.sleep(wait)
        else:
            print("[NVD] All retries exhausted. Stopping ingestion.")
            break

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            break

        for item in vulnerabilities:
            cve = item.get("cve", {})
            cvss_score, severity = _extract_cvss(cve.get("metrics", {}))
            record = {
                "cve_id": cve.get("id", ""),
                "description": _extract_description(cve.get("descriptions", [])),
                "published": cve.get("published", ""),
                "last_modified": cve.get("lastModified", ""),
                "cvss_score": cvss_score,
                "severity": severity,
                "cwe_ids": _extract_cwe_ids(cve.get("weaknesses", [])),
                "source": "nvd",
            }
            records.append(record)

        fetched = len(records)
        if fetched % 100 == 0 or fetched >= max_records:
            print(f"[NVD] Fetched {fetched} records so far ...")

        total_results = data.get("totalResults", 0)
        start_index += len(vulnerabilities)
        if start_index >= total_results or len(vulnerabilities) < fetch_count:
            break

        # NVD rate limit: 6 seconds between paginated requests (no API key)
        print(f"[NVD] Sleeping 6s to respect rate limit ...")
        time.sleep(6)

    print(f"[NVD] Ingestion complete. {len(records)} records fetched.")
    return records


def fetch_hf_cves(max_records: int = 200, existing_ids: set = None) -> list:
    """Load CVE records from the HuggingFace stasvinokur/cve-and-cwe-dataset-1999-2025 dataset.

    Schema: CVE-ID, DESCRIPTION, CVSS-V4, CVSS-V3, CVSS-V2, SEVERITY, CWE-ID
    License: CC0-1.0 (public domain). 280k records covering 1999-2025.
    Deduplicates against existing_ids (NVD takes precedence).
    """
    if existing_ids is None:
        existing_ids = set()

    try:
        from datasets import load_dataset
    except ImportError:
        print("[HF] 'datasets' package not installed. Skipping HuggingFace ingestion.")
        return []

    print(f"[HF] Loading dataset '{HF_DATASET}' (streaming) ...")
    records = []

    try:
        dataset = load_dataset(HF_DATASET, split="train", streaming=True)
        for raw in dataset:
            if len(records) >= max_records:
                break

            cve_id = raw.get("CVE-ID", "")
            if not cve_id or cve_id in existing_ids:
                continue

            # Prefer CVSS-V3, fall back to V4 then V2
            cvss_score = raw.get("CVSS-V3") or raw.get("CVSS-V4") or raw.get("CVSS-V2")
            if cvss_score is not None:
                try:
                    cvss_score = float(cvss_score)
                except (ValueError, TypeError):
                    cvss_score = None

            severity = raw.get("SEVERITY") or None
            if severity:
                severity = str(severity).upper()

            cwe_raw = raw.get("CWE-ID", "")
            # Exclude NVD catch-all placeholders; wrap single value in list
            if cwe_raw and cwe_raw not in ("NVD-CWE-Other", "NVD-CWE-noinfo"):
                cwe_ids = [cwe_raw]
            else:
                cwe_ids = []

            # Derive approximate published year from CVE-ID (e.g. CVE-2023-12345 → "2023")
            published = ""
            if cve_id.startswith("CVE-"):
                parts = cve_id.split("-")
                if len(parts) >= 2 and parts[1].isdigit():
                    published = parts[1]

            record = {
                "cve_id": cve_id,
                "description": str(raw.get("DESCRIPTION", "")),
                "published": published,
                "last_modified": "",
                "cvss_score": cvss_score,
                "severity": severity,
                "cwe_ids": cwe_ids,
                "source": "huggingface",
            }
            records.append(record)

        print(f"[HF] Loaded {len(records)} records (after dedup against NVD).")
    except Exception as exc:
        print(f"[HF] Failed to load dataset: {exc}")

    return records


def ingest(max_records: int = NVD_MAX_RECORDS) -> list:
    """Run full ingestion: NVD + HuggingFace, deduplicate, save raw JSONL."""
    nvd_records = fetch_nvd_cves(max_records=max_records)
    nvd_ids = {r["cve_id"] for r in nvd_records}

    hf_records = fetch_hf_cves(max_records=200, existing_ids=nvd_ids)

    all_records = nvd_records + hf_records

    # Final dedup by cve_id (NVD first, so duplicates are already excluded above)
    seen = set()
    deduped = []
    for record in all_records:
        cid = record["cve_id"]
        if cid and cid not in seen:
            seen.add(cid)
            deduped.append(record)

    os.makedirs(os.path.dirname(RAW_PATH), exist_ok=True)
    with open(RAW_PATH, "w", encoding="utf-8") as f:
        for record in deduped:
            f.write(json.dumps(record) + "\n")

    nvd_count = sum(1 for r in deduped if r["source"] == "nvd")
    hf_count = sum(1 for r in deduped if r["source"] == "huggingface")
    print(
        f"\n[Ingest] Summary: {len(deduped)} total records "
        f"(NVD={nvd_count}, HuggingFace={hf_count})"
    )
    print(f"[Ingest] Raw data saved to: {RAW_PATH}")

    return deduped
