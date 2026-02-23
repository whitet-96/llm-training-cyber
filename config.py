# Scoring weights (must sum to 1.0)
WEIGHT_RELEVANCE = 0.35
WEIGHT_COMPLETENESS = 0.25
WEIGHT_SOURCE_CREDIBILITY = 0.25
WEIGHT_CLARITY = 0.15

# Quality threshold
QUALITY_THRESHOLD = 0.60

# Hard filters
MIN_DESCRIPTION_LENGTH = 50    # characters
MAX_DESCRIPTION_LENGTH = 5000  # characters

# NVD API
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RESULTS_PER_PAGE = 100
NVD_MAX_RECORDS = 500

# HuggingFace dataset
HF_DATASET = "mrm8488/cve-hf"  # fallback if primary unavailable

# Output paths
RAW_PATH = "data/raw/cves_raw.jsonl"
SCORED_PATH = "data/scored/cves_scored.jsonl"
PIPELINE_VERSION = "v0.1.0"
