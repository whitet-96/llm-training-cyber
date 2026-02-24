"""Cybersecurity Dataset Curation Pipeline — entrypoint."""

import argparse
import json
import os
import sys

# Allow imports from project root when run as a script
sys.path.insert(0, os.path.dirname(__file__))

from config import SCORED_PATH, RAW_PATH
from ingestion.ingest import ingest
from scoring.score import score_dataset


def load_jsonl(path: str) -> list:
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def save_jsonl(records: list, path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record) + "\n")


def print_summary(scored: list, output_path: str) -> None:
    total = len(scored)
    passing = [r for r in scored if r.get("training_ready")]
    pass_count = len(passing)
    pass_pct = (pass_count / total * 100) if total else 0.0

    def avg(field):
        vals = [r[field] for r in scored if field in r]
        return sum(vals) / len(vals) if vals else 0.0

    print("\n" + "=" * 60)
    print("  SCORE STAGE SUMMARY")
    print("=" * 60)
    print(f"  Total records scored  : {total}")
    print(f"  Training-ready records: {pass_count} ({pass_pct:.1f}%)")
    print(f"  Avg relevance score   : {avg('relevance_score'):.4f}")
    print(f"  Avg completeness score: {avg('completeness_score'):.4f}")
    print(f"  Avg credibility score : {avg('source_credibility_score'):.4f}")
    print(f"  Avg clarity score     : {avg('clarity_score'):.4f}")
    print(f"  Avg composite score   : {avg('composite_score'):.4f}")
    print(f"  Output file           : {output_path}")
    print("=" * 60 + "\n")


def print_filter_summary(summary: dict) -> None:
    print("\n" + "=" * 60)
    print("  FILTER STAGE SUMMARY")
    print("=" * 60)
    print(f"  Total input           : {summary['total_input']}")
    print(f"  Hard excluded         : {summary['hard_excluded']}")
    print(f"  Training ready (raw)  : {summary['training_ready_raw']}")
    print(f"  Review queue          : {summary['review_queue']}")
    print(f"  Tier rejected         : {summary['tier_rejected']}")
    print(f"  After stratified sample: {summary['sampled']}")
    print(f"  Training final (clean): {summary['training_final']}")
    print(f"  Flagged contamination : {summary['flagged_contamination']}")
    print("=" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Cybersecurity Dataset Curation Pipeline"
    )
    parser.add_argument(
        "--stage",
        choices=["ingest", "score", "filter", "report", "all"],
        default="all",
        help="Pipeline stage to run (default: all)",
    )
    parser.add_argument(
        "--max-records",
        type=int,
        default=500,
        dest="max_records",
        help="Maximum number of CVE records to ingest (default: 500)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=SCORED_PATH,
        help=f"Output path for scored JSONL (default: {SCORED_PATH})",
    )
    args = parser.parse_args()

    if args.stage in ("ingest", "all"):
        print(f"[Pipeline] Stage: ingest (max_records={args.max_records})")
        ingest(max_records=args.max_records)
        print()

    if args.stage in ("score", "all"):
        print("[Pipeline] Stage: score")
        if not os.path.exists(RAW_PATH):
            print(f"[Pipeline] ERROR: Raw data not found at '{RAW_PATH}'. Run --stage ingest first.")
            sys.exit(1)

        raw_records = load_jsonl(RAW_PATH)
        print(f"[Pipeline] Loaded {len(raw_records)} raw records from {RAW_PATH}")

        scored = score_dataset(raw_records)
        save_jsonl(scored, args.output)
        print(f"[Pipeline] Scored JSONL saved to: {args.output}")

        print_summary(scored, args.output)

    if args.stage in ("filter", "all"):
        print("[Pipeline] Stage: filter")
        if not os.path.exists(args.output):
            print(f"[Pipeline] ERROR: Scored data not found at '{args.output}'. Run --stage score first.")
            sys.exit(1)

        from filtering.filter import run_filter_pipeline
        filter_summary = run_filter_pipeline(scored_path=args.output)
        print_filter_summary(filter_summary)

    if args.stage in ("report", "all"):
        print("[Pipeline] Stage: report")
        if not os.path.exists(args.output):
            print(f"[Pipeline] ERROR: Scored data not found at '{args.output}'. Run --stage score first.")
            sys.exit(1)

        from reporting.report import generate_report
        generate_report(scored_path=args.output)
        print()


if __name__ == "__main__":
    main()
