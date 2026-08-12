#!/usr/bin/env python3
"""Run RAG attribution over merged RITA/LSTM threat features."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from statistics import mean
from typing import Any


BACKEND_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = BACKEND_ROOT.parent
DEFAULT_INPUT = BACKEND_ROOT / "outputs" / "ares_malicious_dual_detection" / "merged_threat_features_for_rag.csv"
DEFAULT_OUTPUT = BACKEND_ROOT / "outputs" / "ares_malicious_rag"
DEFAULT_KB = BACKEND_ROOT / "chroma_db"

if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Batch RAG attribution for merged detector features.")
    parser.add_argument("--input-csv", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--kb-path", type=Path, default=DEFAULT_KB)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--min-top1-score", type=float, default=0.60)
    parser.add_argument("--min-score-gap", type=float, default=0.03)
    return parser.parse_args()


def as_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def load_features(path: Path) -> list[dict[str, Any]]:
    features: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            feature = json.loads(row["feature_json"])
            # CSV fields are retained as an authoritative fallback for old batch output.
            feature.setdefault("protocol", row.get("protocol", ""))
            feature.setdefault("source_file", row.get("source_file", ""))
            feature.setdefault("dataset_label", row.get("dataset_label", ""))
            features.append(feature)
    return features


def decide(candidates: list[dict], min_top1_score: float, min_score_gap: float) -> tuple[bool, str]:
    if not candidates:
        return False, "no_candidate"
    top1 = as_float(candidates[0].get("score"))
    top2 = as_float(candidates[1].get("score")) if len(candidates) > 1 else 0.0
    if top1 < min_top1_score:
        return False, "insufficient_top1_similarity"
    if len(candidates) > 1 and top1 - top2 < min_score_gap:
        return False, "ambiguous_top1_top2_gap"
    return True, "accepted"


def main() -> int:
    args = parse_args()
    input_csv = args.input_csv.resolve()
    if not input_csv.exists():
        raise SystemExit(f"Merged feature CSV not found: {input_csv}")

    from app.rag_engine import ThreatAttributionEngine

    features = load_features(input_csv)
    engine = ThreatAttributionEngine(kb_path=args.kb_path.resolve(), top_k=args.top_k)
    details: list[dict[str, Any]] = []
    for index, feature in enumerate(features, start=1):
        source = feature.get("source_file", "")
        sources = ";".join(feature.get("detection_sources") or [])
        print(f"[{index}/{len(features)}] {source} ({sources})")
        result = engine.attribute_single_threat(feature)
        candidates = result.get("candidates") or []
        accepted, decision = decide(candidates, args.min_top1_score, args.min_score_gap)
        top1 = as_float(candidates[0].get("score")) if candidates else 0.0
        top2 = as_float(candidates[1].get("score")) if len(candidates) > 1 else 0.0
        primary = (candidates[0].get("name") or "") if accepted and candidates else ""
        details.append({
            "source_file": source,
            "dataset_label": feature.get("dataset_label", ""),
            "detection_sources": sources,
            "src_ip": feature.get("src_ip", ""),
            "dst_ip": feature.get("dst_ip", ""),
            "dst_port": feature.get("dst_port", ""),
            "protocol": feature.get("protocol", ""),
            "beacon_score": feature.get("beacon_score", 0.0),
            "lstm_confidence": feature.get("lstm_confidence", 0.0),
            "retrieved_top1": candidates[0].get("name", "") if candidates else "",
            "primary_candidate": primary,
            "attribution_accepted": accepted,
            "attribution_decision": decision,
            "top1_score": top1,
            "top2_score": top2,
            "score_gap": top1 - top2,
            "confidence": as_float(result.get("confidence")),
            "matched_techniques": ";".join(result.get("matched_techniques") or []),
            "query": result.get("query", ""),
            "candidates_json": json.dumps(candidates, ensure_ascii=False),
        })

    args.output_dir.mkdir(parents=True, exist_ok=True)
    fields = list(details[0]) if details else []
    details_path = args.output_dir / "rag_attribution_details.csv"
    with details_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(details)

    by_source = Counter(row["detection_sources"] for row in details)
    decisions = Counter(row["attribution_decision"] for row in details)
    candidates = Counter(row["primary_candidate"] for row in details if row["primary_candidate"])
    techniques = Counter()
    for row in details:
        techniques.update(filter(None, row["matched_techniques"].split(";")))
    summary = {
        "input_feature_count": len(features),
        "top_k": args.top_k,
        "min_top1_score": args.min_top1_score,
        "min_score_gap": args.min_score_gap,
        "retrieval_coverage": sum(bool(row["retrieved_top1"]) for row in details) / len(details) if details else 0.0,
        "accepted_attribution_count": sum(bool(row["attribution_accepted"]) for row in details),
        "accepted_attribution_rate": sum(bool(row["attribution_accepted"]) for row in details) / len(details) if details else 0.0,
        "mean_top1_score": mean([row["top1_score"] for row in details]) if details else 0.0,
        "mean_score_gap": mean([row["score_gap"] for row in details]) if details else 0.0,
        "detection_source_counts": dict(by_source),
        "attribution_decision_frequency": dict(decisions),
        "accepted_candidate_frequency": dict(candidates),
        "technique_frequency": dict(techniques.most_common(30)),
        "details_path": str(details_path),
    }
    summary_path = args.output_dir / "rag_attribution_summary.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote: {summary_path}")
    print(f"Wrote: {details_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
