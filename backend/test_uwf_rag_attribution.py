#!/usr/bin/env python3
"""Evaluate the RAG attribution pipeline on UWF-ZeekData22 CSV files.

The UWF data is connection-level Zeek-derived CSV, not RITA output and not
APT-labelled ground truth. This script therefore evaluates attribution as a
proxy task: aggregate repeated connections, map behavior to the feature shape
expected by the current RAG engine, then report retrieval coverage, confidence,
candidate concentration, and technique matches.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from statistics import mean
from typing import Any


BACKEND_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = BACKEND_ROOT.parent
DEFAULT_DATA_DIR = PROJECT_ROOT / "UWF-ZeekData22"
DEFAULT_KB_PATH = BACKEND_ROOT / "chroma_db"
DEFAULT_OUTPUT_DIR = BACKEND_ROOT / "outputs"
C2_TECHNIQUE_PREFIXES = (
    "T1071",
    "T1095",
    "T1102",
    "T1105",
    "T1568",
    "T1571",
    "T1572",
    "T1573",
)

if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))


@dataclass
class Aggregate:
    src_ip: str
    dst_ip: str
    dst_port: str
    protocol: str
    service: str
    label: str
    connection_count: int = 0
    total_duration: float = 0.0
    total_bytes: int = 0
    orig_pkts: int = 0
    resp_pkts: int = 0
    conn_states: Counter[str] = field(default_factory=Counter)
    histories: Counter[str] = field(default_factory=Counter)
    first_ts: float | None = None
    last_ts: float | None = None
    files: set[str] = field(default_factory=set)

    def update(self, row: dict[str, str], file_name: str) -> None:
        duration = safe_float(row.get("duration"))
        ts = safe_float(row.get("ts"))
        orig_bytes = safe_int(row.get("orig_bytes"))
        resp_bytes = safe_int(row.get("resp_bytes"))
        if orig_bytes == 0 and resp_bytes == 0:
            orig_bytes = safe_int(row.get("orig_ip_bytes"))
            resp_bytes = safe_int(row.get("resp_ip_bytes"))

        self.connection_count += 1
        self.total_duration += duration
        self.total_bytes += orig_bytes + resp_bytes
        self.orig_pkts += safe_int(row.get("orig_pkts"))
        self.resp_pkts += safe_int(row.get("resp_pkts"))
        conn_state = (row.get("conn_state") or "").strip()
        history = (row.get("history") or "").strip()
        if conn_state:
            self.conn_states[conn_state] += 1
        if history:
            self.histories[history] += 1
        self.files.add(file_name)

        if ts > 0:
            self.first_ts = ts if self.first_ts is None else min(self.first_ts, ts)
            self.last_ts = ts if self.last_ts is None else max(self.last_ts, ts)

    @property
    def active_window(self) -> float:
        if self.first_ts is None or self.last_ts is None:
            return 0.0
        return max(0.0, self.last_ts - self.first_ts)

    @property
    def avg_interval(self) -> float:
        if self.connection_count <= 1:
            return 0.0
        return self.active_window / (self.connection_count - 1)

    @property
    def dominant_conn_state(self) -> str:
        return self.conn_states.most_common(1)[0][0] if self.conn_states else ""

    @property
    def dominant_history(self) -> str:
        return self.histories.most_common(1)[0][0] if self.histories else ""


def safe_float(value: Any) -> float:
    try:
        if value in (None, "", "-"):
            return 0.0
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def safe_int(value: Any) -> int:
    try:
        if value in (None, "", "-"):
            return 0
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def normalize_label(value: str | None) -> str:
    label = (value or "none").strip()
    return label if label else "none"


def score_c2_likelihood(agg: Aggregate) -> tuple[float, list[str]]:
    """Score whether an aggregate has C2-like communication behavior.

    This is not a ground-truth classifier. It is a gate for the RAG attribution
    stage, so background DNS volume does not dominate APT candidate retrieval.
    """
    score = 0.0
    reasons: list[str] = []
    is_dns = agg.service == "dns" or agg.dst_port == "53"
    is_labeled = agg.label.lower() != "none"
    avg_bytes = agg.total_bytes / agg.connection_count if agg.connection_count else 0.0

    if is_labeled:
        score += 20.0
        reasons.append(f"uwf_label={agg.label}")

    if agg.connection_count >= 1000:
        score += 30.0
        reasons.append("very_high_repeat_count")
    elif agg.connection_count >= 100:
        score += 24.0
        reasons.append("high_repeat_count")
    elif agg.connection_count >= 20:
        score += 16.0
        reasons.append("moderate_repeat_count")
    elif agg.connection_count >= 5:
        score += 8.0
        reasons.append("repeated_connection")

    if agg.active_window >= 28800:
        score += 18.0
        reasons.append("long_active_window")
    elif agg.active_window >= 3600:
        score += 10.0
        reasons.append("multi_hour_active_window")

    if agg.avg_interval and 1.0 <= agg.avg_interval <= 3600.0 and agg.connection_count >= 10:
        score += 18.0
        reasons.append("periodic_interval")

    if is_dns and is_labeled:
        score += 16.0
        reasons.append("labeled_dns_channel")
    elif is_dns and agg.connection_count >= 100:
        score += 10.0
        reasons.append("high_volume_dns")
    elif is_dns:
        score += 4.0
        reasons.append("dns_channel")

    if agg.dst_port not in {"", "unknown", "53", "67", "80", "123", "137", "138", "443", "547"}:
        score += 12.0
        reasons.append(f"non_standard_port={agg.dst_port}")

    if agg.dominant_conn_state in {"S0", "REJ", "RSTO", "RSTR"} and is_labeled:
        score += 8.0
        reasons.append(f"scan_like_state={agg.dominant_conn_state}")

    if agg.connection_count >= 20 and avg_bytes <= 800:
        score += 8.0
        reasons.append("low_byte_repeated_traffic")

    return min(score, 100.0), reasons


def aggregate_uwf_csvs(
    data_dir: Path,
    *,
    max_rows_per_file: int,
    max_files: int,
    row_stride: int,
) -> tuple[dict[tuple[str, str, str, str, str, str], Aggregate], dict[str, Any]]:
    files = sorted(data_dir.glob("*.csv"))
    if max_files > 0:
        files = files[:max_files]
    if not files:
        raise FileNotFoundError(f"No CSV files found in {data_dir}")

    aggregates: dict[tuple[str, str, str, str, str, str], Aggregate] = {}
    scanned_rows = 0
    rows_by_label: Counter[str] = Counter()
    rows_by_file: Counter[str] = Counter()

    for csv_path in files:
        print(f"Reading {csv_path.name} ...")
        with csv_path.open("r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            for row_idx, row in enumerate(reader, 1):
                if max_rows_per_file > 0 and row_idx > max_rows_per_file:
                    break
                if row_stride > 1 and (row_idx - 1) % row_stride != 0:
                    continue

                src_ip = (row.get("src_ip") or "").strip()
                dst_ip = (row.get("dest_ip") or row.get("dst_ip") or "").strip()
                dst_port = str(row.get("dest_port") or row.get("dst_port") or "").strip()
                protocol = (row.get("protocol") or "").strip().lower()
                service = (row.get("service") or "").strip().lower()
                label = normalize_label(row.get("mitre_attack_tactics"))

                if not src_ip or not dst_ip:
                    continue

                key = (src_ip, dst_ip, dst_port, protocol, service, label)
                if key not in aggregates:
                    aggregates[key] = Aggregate(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=dst_port or "unknown",
                        protocol=protocol,
                        service=service,
                        label=label,
                    )
                aggregates[key].update(row, csv_path.name)

                scanned_rows += 1
                rows_by_label[label] += 1
                rows_by_file[csv_path.name] += 1

    stats = {
        "files": [p.name for p in files],
        "scanned_rows": scanned_rows,
        "rows_by_label": dict(rows_by_label),
        "rows_by_file": dict(rows_by_file),
        "aggregate_count": len(aggregates),
    }
    return aggregates, stats


def aggregate_to_feature(agg: Aggregate) -> dict[str, Any]:
    is_dns = agg.service == "dns" or agg.dst_port == "53"
    is_labeled = agg.label.lower() != "none"
    c2_score, c2_reasons = score_c2_likelihood(agg)

    beacon_score = 0.0
    if agg.connection_count >= 1000:
        beacon_score = 95.0
    elif agg.connection_count >= 100:
        beacon_score = 85.0
    elif agg.connection_count >= 20:
        beacon_score = 70.0
    elif agg.connection_count >= 5:
        beacon_score = 55.0

    if is_labeled and c2_score >= 50:
        beacon_score = max(beacon_score, 70.0)

    if agg.avg_interval and 1.0 <= agg.avg_interval <= 3600.0 and agg.connection_count >= 10:
        beacon_score = min(100.0, beacon_score + 10.0)

    c2_over_dns_value = float(agg.connection_count) if is_dns and c2_score >= 50 else 0.0
    long_conn_value = max(agg.total_duration, agg.active_window if agg.connection_count >= 5 else 0.0)

    if is_labeled and (beacon_score >= 90 or c2_over_dns_value >= 800 or long_conn_value >= 28800):
        threat_category = "high"
    elif is_labeled or beacon_score >= 70 or c2_over_dns_value >= 500:
        threat_category = "medium"
    elif agg.label.lower() == "none":
        threat_category = "none"
    else:
        threat_category = "low"

    return {
        "src_ip": agg.src_ip,
        "dst_ip": agg.dst_ip,
        "dst_port": agg.dst_port,
        "protocol": agg.protocol,
        "service": agg.service,
        "beacon_score": beacon_score,
        "long_conn_value": long_conn_value,
        "c2_over_dns_value": c2_over_dns_value,
        "connection_count": agg.connection_count,
        "total_bytes": agg.total_bytes,
        "avg_interval": agg.avg_interval,
        "conn_state": agg.dominant_conn_state,
        "history": agg.dominant_history,
        "c2_score": c2_score,
        "c2_reasons": c2_reasons,
        "threat_category": threat_category,
        "uwf_label": agg.label,
        "source_files": sorted(agg.files),
    }


def select_samples(
    aggregates: dict[tuple[str, str, str, str, str, str], Aggregate],
    *,
    sample_per_label: int,
    max_samples: int,
    include_none: bool,
) -> list[Aggregate]:
    by_label: dict[str, list[Aggregate]] = defaultdict(list)
    for agg in aggregates.values():
        if not include_none and agg.label.lower() == "none":
            continue
        by_label[agg.label].append(agg)

    selected: list[Aggregate] = []
    for label in sorted(by_label):
        items = sorted(
            by_label[label],
            key=lambda a: (a.connection_count, a.active_window, a.total_bytes),
            reverse=True,
        )
        selected.extend(items[:sample_per_label])

    selected.sort(
        key=lambda a: (a.label.lower() == "none", -a.connection_count, a.label)
    )
    if max_samples > 0:
        selected = selected[:max_samples]
    return selected


def filter_c2_samples(
    samples: list[Aggregate],
    *,
    c2_threshold: float,
    include_low_c2: bool,
) -> list[Aggregate]:
    if include_low_c2:
        return samples
    return [agg for agg in samples if score_c2_likelihood(agg)[0] >= c2_threshold]


def has_c2_technique(techniques: list[str]) -> bool:
    return any(
        technique.startswith(C2_TECHNIQUE_PREFIXES)
        for technique in techniques
    )


def run_rag(samples: list[Aggregate], kb_path: Path, top_k: int) -> list[dict[str, Any]]:
    from app.rag_engine import ThreatAttributionEngine

    engine = ThreatAttributionEngine(kb_path=kb_path, top_k=top_k)
    results: list[dict[str, Any]] = []

    for idx, agg in enumerate(samples, 1):
        feature = aggregate_to_feature(agg)
        print(
            f"RAG {idx}/{len(samples)} "
            f"label={agg.label} conn={agg.connection_count} "
            f"{agg.src_ip}->{agg.dst_ip}:{agg.dst_port}"
        )
        attribution = engine.attribute_single_threat(feature)
        candidates = attribution.get("candidates") or []
        primary = attribution.get("primary_candidate") or {}
        top1_score = float(candidates[0]["score"]) if candidates else 0.0
        top2_score = float(candidates[1]["score"]) if len(candidates) > 1 else 0.0

        results.append(
            {
                "label": agg.label,
                "src_ip": agg.src_ip,
                "dst_ip": agg.dst_ip,
                "dst_port": agg.dst_port,
                "protocol": agg.protocol,
                "service": agg.service,
                "conn_state": agg.dominant_conn_state,
                "history": agg.dominant_history,
                "connection_count": agg.connection_count,
                "active_window": agg.active_window,
                "total_duration": agg.total_duration,
                "total_bytes": agg.total_bytes,
                "c2_score": feature["c2_score"],
                "c2_reasons": feature["c2_reasons"],
                "query": attribution.get("query", ""),
                "primary_candidate": primary.get("name", ""),
                "confidence": float(attribution.get("confidence") or 0.0),
                "top1_score": top1_score,
                "top2_score": top2_score,
                "score_gap": top1_score - top2_score,
                "matched_techniques": attribution.get("matched_techniques") or [],
                "c2_technique_hit": has_c2_technique(
                    attribution.get("matched_techniques") or []
                ),
                "candidates": [
                    {
                        "name": c.get("name", ""),
                        "score": c.get("score", 0.0),
                        "techniques": (c.get("metadata") or {}).get("c2_techniques", []),
                    }
                    for c in candidates
                ],
                "feature": feature,
            }
        )

    return results


def summarize(
    parse_stats: dict[str, Any],
    selected_samples: list[Aggregate],
    rag_samples: list[Aggregate],
    results: list[dict[str, Any]],
    *,
    confidence_threshold: float,
    c2_threshold: float,
    include_low_c2: bool,
    no_rag: bool,
) -> dict[str, Any]:
    groups_by_label = Counter(agg.label for agg in selected_samples)
    c2_groups_by_label = Counter(agg.label for agg in rag_samples)
    c2_scores = [score_c2_likelihood(agg)[0] for agg in selected_samples]
    summary: dict[str, Any] = {
        **parse_stats,
        "sampled_count": len(selected_samples),
        "sampled_by_label": dict(groups_by_label),
        "c2_threshold": c2_threshold,
        "include_low_c2": include_low_c2,
        "c2_candidate_count": len(rag_samples),
        "c2_filtered_count": len(selected_samples) - len(rag_samples),
        "c2_candidate_by_label": dict(c2_groups_by_label),
        "mean_sample_c2_score": mean(c2_scores) if c2_scores else 0.0,
        "rag_executed": not no_rag,
    }
    if no_rag:
        return summary

    by_label: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in results:
        by_label[item["label"]].append(item)

    label_metrics: dict[str, Any] = {}
    for label, items in sorted(by_label.items()):
        with_candidates = [i for i in items if i["primary_candidate"]]
        high_conf = [i for i in items if i["confidence"] >= confidence_threshold]
        label_metrics[label] = {
            "samples": len(items),
            "with_candidates": len(with_candidates),
            "coverage": len(with_candidates) / len(items) if items else 0.0,
            "c2_technique_hit_count": sum(1 for i in items if i["c2_technique_hit"]),
            "c2_technique_hit_rate": (
                sum(1 for i in items if i["c2_technique_hit"]) / len(items)
                if items else 0.0
            ),
            "high_confidence_count": len(high_conf),
            "high_confidence_rate": len(high_conf) / len(items) if items else 0.0,
            "mean_confidence": mean([i["confidence"] for i in items]) if items else 0.0,
            "mean_top1_score": mean([i["top1_score"] for i in items]) if items else 0.0,
            "mean_score_gap": mean([i["score_gap"] for i in items]) if items else 0.0,
        }

    candidate_frequency = Counter(
        item["primary_candidate"] for item in results if item["primary_candidate"]
    )
    technique_frequency: Counter[str] = Counter()
    for item in results:
        technique_frequency.update(item.get("matched_techniques") or [])

    c2_hit_count = sum(1 for item in results if item.get("c2_technique_hit"))

    benign_items = [i for i in results if i["label"].lower() == "none"]
    benign_high = [i for i in benign_items if i["confidence"] >= confidence_threshold]

    summary.update(
        {
            "confidence_threshold": confidence_threshold,
            "label_metrics": label_metrics,
            "benign_high_confidence_rate": (
                len(benign_high) / len(benign_items) if benign_items else None
            ),
            "c2_technique_hit_count": c2_hit_count,
            "c2_technique_hit_rate": c2_hit_count / len(results) if results else 0.0,
            "candidate_frequency": dict(candidate_frequency.most_common(20)),
            "technique_frequency": dict(technique_frequency.most_common(30)),
        }
    )
    return summary


def write_outputs(
    output_dir: Path,
    output_prefix: str,
    summary: dict[str, Any],
    results: list[dict[str, Any]],
) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = output_dir / f"{output_prefix}_summary.json"
    details_path = output_dir / f"{output_prefix}_details.csv"

    with summary_path.open("w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    fieldnames = [
        "label",
        "src_ip",
        "dst_ip",
        "dst_port",
        "protocol",
        "service",
        "conn_state",
        "history",
        "connection_count",
        "active_window",
        "total_duration",
        "total_bytes",
        "c2_score",
        "c2_reasons",
        "primary_candidate",
        "confidence",
        "top1_score",
        "top2_score",
        "score_gap",
        "c2_technique_hit",
        "matched_techniques",
        "query",
        "candidates_json",
    ]
    with details_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for item in results:
            row = {name: item.get(name, "") for name in fieldnames}
            row["c2_reasons"] = ";".join(item.get("c2_reasons") or [])
            row["matched_techniques"] = ";".join(item.get("matched_techniques") or [])
            row["candidates_json"] = json.dumps(
                item.get("candidates") or [], ensure_ascii=False
            )
            writer.writerow(row)

    return summary_path, details_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run proxy RAG attribution tests on UWF-ZeekData22 CSV data."
    )
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--kb-path", type=Path, default=DEFAULT_KB_PATH)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--output-prefix", default="uwf_rag")
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--sample-per-label", type=int, default=25)
    parser.add_argument("--max-samples", type=int, default=0)
    parser.add_argument("--max-rows-per-file", type=int, default=0)
    parser.add_argument("--max-files", type=int, default=0)
    parser.add_argument(
        "--row-stride",
        type=int,
        default=1,
        help="Keep one row every N rows while reading each CSV.",
    )
    parser.add_argument("--confidence-threshold", type=float, default=60.0)
    parser.add_argument(
        "--c2-threshold",
        type=float,
        default=50.0,
        help="Only aggregates with c2_score >= this value enter RAG.",
    )
    parser.add_argument(
        "--include-low-c2",
        action="store_true",
        help="Send all selected samples to RAG, even below --c2-threshold.",
    )
    parser.add_argument("--exclude-none", action="store_true")
    parser.add_argument(
        "--no-rag",
        action="store_true",
        help="Only parse, aggregate, sample, and write summary; skip vector search.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    data_dir = args.data_dir.resolve()
    kb_path = args.kb_path.resolve()
    output_dir = args.output_dir.resolve()

    print(f"Data directory: {data_dir}")
    print(f"Knowledge base: {kb_path}")

    aggregates, parse_stats = aggregate_uwf_csvs(
        data_dir,
        max_rows_per_file=args.max_rows_per_file,
        max_files=args.max_files,
        row_stride=max(1, args.row_stride),
    )
    samples = select_samples(
        aggregates,
        sample_per_label=args.sample_per_label,
        max_samples=args.max_samples,
        include_none=not args.exclude_none,
    )
    rag_samples = filter_c2_samples(
        samples,
        c2_threshold=args.c2_threshold,
        include_low_c2=args.include_low_c2,
    )

    print(f"Scanned rows: {parse_stats['scanned_rows']}")
    print(f"Aggregated groups: {parse_stats['aggregate_count']}")
    print(f"Selected samples: {len(samples)}")
    print(f"C2 candidates for RAG: {len(rag_samples)}")

    results: list[dict[str, Any]] = []
    if not args.no_rag:
        results = run_rag(rag_samples, kb_path=kb_path, top_k=args.top_k)

    summary = summarize(
        parse_stats,
        samples,
        rag_samples,
        results,
        confidence_threshold=args.confidence_threshold,
        c2_threshold=args.c2_threshold,
        include_low_c2=args.include_low_c2,
        no_rag=args.no_rag,
    )
    summary_path, details_path = write_outputs(
        output_dir, args.output_prefix, summary, results
    )

    print(f"Summary written to: {summary_path}")
    print(f"Details written to: {details_path}")
    if args.no_rag:
        print("RAG was skipped because --no-rag was set.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
