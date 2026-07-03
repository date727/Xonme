#!/usr/bin/env python3
"""Batch-evaluate RITA on the ARES 2025 PCAP artifacts.

The web API in app.main handles one uploaded PCAP at a time and then continues
into LSTM, RAG, and LLM reporting. This script keeps only the shared PCAP ->
Zeek -> RITA path and turns RITA's high-risk output into binary predictions so
we can compute TP/TN/FP/FN against the ARES folder labels:

    data/pcap/cs      -> malicious / positive
    data/pcap/benign  -> benign / negative
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import io
import json
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from fastapi import HTTPException

from app.data_extractor import ThreatFeatureExtractor
from app.main import make_rita_db_name, run_zeek


BACKEND_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = BACKEND_ROOT.parent
DEFAULT_DATASET = PROJECT_ROOT / "pcap"
DEFAULT_OUTPUT = BACKEND_ROOT / "outputs" / "rita_ares_eval"
PCAP_SUFFIXES = {".pcap", ".pcapng"}


@dataclass
class SampleResult:
    file: str
    label: str
    expected_malicious: bool
    predicted_malicious: bool
    outcome: str
    rita_ok: bool
    threat_count: int
    csv_path: str
    zeek_log_dir: str
    elapsed_seconds: float
    error: str = ""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate RITA TP/TN/FP/FN on ARES 2025 PCAP artifacts."
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=DEFAULT_DATASET,
        help=f"ARES pcap directory. Default: {DEFAULT_DATASET}",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Directory for RITA CSVs and metrics. Default: {DEFAULT_OUTPUT}",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Only evaluate the first N samples after sorting. 0 means all samples.",
    )
    parser.add_argument(
        "--pattern",
        default="*",
        help="Filename glob applied inside benign/ and cs/. Example: '*http*'.",
    )
    parser.add_argument(
        "--skip-existing",
        action="store_true",
        help="Reuse rows from an existing per_sample_results.csv when possible.",
    )
    parser.add_argument(
        "--keep-zeek-logs",
        action="store_true",
        help="Keep generated Zeek log directories after each sample.",
    )
    parser.add_argument(
        "--rita-import-timeout",
        type=int,
        default=600,
        help="Seconds to wait for each RITA import.",
    )
    parser.add_argument(
        "--rita-view-timeout",
        type=int,
        default=120,
        help="Seconds to wait for each RITA view export.",
    )
    return parser.parse_args()


def require_tools() -> None:
    missing = [tool for tool in ("zeek", "rita") if shutil.which(tool) is None]
    if missing:
        joined = ", ".join(missing)
        raise SystemExit(
            f"Missing required command(s): {joined}. "
            "Install Zeek and RITA first, then run this script again."
        )


def discover_samples(dataset: Path, pattern: str) -> list[tuple[Path, bool, str]]:
    samples: list[tuple[Path, bool, str]] = []
    for label, expected_malicious in (("benign", False), ("cs", True)):
        label_dir = dataset / label
        if not label_dir.is_dir():
            raise SystemExit(f"Expected directory not found: {label_dir}")

        for pcap in sorted(label_dir.glob(pattern)):
            if pcap.is_file() and pcap.suffix.lower() in PCAP_SUFFIXES:
                samples.append((pcap, expected_malicious, label))

    return sorted(samples, key=lambda item: (item[2], item[0].name))


def safe_stem(path: Path) -> str:
    keep = []
    for ch in path.stem.lower():
        keep.append(ch if ch.isalnum() else "_")
    return "".join(keep).strip("_") or "sample"


def run_rita(log_dir: Path, db_name: str, import_timeout: int, view_timeout: int) -> str:
    subprocess.run(
        ["rita", "import", f"--database={db_name}", f"--logs={log_dir}"],
        check=True,
        capture_output=True,
        text=True,
        timeout=import_timeout,
    )
    view = subprocess.run(
        ["rita", "view", "--stdout", db_name],
        check=True,
        capture_output=True,
        text=True,
        timeout=view_timeout,
    )
    return view.stdout


def extract_rita_threats(rita_csv_text: str) -> list[dict]:
    """Use the same high-risk extraction logic as the current main.py RAG path."""
    with contextlib.redirect_stdout(io.StringIO()):
        extractor = ThreatFeatureExtractor(rita_csv_text)
        return extractor.extract_all()


def classify_outcome(expected_malicious: bool, predicted_malicious: bool) -> str:
    if expected_malicious and predicted_malicious:
        return "TP"
    if not expected_malicious and not predicted_malicious:
        return "TN"
    if not expected_malicious and predicted_malicious:
        return "FP"
    return "FN"


def load_existing(output_dir: Path) -> dict[str, SampleResult]:
    results_csv = output_dir / "per_sample_results.csv"
    if not results_csv.exists():
        return {}

    existing: dict[str, SampleResult] = {}
    with results_csv.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            existing[row["file"]] = SampleResult(
                file=row["file"],
                label=row["label"],
                expected_malicious=row["expected_malicious"].lower() == "true",
                predicted_malicious=row["predicted_malicious"].lower() == "true",
                outcome=row["outcome"],
                rita_ok=row["rita_ok"].lower() == "true",
                threat_count=int(row["threat_count"] or 0),
                csv_path=row["csv_path"],
                zeek_log_dir=row["zeek_log_dir"],
                elapsed_seconds=float(row["elapsed_seconds"] or 0),
                error=row.get("error", ""),
            )
    return existing


def evaluate_sample(
    pcap: Path,
    expected_malicious: bool,
    label: str,
    output_dir: Path,
    run_id: str,
    import_timeout: int,
    view_timeout: int,
    keep_zeek_logs: bool,
) -> SampleResult:
    started = time.perf_counter()
    sample_id = f"{run_id}_{safe_stem(pcap)}"
    log_dir = output_dir / "zeek_logs" / sample_id
    csv_path = output_dir / "rita_csv" / f"{sample_id}.csv"
    log_dir.mkdir(parents=True, exist_ok=True)
    csv_path.parent.mkdir(parents=True, exist_ok=True)

    db_name = make_rita_db_name(sample_id)
    rita_ok = False
    threat_count = 0
    predicted_malicious = False
    error = ""

    try:
        run_zeek(str(pcap), log_dir)
        if not list(log_dir.glob("*.log")):
            raise RuntimeError("Zeek did not produce any log files")

        rita_csv = run_rita(log_dir, db_name, import_timeout, view_timeout)
        csv_path.write_text(rita_csv, encoding="utf-8")
        rita_ok = True

        threats = extract_rita_threats(rita_csv)
        threat_count = len(threats)
        predicted_malicious = threat_count > 0
    except (HTTPException, subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError) as exc:
        if isinstance(exc, HTTPException):
            error = str(exc.detail)
        elif isinstance(exc, subprocess.CalledProcessError):
            error = (exc.stderr or exc.stdout or str(exc)).strip()
        else:
            error = str(exc)
    finally:
        if not keep_zeek_logs and log_dir.exists():
            shutil.rmtree(log_dir, ignore_errors=True)

    elapsed = time.perf_counter() - started
    outcome = classify_outcome(expected_malicious, predicted_malicious)
    return SampleResult(
        file=str(pcap),
        label=label,
        expected_malicious=expected_malicious,
        predicted_malicious=predicted_malicious,
        outcome=outcome,
        rita_ok=rita_ok,
        threat_count=threat_count,
        csv_path=str(csv_path) if csv_path.exists() else "",
        zeek_log_dir=str(log_dir) if keep_zeek_logs else "",
        elapsed_seconds=round(elapsed, 3),
        error=error,
    )


def compute_metrics(results: list[SampleResult]) -> dict:
    counts = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
    for result in results:
        counts[result.outcome] += 1

    tp = counts["TP"]
    tn = counts["TN"]
    fp = counts["FP"]
    fn = counts["FN"]
    total = tp + tn + fp + fn

    def ratio(num: int, den: int) -> float:
        return round(num / den, 6) if den else 0.0

    return {
        "counts": counts,
        "total": total,
        "accuracy": ratio(tp + tn, total),
        "precision": ratio(tp, tp + fp),
        "recall": ratio(tp, tp + fn),
        "f1": ratio(2 * tp, 2 * tp + fp + fn),
        "false_positive_rate": ratio(fp, fp + tn),
        "false_negative_rate": ratio(fn, fn + tp),
        "rita_failures": sum(1 for r in results if not r.rita_ok),
    }


def write_outputs(output_dir: Path, results: list[SampleResult], metrics: dict) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    results_csv = output_dir / "per_sample_results.csv"
    with results_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(asdict(results[0]).keys()))
        writer.writeheader()
        for result in results:
            writer.writerow(asdict(result))

    metrics_json = output_dir / "metrics.json"
    metrics_json.write_text(
        json.dumps(metrics, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    summary = [
        "# RITA ARES 2025 Evaluation",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| TP | {metrics['counts']['TP']} |",
        f"| TN | {metrics['counts']['TN']} |",
        f"| FP | {metrics['counts']['FP']} |",
        f"| FN | {metrics['counts']['FN']} |",
        f"| Accuracy | {metrics['accuracy']:.4f} |",
        f"| Precision | {metrics['precision']:.4f} |",
        f"| Recall | {metrics['recall']:.4f} |",
        f"| F1 | {metrics['f1']:.4f} |",
        f"| RITA failures | {metrics['rita_failures']} |",
        "",
        f"Per-sample details: `{results_csv}`",
        f"Machine-readable metrics: `{metrics_json}`",
    ]
    (output_dir / "summary.md").write_text("\n".join(summary) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    require_tools()

    dataset = args.dataset.resolve()
    output_dir = args.output_dir.resolve()
    samples = discover_samples(dataset, args.pattern)
    if args.limit > 0:
        samples = samples[: args.limit]
    if not samples:
        raise SystemExit(f"No PCAP samples found in {dataset} with pattern {args.pattern!r}")

    run_id = time.strftime("%Y%m%d_%H%M%S")
    existing = load_existing(output_dir) if args.skip_existing else {}
    results: list[SampleResult] = []

    print(f"Dataset: {dataset}")
    print(f"Samples: {len(samples)}")
    print(f"Output:  {output_dir}")
    print()

    for index, (pcap, expected_malicious, label) in enumerate(samples, start=1):
        if str(pcap) in existing:
            result = existing[str(pcap)]
            print(f"[{index}/{len(samples)}] reuse {pcap.name}: {result.outcome}")
        else:
            print(f"[{index}/{len(samples)}] evaluate {pcap.name} ({label})")
            result = evaluate_sample(
                pcap=pcap,
                expected_malicious=expected_malicious,
                label=label,
                output_dir=output_dir,
                run_id=run_id,
                import_timeout=args.rita_import_timeout,
                view_timeout=args.rita_view_timeout,
                keep_zeek_logs=args.keep_zeek_logs,
            )
            status = result.outcome if result.rita_ok else f"{result.outcome} / RITA_ERROR"
            print(f"    -> {status}, threats={result.threat_count}, elapsed={result.elapsed_seconds}s")
            if result.error:
                print(f"       error: {result.error[:240]}")
        results.append(result)

    metrics = compute_metrics(results)
    write_outputs(output_dir, results, metrics)

    print()
    print("Confusion matrix")
    print(f"  TP={metrics['counts']['TP']}  FP={metrics['counts']['FP']}")
    print(f"  FN={metrics['counts']['FN']}  TN={metrics['counts']['TN']}")
    print(
        "Metrics: "
        f"accuracy={metrics['accuracy']:.4f}, "
        f"precision={metrics['precision']:.4f}, "
        f"recall={metrics['recall']:.4f}, "
        f"f1={metrics['f1']:.4f}"
    )
    print(f"Wrote results to {output_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
