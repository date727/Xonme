#!/usr/bin/env python3
"""Benchmark the full main.py PCAP analysis pipeline.

This script follows the same processing path as app.main `/analyze` and records
both end-to-end time and per-stage wall-clock time:

    PCAP upload -> Zeek -> RITA -> LSTM -> RAG -> AI report -> response
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
import time
import shutil
import subprocess
import traceback
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path

from fastapi import HTTPException

from app import main as main_app


BACKEND_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = BACKEND_ROOT.parent
DEFAULT_DATASET = PROJECT_ROOT / "ares2025-artifacts-main" / "data" / "pcap"
DEFAULT_OUTPUT = BACKEND_ROOT / "outputs" / "main_pipeline_benchmark"
PCAP_SUFFIXES = {".pcap", ".pcapng"}


@dataclass
class BenchmarkResult:
    file: str
    label: str
    status_code: int
    ok: bool
    elapsed_seconds: float
    upload_seconds: float = 0.0
    zeek_seconds: float = 0.0
    rita_import_seconds: float = 0.0
    rita_view_seconds: float = 0.0
    rita_total_seconds: float = 0.0
    output_write_seconds: float = 0.0
    lstm_seconds: float = 0.0
    rag_seconds: float = 0.0
    ai_seconds: float = 0.0
    run_name: str = ""
    csv_path: str = ""
    rita_ok: bool = False
    lstm_flagged: int = 0
    rita_threats: int = 0
    merged_threats: int = 0
    rag_candidates: int = 0
    analysis_chars: int = 0
    error: str = ""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Benchmark app.main /analyze from PCAP input to AI report output."
    )
    parser.add_argument(
        "--file",
        type=Path,
        action="append",
        default=[],
        help="PCAP file to benchmark. Can be passed multiple times.",
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=DEFAULT_DATASET,
        help=f"ARES pcap directory used when --file is not provided. Default: {DEFAULT_DATASET}",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Directory for benchmark outputs. Default: {DEFAULT_OUTPUT}",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Only benchmark the first N discovered dataset samples. 0 means all samples.",
    )
    parser.add_argument(
        "--pattern",
        default="*",
        help="Filename glob applied inside benign/ and cs/ when using --dataset.",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=1,
        help="Number of times to run each PCAP. Default: 1.",
    )
    return parser.parse_args()


def discover_dataset_samples(dataset: Path, pattern: str) -> list[tuple[Path, str]]:
    samples: list[tuple[Path, str]] = []
    for label in ("benign", "cs"):
        label_dir = dataset / label
        if not label_dir.is_dir():
            raise SystemExit(f"Expected directory not found: {label_dir}")

        for pcap in sorted(label_dir.glob(pattern)):
            if pcap.is_file() and pcap.suffix.lower() in PCAP_SUFFIXES:
                samples.append((pcap, label))

    return sorted(samples, key=lambda item: (item[1], item[0].name))


def resolve_samples(args: argparse.Namespace) -> list[tuple[Path, str]]:
    if args.file:
        samples = []
        for pcap in args.file:
            path = pcap.resolve()
            if not path.is_file():
                raise SystemExit(f"PCAP file not found: {path}")
            if path.suffix.lower() not in PCAP_SUFFIXES:
                raise SystemExit(f"Unsupported PCAP extension: {path}")
            samples.append((path, "manual"))
        return samples

    samples = discover_dataset_samples(args.dataset.resolve(), args.pattern)
    if args.limit > 0:
        samples = samples[: args.limit]
    if not samples:
        raise SystemExit(
            f"No PCAP samples found in {args.dataset} with pattern {args.pattern!r}"
        )
    return samples


def elapsed_since(started: float) -> float:
    return round(time.perf_counter() - started, 3)


def analyze_once(pcap: Path, label: str) -> BenchmarkResult:
    total_started = time.perf_counter()
    name = uuid.uuid4().hex
    rita_db_name = main_app.make_rita_db_name(name)
    upload_path = main_app.UPLOADS_DIR / f"{name}.pcap"
    output_dir = main_app.OUTPUTS_DIR / name

    result = BenchmarkResult(
        file=str(pcap),
        label=label,
        status_code=0,
        ok=False,
        elapsed_seconds=0.0,
        run_name=name,
    )

    try:
        main_app.ensure_dirs()
        output_dir.mkdir(parents=True, exist_ok=True)

        stage_started = time.perf_counter()
        with pcap.open("rb") as f:
            with upload_path.open("wb") as out:
                shutil.copyfileobj(f, out)
        result.upload_seconds = elapsed_since(stage_started)

        stage_started = time.perf_counter()
        main_app.run_zeek(str(upload_path), output_dir)
        result.zeek_seconds = elapsed_since(stage_started)

        zeek_logs = list(output_dir.glob("*.log"))
        if not zeek_logs:
            raise HTTPException(status_code=500, detail="Zeek did not produce any log files")

        rita_started = time.perf_counter()
        rita_ok = False
        csv_text = ""

        stage_started = time.perf_counter()
        try:
            main_app.run_command(
                ["rita", "import", f"--database={rita_db_name}", f"--logs={output_dir}"],
                timeout=600,
            )
        except HTTPException as exc:
            result.error = f"RITA import failed: {exc.detail}"
        else:
            result.rita_import_seconds = elapsed_since(stage_started)

            stage_started = time.perf_counter()
            try:
                view_result = subprocess.run(
                    ["rita", "view", "--stdout", rita_db_name],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                csv_text = view_result.stdout
                rita_ok = True
            except subprocess.TimeoutExpired:
                result.error = "RITA view timed out after 120s"
            except subprocess.CalledProcessError as exc:
                result.error = f"RITA view failed: {(exc.stderr or exc.stdout or '').strip()}"
            finally:
                result.rita_view_seconds = elapsed_since(stage_started)

        if not result.rita_import_seconds:
            result.rita_import_seconds = elapsed_since(stage_started)
        result.rita_total_seconds = elapsed_since(rita_started)
        result.rita_ok = rita_ok

        if not rita_ok:
            csv_text = main_app._collect_zeek_logs(output_dir)

        stage_started = time.perf_counter()
        csv_path = main_app.OUTPUTS_DIR / f"{name}.csv"
        csv_path.write_text(csv_text, encoding="utf-8")
        result.csv_path = str(csv_path)
        result.output_write_seconds = elapsed_since(stage_started)

        stage_started = time.perf_counter()
        lstm_results = None
        if main_app._LSTM_AVAILABLE:
            try:
                from app.zeek_to_lstm_converter import export_lstm_features_from_zeek

                lstm_csv_text = export_lstm_features_from_zeek(output_dir)
                if lstm_csv_text:
                    lstm_results = main_app.predict_beacons(lstm_csv_text)
                    result.lstm_flagged = int(lstm_results.get("total_flagged", 0))
            except Exception as exc:
                result.error = append_error(result.error, f"LSTM failed: {exc}")
                traceback.print_exc()
        result.lstm_seconds = elapsed_since(stage_started)

        stage_started = time.perf_counter()
        rag_context = None
        if main_app._RAG_AVAILABLE:
            try:
                if (lstm_results and lstm_results.get("total_flagged", 0) > 0) or rita_ok:
                    from app.threat_feature_merger import merge_threat_features

                    rita_features = []
                    if rita_ok:
                        extractor = main_app.ThreatFeatureExtractor(csv_text)
                        rita_features = extractor.extract_all()
                        result.rita_threats = len(rita_features)

                    merged_features = merge_threat_features(rita_features, lstm_results)
                    result.merged_threats = len(merged_features)

                    if merged_features:
                        rag_engine = main_app.ThreatAttributionEngine(
                            kb_path=main_app.APP_ROOT / "chroma_db"
                        )
                        rag_result = rag_engine.attribute_single_threat(merged_features[0])
                        result.rag_candidates = len(rag_result.get("candidates", []))
                        if rag_result.get("candidates"):
                            rag_context = rag_engine.generate_attribution_report(rag_result)
            except Exception as exc:
                result.error = append_error(result.error, f"RAG failed: {exc}")
                traceback.print_exc()
        result.rag_seconds = elapsed_since(stage_started)

        stage_started = time.perf_counter()
        analysis_markdown = main_app.generate_ai_analysis(
            csv_text,
            lstm_results=lstm_results,
            rita_ok=rita_ok,
            rag_context=rag_context,
        )
        result.ai_seconds = elapsed_since(stage_started)

        result.analysis_chars = len(analysis_markdown)
        result.status_code = 200
        result.ok = True
    except Exception as exc:
        status_code = exc.status_code if isinstance(exc, HTTPException) else 500
        detail = exc.detail if isinstance(exc, HTTPException) else str(exc)
        result.status_code = status_code
        result.error = append_error(result.error, str(detail))
    finally:
        result.elapsed_seconds = elapsed_since(total_started)

    return result


def append_error(existing: str, message: str) -> str:
    if not existing:
        return message[:1000]
    return f"{existing} | {message}"[:1000]


def summarize(results: list[BenchmarkResult]) -> dict:
    successful_times = [r.elapsed_seconds for r in results if r.ok]
    failed_times = [r.elapsed_seconds for r in results if not r.ok]

    def percentile(values: list[float], pct: float) -> float:
        if not values:
            return 0.0
        ordered = sorted(values)
        index = round((len(ordered) - 1) * pct)
        return round(ordered[index], 3)

    timing_fields = [
        "elapsed_seconds",
        "upload_seconds",
        "zeek_seconds",
        "rita_import_seconds",
        "rita_view_seconds",
        "rita_total_seconds",
        "output_write_seconds",
        "lstm_seconds",
        "rag_seconds",
        "ai_seconds",
    ]

    def stats_for(field: str) -> dict:
        values = [getattr(r, field) for r in results if r.ok]
        return {
            "min": round(min(values), 3) if values else 0.0,
            "max": round(max(values), 3) if values else 0.0,
            "mean": round(statistics.mean(values), 3) if values else 0.0,
            "median": round(statistics.median(values), 3) if values else 0.0,
            "p90": percentile(values, 0.90),
            "p95": percentile(values, 0.95),
        }

    return {
        "total_runs": len(results),
        "successful_runs": len(successful_times),
        "failed_runs": len(failed_times),
        "total_elapsed_seconds": round(sum(r.elapsed_seconds for r in results), 3),
        "stage_seconds": {field: stats_for(field) for field in timing_fields},
        "success_elapsed_seconds": {
            "min": round(min(successful_times), 3) if successful_times else 0.0,
            "max": round(max(successful_times), 3) if successful_times else 0.0,
            "mean": round(statistics.mean(successful_times), 3) if successful_times else 0.0,
            "median": round(statistics.median(successful_times), 3) if successful_times else 0.0,
            "p90": percentile(successful_times, 0.90),
            "p95": percentile(successful_times, 0.95),
        },
    }


def write_outputs(output_dir: Path, results: list[BenchmarkResult], summary: dict) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    results_csv = output_dir / "pipeline_timing_results.csv"
    with results_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(asdict(results[0]).keys()))
        writer.writeheader()
        for result in results:
            writer.writerow(asdict(result))

    summary_json = output_dir / "pipeline_timing_summary.json"
    summary_json.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    lines = [
        "# Main Pipeline Benchmark",
        "",
        "## Run Summary",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Total runs | {summary['total_runs']} |",
        f"| Successful runs | {summary['successful_runs']} |",
        f"| Failed runs | {summary['failed_runs']} |",
        f"| Total elapsed seconds | {summary['total_elapsed_seconds']:.3f} |",
        f"| Min success seconds | {summary['success_elapsed_seconds']['min']:.3f} |",
        f"| Mean success seconds | {summary['success_elapsed_seconds']['mean']:.3f} |",
        f"| Median success seconds | {summary['success_elapsed_seconds']['median']:.3f} |",
        f"| P90 success seconds | {summary['success_elapsed_seconds']['p90']:.3f} |",
        f"| P95 success seconds | {summary['success_elapsed_seconds']['p95']:.3f} |",
        f"| Max success seconds | {summary['success_elapsed_seconds']['max']:.3f} |",
        "",
        "## Stage Timings",
        "",
        "| Stage | Mean | Median | P95 | Min | Max |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for stage, stats in summary["stage_seconds"].items():
        lines.append(
            f"| {stage} | {stats['mean']:.3f} | {stats['median']:.3f} | "
            f"{stats['p95']:.3f} | {stats['min']:.3f} | {stats['max']:.3f} |"
        )
    lines.extend(
        [
            "",
        f"Per-run details: `{results_csv}`",
        f"Machine-readable summary: `{summary_json}`",
        ]
    )
    (output_dir / "pipeline_timing_summary.md").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    args = parse_args()
    if args.repeat < 1:
        raise SystemExit("--repeat must be at least 1")

    output_dir = args.output_dir.resolve()
    samples = resolve_samples(args)
    total_runs = len(samples) * args.repeat

    print("Benchmark target: app.main /analyze stage-equivalent pipeline")
    print(f"Samples: {len(samples)}")
    print(f"Repeat:  {args.repeat}")
    print(f"Runs:    {total_runs}")
    print(f"Output:  {output_dir}")
    print()

    results: list[BenchmarkResult] = []
    run_index = 0
    for repeat_index in range(1, args.repeat + 1):
        for pcap, label in samples:
            run_index += 1
            print(
                f"[{run_index}/{total_runs}] "
                f"repeat={repeat_index} file={pcap.name} label={label}"
            )
            result = analyze_once(pcap, label)
            results.append(result)
            if result.ok:
                print(
                    f"    -> OK total={result.elapsed_seconds:.3f}s "
                    f"zeek={result.zeek_seconds:.3f}s "
                    f"rita={result.rita_total_seconds:.3f}s "
                    f"lstm={result.lstm_seconds:.3f}s "
                    f"rag={result.rag_seconds:.3f}s "
                    f"ai={result.ai_seconds:.3f}s "
                    f"report_chars={result.analysis_chars}"
                )
            else:
                print(
                    f"    -> FAIL {result.elapsed_seconds:.3f}s, "
                    f"status={result.status_code}, error={result.error[:240]}"
                )

    summary = summarize(results)
    write_outputs(output_dir, results, summary)

    print()
    print("End-to-end timing")
    print(f"  successful={summary['successful_runs']} failed={summary['failed_runs']}")
    print(
        "  success seconds: "
        f"mean={summary['success_elapsed_seconds']['mean']:.3f}, "
        f"median={summary['success_elapsed_seconds']['median']:.3f}, "
        f"p95={summary['success_elapsed_seconds']['p95']:.3f}"
    )
    print("  stage mean seconds:")
    for stage in [
        "upload_seconds",
        "zeek_seconds",
        "rita_total_seconds",
        "lstm_seconds",
        "rag_seconds",
        "ai_seconds",
    ]:
        print(f"    {stage}={summary['stage_seconds'][stage]['mean']:.3f}")
    print(f"Wrote results to {output_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
