#!/usr/bin/env python3
"""Benchmark the full main.py PCAP analysis pipeline.

This script calls the FastAPI `/analyze` endpoint in-process with TestClient, so
the measured time covers the same path as a real upload:

    PCAP upload -> Zeek -> RITA -> LSTM -> RAG -> AI report -> response

It intentionally measures end-to-end wall-clock time instead of individual
stage timings.
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app


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
    run_name: str = ""
    csv_path: str = ""
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


def analyze_once(client: TestClient, pcap: Path, label: str) -> BenchmarkResult:
    started = time.perf_counter()
    status_code = 0
    try:
        with pcap.open("rb") as f:
            response = client.post(
                "/analyze",
                files={"pcap": (pcap.name, f, "application/vnd.tcpdump.pcap")},
            )

        elapsed = time.perf_counter() - started
        status_code = response.status_code

        if response.status_code != 200:
            return BenchmarkResult(
                file=str(pcap),
                label=label,
                status_code=status_code,
                ok=False,
                elapsed_seconds=round(elapsed, 3),
                error=response.text[:1000],
            )

        payload = response.json()
        analysis = payload.get("analysis_markdown") or ""
        return BenchmarkResult(
            file=str(pcap),
            label=label,
            status_code=status_code,
            ok=True,
            elapsed_seconds=round(elapsed, 3),
            run_name=payload.get("name", ""),
            csv_path=payload.get("csv_path", ""),
            analysis_chars=len(analysis),
        )
    except Exception as exc:
        elapsed = time.perf_counter() - started
        return BenchmarkResult(
            file=str(pcap),
            label=label,
            status_code=status_code,
            ok=False,
            elapsed_seconds=round(elapsed, 3),
            error=str(exc)[:1000],
        )


def summarize(results: list[BenchmarkResult]) -> dict:
    successful_times = [r.elapsed_seconds for r in results if r.ok]
    failed_times = [r.elapsed_seconds for r in results if not r.ok]

    def percentile(values: list[float], pct: float) -> float:
        if not values:
            return 0.0
        ordered = sorted(values)
        index = round((len(ordered) - 1) * pct)
        return round(ordered[index], 3)

    return {
        "total_runs": len(results),
        "successful_runs": len(successful_times),
        "failed_runs": len(failed_times),
        "total_elapsed_seconds": round(sum(r.elapsed_seconds for r in results), 3),
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
        f"Per-run details: `{results_csv}`",
        f"Machine-readable summary: `{summary_json}`",
    ]
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

    print("Benchmark target: app.main /analyze")
    print(f"Samples: {len(samples)}")
    print(f"Repeat:  {args.repeat}")
    print(f"Runs:    {total_runs}")
    print(f"Output:  {output_dir}")
    print()

    results: list[BenchmarkResult] = []
    with TestClient(app) as client:
        run_index = 0
        for repeat_index in range(1, args.repeat + 1):
            for pcap, label in samples:
                run_index += 1
                print(
                    f"[{run_index}/{total_runs}] "
                    f"repeat={repeat_index} file={pcap.name} label={label}"
                )
                result = analyze_once(client, pcap, label)
                results.append(result)
                if result.ok:
                    print(
                        f"    -> OK {result.elapsed_seconds:.3f}s, "
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
    print(f"Wrote results to {output_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
