#!/usr/bin/env python3
"""Batch-run ARES PCAPs through Zeek, RITA and the PCAP LSTM detector.

The script writes both detector-specific artifacts and one consolidated CSV of
merged threat features.  The latter is deliberately model-agnostic: it can be
used as the auditable input to the RAG attribution experiment without rerunning
Zeek/RITA/LSTM.

Expected input layout (the directory may contain PCAPs directly)::

    RAG_data/ARES_malicious/*.pcap[ng]

For each PCAP, RITA is run over Zeek logs and the LSTM consumes packet-time
features reconstructed directly from the PCAP.  A threat is included when it is
flagged by either detector, and the merged row records exactly which detector
provided the evidence.
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
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from fastapi import HTTPException

from app.data_extractor import ThreatFeatureExtractor
from app.lstm_predictor import predict_beacons
from app.main import make_rita_db_name, run_zeek
from app.pcap_lstm_feature_extractor import export_lstm_features_from_pcap
from app.threat_feature_merger import merge_threat_features


BACKEND_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = BACKEND_ROOT.parent
DEFAULT_DATASET = PROJECT_ROOT / "RAG_data" / "ARES_malicious"
DEFAULT_OUTPUT = BACKEND_ROOT / "outputs" / "ares_dual_detection"
PCAP_SUFFIXES = {".pcap", ".pcapng"}


@dataclass
class SampleResult:
    source_file: str
    dataset_label: str
    rita_ok: bool
    rita_threat_count: int
    lstm_completed: bool
    lstm_flagged_count: int
    merged_threat_count: int
    elapsed_seconds: float
    artifact_dir: str
    error: str = ""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Batch ARES PCAPs through Zeek + RITA and the LSTM detector."
    )
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--dataset-label", default="malicious",
        help="Reporting-only ground-truth label stored in output CSV.",
    )
    parser.add_argument("--pattern", default="*", help="PCAP filename glob.")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--rita-import-timeout", type=int, default=600)
    parser.add_argument("--rita-view-timeout", type=int, default=120)
    parser.add_argument("--keep-zeek-logs", action="store_true")
    return parser.parse_args()


def safe_stem(path: Path) -> str:
    text = "".join(ch if ch.isalnum() else "_" for ch in path.stem.lower())
    return text.strip("_") or "sample"


def require_tools() -> None:
    missing = [name for name in ("zeek", "rita") if shutil.which(name) is None]
    if missing:
        raise SystemExit(f"Missing required command(s): {', '.join(missing)}")


def require_compatible_lstm_artifacts() -> None:
    """Fail before a costly batch run if API model artifacts are stale.

    ``pcap_lstm_feature_extractor`` emits the current 24-dimensional all-TCP
    feature schema.  Older API artifacts use the previous 15-dimensional RITA
    IAT schema and cannot be used for this batch pipeline.
    """
    models_dir = BACKEND_ROOT / "app" / "models"
    required = [
        models_dir / "beacon_lstm_model.keras",
        models_dir / "scaler.pkl",
        models_dir / "model_metadata.json",
    ]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        raise SystemExit("Missing LSTM model artifact(s): " + ", ".join(missing))
    try:
        metadata = json.loads((models_dir / "model_metadata.json").read_text(encoding="utf-8"))
        feature_count = len(metadata.get("feature_cols") or [])
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Cannot read LSTM metadata: {exc}") from exc
    if feature_count != 24:
        raise SystemExit(
            "Incompatible backend/app/models artifacts: expected the current "
            f"24-feature all-TCP LSTM model, found {feature_count} features. "
            "Copy LSTM/models/{beacon_lstm_model.keras,scaler.pkl,model_metadata.json} "
            "to backend/app/models/ before running this batch."
        )


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


def extract_rita_features(rita_csv: str) -> list[dict[str, Any]]:
    """Use the same RITA extraction logic used by the application pipeline."""
    # The extractor emits human-oriented diagnostics; keep batch console output
    # compact while preserving the actual returned detector features.
    with contextlib.redirect_stdout(io.StringIO()):
        return ThreatFeatureExtractor(rita_csv).extract_all()


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def evaluate_sample(
    pcap: Path,
    *,
    dataset_label: str,
    output_dir: Path,
    run_id: str,
    import_timeout: int,
    view_timeout: int,
    keep_zeek_logs: bool,
) -> tuple[SampleResult, list[dict[str, Any]]]:
    started = time.perf_counter()
    sample_id = f"{run_id}_{safe_stem(pcap)}"
    artifact_dir = output_dir / "samples" / sample_id
    zeek_dir = artifact_dir / "zeek_logs"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    zeek_dir.mkdir(parents=True, exist_ok=True)

    rita_ok = False
    rita_features: list[dict[str, Any]] = []
    lstm_result: dict[str, Any] | None = None
    merged_features: list[dict[str, Any]] = []
    errors: list[str] = []

    # RITA and LSTM are independent branches.  A RITA failure must not prevent
    # a packet-timing LSTM result from being retained for RAG analysis.
    try:
        run_zeek(str(pcap), zeek_dir)
        if not list(zeek_dir.glob("*.log")):
            raise RuntimeError("Zeek did not produce any log files")

        db_name = make_rita_db_name(sample_id)
        rita_csv = run_rita(zeek_dir, db_name, import_timeout, view_timeout)
        (artifact_dir / "rita_view.csv").write_text(rita_csv, encoding="utf-8")
        rita_ok = True
        rita_features = extract_rita_features(rita_csv)
    except (HTTPException, subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError) as exc:
        if isinstance(exc, HTTPException):
            errors.append(f"RITA/Zeek: {exc.detail}")
        elif isinstance(exc, subprocess.CalledProcessError):
            errors.append(f"RITA/Zeek: {(exc.stderr or exc.stdout or str(exc)).strip()}")
        else:
            errors.append(f"RITA/Zeek: {exc}")
    except Exception as exc:
        errors.append(f"RITA/Zeek: {type(exc).__name__}: {exc}")

    try:
        lstm_csv = export_lstm_features_from_pcap(pcap, source_file=pcap.name)
        (artifact_dir / "lstm_features.csv").write_text(lstm_csv, encoding="utf-8")
        if lstm_csv:
            lstm_result = predict_beacons(lstm_csv)
        if lstm_result is not None:
            write_json(artifact_dir / "lstm_result.json", lstm_result)
    except Exception as exc:
        errors.append(f"LSTM: {type(exc).__name__}: {exc}")

    try:
        merged_features = merge_threat_features(rita_features, lstm_result)
        write_json(artifact_dir / "merged_features.json", merged_features)
    except Exception as exc:
        errors.append(f"Merge: {type(exc).__name__}: {exc}")
    finally:
        if not keep_zeek_logs and zeek_dir.exists():
            shutil.rmtree(zeek_dir, ignore_errors=True)

    elapsed = round(time.perf_counter() - started, 3)
    lstm_flagged = int((lstm_result or {}).get("total_flagged") or 0)
    sample_result = SampleResult(
        source_file=pcap.name,
        dataset_label=dataset_label,
        rita_ok=rita_ok,
        rita_threat_count=len(rita_features),
        lstm_completed=lstm_result is not None,
        lstm_flagged_count=lstm_flagged,
        merged_threat_count=len(merged_features),
        elapsed_seconds=elapsed,
        artifact_dir=str(artifact_dir),
        error=" | ".join(errors),
    )

    consolidated: list[dict[str, Any]] = []
    for index, feature in enumerate(merged_features, start=1):
        consolidated.append({
            "source_file": pcap.name,
            "dataset_label": dataset_label,
            "threat_index": index,
            "detection_sources": ";".join(feature.get("detection_sources") or []),
            "src_ip": feature.get("src_ip", ""),
            "dst_ip": feature.get("dst_ip", ""),
            "dst_port": feature.get("dst_port", ""),
            "protocol": feature.get("protocol", ""),
            "beacon_score": feature.get("beacon_score", 0.0),
            "long_conn_value": feature.get("long_conn_value", 0.0),
            "c2_over_dns_value": feature.get("c2_over_dns_value", 0.0),
            "connection_count": feature.get("connection_count", 0),
            "total_bytes": feature.get("total_bytes", 0),
            "lstm_confidence": feature.get("lstm_confidence", 0.0),
            "lstm_risk": feature.get("lstm_risk", ""),
            "threat_category": feature.get("threat_category", ""),
            "feature_json": json.dumps(feature, ensure_ascii=False),
        })
    return sample_result, consolidated


def write_outputs(output_dir: Path, results: list[SampleResult], threats: list[dict[str, Any]]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    sample_csv = output_dir / "per_sample_detection_summary.csv"
    with sample_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(asdict(results[0]).keys()))
        writer.writeheader()
        writer.writerows(asdict(result) for result in results)

    fields = [
        "source_file", "dataset_label", "threat_index", "detection_sources",
        "src_ip", "dst_ip", "dst_port", "protocol", "beacon_score", "long_conn_value",
        "c2_over_dns_value", "connection_count", "total_bytes", "lstm_confidence",
        "lstm_risk", "threat_category", "feature_json",
    ]
    threat_csv = output_dir / "merged_threat_features_for_rag.csv"
    with threat_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(threats)

    source_counts = Counter(row["detection_sources"] for row in threats)
    summary = {
        "pcap_count": len(results),
        "successful_zeek_rita_count": sum(result.rita_ok for result in results),
        "lstm_completed_count": sum(result.lstm_completed for result in results),
        "lstm_flagged_connection_count": sum(result.lstm_flagged_count for result in results),
        "merged_threat_count": len(threats),
        "detector_source_counts": dict(source_counts),
        "failed_samples": [
            {"source_file": result.source_file, "error": result.error}
            for result in results if result.error
        ],
        "artifacts": {
            "per_sample_summary": str(sample_csv),
            "merged_features_for_rag": str(threat_csv),
        },
    }
    write_json(output_dir / "batch_summary.json", summary)


def main() -> int:
    args = parse_args()
    require_tools()
    require_compatible_lstm_artifacts()
    dataset = args.dataset.resolve()
    output_dir = args.output_dir.resolve()
    if not dataset.is_dir():
        raise SystemExit(f"Dataset directory not found: {dataset}")

    pcaps = [
        path for path in sorted(dataset.glob(args.pattern))
        if path.is_file() and path.suffix.lower() in PCAP_SUFFIXES
    ]
    if args.limit > 0:
        pcaps = pcaps[:args.limit]
    if not pcaps:
        raise SystemExit(f"No PCAP/PCAPNG files found in {dataset}")

    run_id = time.strftime("%Y%m%d_%H%M%S")
    results: list[SampleResult] = []
    threats: list[dict[str, Any]] = []
    print(f"Dataset: {dataset}")
    print(f"PCAPs: {len(pcaps)}")
    print(f"Output: {output_dir}")

    for index, pcap in enumerate(pcaps, start=1):
        print(f"[{index}/{len(pcaps)}] {pcap.name}")
        result, rows = evaluate_sample(
            pcap,
            dataset_label=args.dataset_label,
            output_dir=output_dir,
            run_id=run_id,
            import_timeout=args.rita_import_timeout,
            view_timeout=args.rita_view_timeout,
            keep_zeek_logs=args.keep_zeek_logs,
        )
        results.append(result)
        threats.extend(rows)
        print(
            f"    RITA={result.rita_threat_count}, "
            f"LSTM={result.lstm_flagged_count}, merged={result.merged_threat_count}, "
            f"elapsed={result.elapsed_seconds}s"
        )
        if result.error:
            print(f"    ERROR: {result.error[:300]}")

    write_outputs(output_dir, results, threats)
    print(f"Done. RAG input CSV: {output_dir / 'merged_threat_features_for_rag.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
