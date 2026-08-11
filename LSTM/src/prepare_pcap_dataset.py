"""Generate manifest-labelled all-TCP feature CSVs from raw PCAP files.

Usage: ``python src/prepare_pcap_dataset.py`` from the LSTM directory.
The script never changes raw captures; it writes derived CSVs beneath
``LSTM/feature_data/<split>/`` and a coverage report beneath ``LSTM/logs/``.
"""
import csv
import sys
from pathlib import Path
import argparse

import pandas as pd

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_REPO_ROOT = _PROJECT_ROOT.parent
sys.path.insert(0, str(_PROJECT_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "backend"))

from app.pcap_lstm_feature_extractor import CSV_FIELDS, PcapLSTMFeatureExtractor
from config import FEATURE_DATA_DIR, LOGS_DIR, SEQ_LENGTH, SPLIT_MANIFEST_PATH, SPLITS


LABELS = {"benign": 0, "malicious": 1}


def _sequence_coverage(frame: pd.DataFrame) -> tuple[int, int]:
    keys = ["source_file", "src_ip", "dst_ip", "dst_port", "ip_protocol"]
    sizes = frame.groupby(keys, dropna=False).size()
    return int(len(sizes)), int((sizes >= SEQ_LENGTH).sum())


def prepare_dataset(only_files: set[str] | None = None) -> list[dict[str, object]]:
    if not SPLIT_MANIFEST_PATH.exists():
        raise FileNotFoundError(f"Missing manifest: {SPLIT_MANIFEST_PATH}")
    manifest = pd.read_csv(SPLIT_MANIFEST_PATH)
    required = {"file_name", "label", "split", "source", "scenario"}
    missing = required - set(manifest.columns)
    if missing:
        raise KeyError(f"Manifest missing columns: {sorted(missing)}")
    reports: list[dict[str, object]] = []
    for item in manifest.itertuples(index=False):
        if only_files and item.file_name not in only_files:
            continue
        if item.split not in SPLITS or item.label not in LABELS:
            raise ValueError(f"Invalid manifest row: {item}")
        raw_path = _PROJECT_ROOT / "data" / item.label / item.file_name
        if not raw_path.exists():
            raise FileNotFoundError(f"Manifest PCAP does not exist: {raw_path}")
        output_path = FEATURE_DATA_DIR / item.split / f"{Path(item.file_name).stem}.csv"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        source_file = f"{item.source}__{item.file_name}"
        rows = PcapLSTMFeatureExtractor(raw_path, source_file=source_file).build_rows()
        frame = pd.DataFrame(rows)
        if not frame.empty:
            frame["label"] = LABELS[item.label]
            frame["split"] = item.split
            frame["dataset"] = item.source
            frame["scenario"] = item.scenario
            frame.to_csv(output_path, index=False)
            group_count, usable_groups = _sequence_coverage(frame)
        else:
            # Retain a valid header so other CSV readers can inspect the file.
            pd.DataFrame(columns=[*CSV_FIELDS, "label", "split", "dataset", "scenario"]).to_csv(output_path, index=False)
            group_count = usable_groups = 0
        reports.append({
            "file_name": item.file_name, "label": item.label, "split": item.split,
            "source": item.source, "scenario": item.scenario, "connection_rows": len(frame),
            "connection_groups": group_count, "groups_with_sequence": usable_groups,
            "feature_csv": str(output_path.relative_to(_PROJECT_ROOT)),
        })
        print(f"{item.split:5} {item.label:9} rows={len(frame):6} usable_groups={usable_groups:4} {item.file_name}")
    report_path = LOGS_DIR / "pcap_feature_coverage.csv"
    pd.DataFrame(reports).to_csv(report_path, index=False)
    print(f"Coverage report written to {report_path}")
    return reports


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build all-TCP LSTM feature CSVs from manifest PCAPs")
    parser.add_argument("--only", nargs="+", help="Only process these manifest file names")
    args = parser.parse_args()
    prepare_dataset(set(args.only) if args.only else None)
