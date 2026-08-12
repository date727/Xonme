"""Offline inference for the deployed all-TCP C2 beacon LSTM.

This command uses the same feature schema, threshold file, communication-group
aggregation, and maximum-window decision rule as ``backend/app/lstm_predictor``.
"""
import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from tensorflow.keras.models import load_model as keras_load_model

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from config import (  # noqa: E402
    FEATURE_COLS,
    MAX_WINDOWS_PER_GROUP,
    METADATA_PATH,
    MODEL_PATH,
    SCALER_PATH,
    THRESHOLD_PATH,
)
from data_prep import build_sequences, load_scaler, load_split, scale_sequences  # noqa: E402


def load_artifacts():
    """Load and verify the model, scaler, metadata, and threshold as one set."""
    required_paths = (MODEL_PATH, SCALER_PATH, METADATA_PATH, THRESHOLD_PATH)
    missing = [str(path) for path in required_paths if not path.exists()]
    if missing:
        raise FileNotFoundError(f"Missing model artifact(s): {', '.join(missing)}")

    metadata = json.loads(METADATA_PATH.read_text(encoding="utf-8"))
    threshold_config = json.loads(THRESHOLD_PATH.read_text(encoding="utf-8"))
    threshold = float(threshold_config["threshold"])
    if not 0.0 <= threshold <= 1.0:
        raise ValueError("decision threshold must be between 0 and 1")
    if metadata.get("feature_cols") != FEATURE_COLS:
        raise ValueError("model metadata feature columns do not match the current training configuration")
    expected_shape = (int(metadata["seq_length"]), len(FEATURE_COLS))
    if metadata.get("input_shape") != list(expected_shape):
        raise ValueError("model metadata input shape does not match its feature schema")

    scaler = load_scaler()
    if getattr(scaler, "n_features_in_", len(FEATURE_COLS)) != len(FEATURE_COLS):
        raise ValueError("scaler feature count does not match model metadata")
    model = keras_load_model(str(MODEL_PATH), compile=False)
    if tuple(model.input_shape[1:]) != expected_shape:
        raise ValueError(f"model input shape {model.input_shape} does not match {expected_shape}")
    return model, scaler, metadata, threshold


def predict_frame(
    frame: pd.DataFrame,
    model,
    scaler,
    metadata: dict,
    threshold: float,
    *,
    max_windows_per_group: int = 0,
) -> dict:
    """Score a feature frame and aggregate windows by communication group."""
    X, labels, groups, window_metadata, stats = build_sequences(
        frame,
        seq_length=int(metadata["seq_length"]),
        max_windows_per_group=max_windows_per_group,
    )
    probabilities = model.predict(scale_sequences(X, scaler), verbose=0).ravel()
    grouped: dict[str, list[int]] = {}
    for index, group in enumerate(groups):
        grouped.setdefault(str(group), []).append(index)

    communications = []
    for indexes in grouped.values():
        best_index = max(indexes, key=lambda index: probabilities[index])
        info = window_metadata[best_index]
        communications.append({
            "source_file": info["source_file"],
            "src_ip": info["src_ip"], "dst_ip": info["dst_ip"],
            "dst_port": info["dst_port"], "ip_protocol": info["ip_protocol"],
            "window_count": len(indexes), "max_probability": float(probabilities[best_index]),
            "flagged": bool(probabilities[best_index] >= threshold),
        })
    communications.sort(key=lambda item: item["max_probability"], reverse=True)
    return {
        "threshold": threshold,
        "sequence_count": int(len(X)),
        "sequence_probabilities": probabilities,
        "labels": labels,
        "stats": stats,
        "communications": communications,
    }


def _print_result(result: dict) -> None:
    communications = result["communications"]
    flagged = [item for item in communications if item["flagged"]]
    print(f"Threshold: {result['threshold']:.12f}")
    print(f"Windows: {result['sequence_count']}; communication groups: {len(communications)}; flagged: {len(flagged)}")
    print(f"{'status':<8} {'max p':>12} {'windows':>7}  communication")
    for item in communications:
        endpoint = f"{item['src_ip']} -> {item['dst_ip']}:{item['dst_port']} ({item['ip_protocol']})"
        print(f"{'FLAGGED' if item['flagged'] else 'clear':<8} {item['max_probability']:>12.8f} {item['window_count']:>7}  {endpoint}")


def _metrics(y_true: np.ndarray, probabilities: np.ndarray, threshold: float) -> dict:
    predictions = (probabilities >= threshold).astype(int)
    tn = int(np.sum((y_true == 0) & (predictions == 0)))
    fp = int(np.sum((y_true == 0) & (predictions == 1)))
    fn = int(np.sum((y_true == 1) & (predictions == 0)))
    tp = int(np.sum((y_true == 1) & (predictions == 1)))
    return {
        "tn": tn, "fp": fp, "fn": fn, "tp": tp,
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Offline all-TCP C2 LSTM inference")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("csv", type=Path, nargs="?", help="One LSTM feature CSV to score")
    source.add_argument("--split", choices=("train", "val", "test"), help="Evaluate a prepared labelled split")
    args = parser.parse_args()

    model, scaler, metadata, threshold = load_artifacts()
    frame = load_split(args.split) if args.split else pd.read_csv(args.csv)
    result = predict_frame(
        frame,
        model,
        scaler,
        metadata,
        threshold,
        max_windows_per_group=MAX_WINDOWS_PER_GROUP if args.split else 0,
    )
    _print_result(result)
    if args.split:
        window_metrics = _metrics(result["labels"], result["sequence_probabilities"], threshold)
        print(f"Window metrics: recall={window_metrics['recall']:.4f}, FPR={window_metrics['fpr']:.4f}, "
              f"TP={window_metrics['tp']}, FP={window_metrics['fp']}, FN={window_metrics['fn']}, TN={window_metrics['tn']}")


if __name__ == "__main__":
    main()
