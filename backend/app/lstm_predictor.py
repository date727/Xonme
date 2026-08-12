"""LSTM beacon detection for ARES/Zeek-style CSV feature rows."""

import csv
import io
import json
import logging
from collections import defaultdict
from pathlib import Path
from typing import Optional

import numpy as np


_keras_model = None
_scaler = None
_metadata = None
_decision_threshold = None
_load_attempted = False

MODELS_DIR = Path(__file__).resolve().parent / "models"
DEFAULT_GROUP_COLS = ["source_file", "src_ip", "dst_ip", "dst_port", "ip_protocol"]
DEFAULT_SORT_COL = "start_time"
INFERENCE_BATCH_SIZE = 512

logger = logging.getLogger(__name__)


def _load_artifacts() -> bool:
    """Lazy-load and cross-check the complete deployed model artifact set."""
    global _keras_model, _scaler, _metadata, _decision_threshold, _load_attempted

    if _load_attempted:
        return _keras_model is not None
    _load_attempted = True

    try:
        import keras
    except ImportError:
        logger.warning("keras not installed; LSTM detection disabled")
        return False

    model_path = MODELS_DIR / "beacon_lstm_model.keras"
    scaler_path = MODELS_DIR / "scaler.pkl"
    meta_path = MODELS_DIR / "model_metadata.json"
    threshold_path = MODELS_DIR / "decision_threshold.json"

    if not all(path.exists() for path in (model_path, scaler_path, meta_path, threshold_path)):
        logger.warning("Missing LSTM artifact(s) under %s; LSTM detection disabled", MODELS_DIR)
        return False

    try:
        _keras_model = keras.models.load_model(str(model_path), compile=False)
    except Exception as exc:
        logger.warning("Failed to load Keras model: %s", exc)
        return False

    try:
        import joblib

        _scaler = joblib.load(str(scaler_path))
    except Exception as exc:
        logger.warning("Failed to load scaler: %s", exc)
        _keras_model = None
        return False

    try:
        _metadata = json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("Failed to load metadata: %s", exc)
        _keras_model = None
        _scaler = None
        return False

    try:
        threshold_config = json.loads(threshold_path.read_text(encoding="utf-8"))
        _decision_threshold = float(threshold_config["threshold"])
        if not 0.0 <= _decision_threshold <= 1.0:
            raise ValueError("threshold must be between 0 and 1")

        feature_cols = _metadata["feature_cols"]
        seq_length = int(_metadata["seq_length"])
        expected_shape = [seq_length, len(feature_cols)]
        if _metadata.get("input_shape") != expected_shape:
            raise ValueError(
                f"metadata input_shape {_metadata.get('input_shape')} does not match {expected_shape}"
            )
        if getattr(_scaler, "n_features_in_", len(feature_cols)) != len(feature_cols):
            raise ValueError("scaler feature count does not match model metadata")

        model_shape = tuple(_keras_model.input_shape)
        if len(model_shape) != 3 or tuple(model_shape[1:]) != tuple(expected_shape):
            raise ValueError(f"model input shape {model_shape} does not match {expected_shape}")
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        logger.warning("Invalid or mismatched LSTM artifact set: %s", exc)
        _keras_model = _scaler = _metadata = _decision_threshold = None
        return False

    logger.info("LSTM artifacts loaded successfully (threshold=%s)", _decision_threshold)
    return True


def _normalize_row(row: dict, source_file: str) -> dict:
    """Support both current and older converter column names."""
    normalized = dict(row)
    aliases = {
        "src": "src_ip",
        "dst": "dst_ip",
        "port": "dst_port",
        "proto": "ip_protocol",
        "ts": "start_time",
    }
    for old, new in aliases.items():
        if new not in normalized and old in normalized:
            normalized[new] = normalized[old]
    normalized.setdefault("source_file", source_file)
    return normalized


def _row_to_feature_vector(row: dict, feature_cols: list[str]) -> np.ndarray:
    values = []
    for col in feature_cols:
        raw = str(row.get(col, "")).strip()
        try:
            values.append(float(raw))
        except (TypeError, ValueError):
            values.append(0.0)
    return np.asarray(values, dtype=np.float32)


def _prepare_groups(
    rows: list[dict],
    seq_len: int,
    group_cols: list[str],
    sort_col: str,
) -> list[tuple[tuple, list[dict]]]:
    """Group and order rows, excluding groups too short for one window."""
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for row in rows:
        key = tuple(row.get(col, "") for col in group_cols)
        groups[key].append(row)
    prepared = []
    for key, group_rows in groups.items():
        if len(group_rows) < seq_len:
            continue
        group_rows.sort(key=lambda row: _safe_float(row.get(sort_col, "0")))
        prepared.append((key, group_rows))
    return prepared


def _iter_sequence_batches(
    prepared_groups: list[tuple[tuple, list[dict]]],
    feature_cols: list[str],
    seq_len: int,
    batch_size: int = INFERENCE_BATCH_SIZE,
):
    """Yield every online window without materialising the full window set."""
    if batch_size <= 0:
        raise ValueError("inference batch size must be greater than zero")
    sequences: list[np.ndarray] = []
    window_info: list[dict] = []
    for key, group_rows in prepared_groups:
        features = np.asarray(
            [_row_to_feature_vector(row, feature_cols) for row in group_rows],
            dtype=np.float32,
        )
        for start in range(len(features) - seq_len + 1):
            end = start + seq_len
            sequences.append(features[start:end])
            first = group_rows[start]
            window_info.append(
                {
                    "group_key": key,
                    "src": first.get("src_ip", "?"),
                    "dst": first.get("dst_ip", "?"),
                    "port": first.get("dst_port", "?"),
                    "proto": first.get("ip_protocol", "?"),
                    "event_count": seq_len,
                    "flow_gap": _safe_float(first.get("flow_gap", "0")),
                    "gap_cv": _safe_float(first.get("gap_rolling_cv", "0")),
                }
            )
            if len(sequences) == batch_size:
                yield np.asarray(sequences, dtype=np.float32), window_info
                sequences, window_info = [], []
    if sequences:
        yield np.asarray(sequences, dtype=np.float32), window_info


def _extract_rows(csv_text: str) -> Optional[tuple[list[dict], list[str], int, list[str], str]]:
    """Parse and validate online feature rows against the deployed model contract."""
    if not _load_artifacts():
        return None

    feature_cols: list[str] = _metadata["feature_cols"]
    seq_len: int = int(_metadata["seq_length"])
    group_cols: list[str] = _metadata.get("group_cols", DEFAULT_GROUP_COLS)
    sort_col: str = _metadata.get("sort_col", DEFAULT_SORT_COL)

    raw_lines = csv_text.splitlines()
    start_idx = 0
    for i, line in enumerate(raw_lines):
        stripped = line.strip()
        if stripped and "," in stripped:
            start_idx = i
            break
    cleaned_csv_text = "\n".join(line for line in raw_lines[start_idx:] if line.strip())

    reader = csv.DictReader(io.StringIO(cleaned_csv_text))
    raw_rows = list(reader)
    if not raw_rows:
        logger.warning("LSTM CSV is empty; skipping detection")
        return None

    rows = [_normalize_row(row, source_file="zeek") for row in raw_rows]
    fieldnames = set(rows[0].keys())

    required = set(feature_cols + group_cols + [sort_col])
    missing = sorted(required - fieldnames)
    if missing:
        logger.warning("LSTM CSV missing required columns %s; skipping detection", missing)
        return None

    return rows, feature_cols, seq_len, group_cols, sort_col


def _risk_level(probability: float) -> str:
    if probability >= 0.9:
        return "Critical"
    if probability >= 0.75:
        return "High"
    if probability >= 0.6:
        return "Medium"
    return "Low"


def _deduplicate_beacons(beacons: list[dict]) -> list[dict]:
    seen: dict[tuple, dict] = {}
    for beacon in beacons:
        key = (beacon["src"], beacon["dst"], beacon.get("port"), beacon.get("proto"))
        if key not in seen or beacon["confidence"] > seen[key]["confidence"]:
            seen[key] = beacon
    return sorted(seen.values(), key=lambda item: item["confidence"], reverse=True)


def _default_threshold() -> float:
    """Return the deployment threshold from decision_threshold.json only."""
    if _decision_threshold is None:
        raise RuntimeError("LSTM decision threshold was not loaded")
    return _decision_threshold


def predict_beacons(
    csv_text: str,
    threshold: float | str | None = None,
    *,
    batch_size: int = INFERENCE_BATCH_SIZE,
) -> Optional[dict]:
    """Run LSTM detection on LSTM feature CSV text."""
    if batch_size <= 0:
        raise ValueError("inference batch size must be greater than zero")
    extracted = _extract_rows(csv_text)
    if extracted is None:
        return None
    rows, feature_cols, seq_len, group_cols, sort_col = extracted
    prepared_groups = _prepare_groups(rows, seq_len, group_cols, sort_col)
    if not prepared_groups:
        logger.info("No groups had enough rows to build LSTM sequences; skipping detection")
        return None
    raw_threshold = _default_threshold() if threshold is None else threshold
    try:
        threshold = float(raw_threshold)
    except (TypeError, ValueError) as exc:
        raise ValueError("threshold must be a number between 0 and 1") from exc
    if not 0.0 <= threshold <= 1.0:
        raise ValueError("threshold must be between 0 and 1")
    feature_count = len(feature_cols)
    best_by_group: dict[tuple, tuple[float, dict]] = {}
    total_windows = 0
    try:
        for sequences, window_info in _iter_sequence_batches(
            prepared_groups, feature_cols, seq_len, batch_size
        ):
            n_rows = sequences.shape[0]
            flat = sequences.reshape(-1, feature_count)
            scaled = _scaler.transform(flat).reshape(n_rows, seq_len, feature_count)
            probabilities = _keras_model.predict(scaled, verbose=0).flatten()
            if len(probabilities) != len(window_info):
                raise ValueError("model returned an unexpected prediction count")
            total_windows += len(window_info)
            for probability, info in zip(probabilities, window_info):
                probability = float(probability)
                current = best_by_group.get(info["group_key"])
                if current is None or probability > current[0]:
                    best_by_group[info["group_key"]] = (probability, info)
    except Exception as exc:
        logger.warning("LSTM batched prediction failed: %s", exc)
        return None

    beacons = []
    for probability, info in best_by_group.values():
        if probability < threshold:
            continue
        beacons.append({
            "src": info["src"], "dst": info["dst"],
            "port": info.get("port", "?"), "proto": info.get("proto", "?"),
            "confidence": round(probability * 100, 1),
            "risk": _risk_level(probability), "event_count": info["event_count"],
            "flow_gap": round(info["flow_gap"], 3), "gap_cv": round(info["gap_cv"], 3),
        })
    beacons.sort(key=lambda item: item["confidence"], reverse=True)
    unique_connections = len(best_by_group)
    total_flagged = len(beacons)

    if total_flagged:
        summary = (
            f"The all-TCP LSTM beacon detection model analyzed {unique_connections} "
            f"connection groups and flagged **{total_flagged}** as potential C2 beacons."
        )
    else:
        summary = (
            f"The all-TCP LSTM beacon detection model analyzed {unique_connections} "
            f"connection groups and found no beacon-like activity."
        )

    logger.info(
        "LSTM: evaluated all %d windows in batches of at most %d; %d/%d groups flagged",
        total_windows, batch_size, total_flagged, unique_connections,
    )

    return {
        "beacons": beacons,
        "total_connections": unique_connections,
        "total_flagged": total_flagged,
        "threshold": float(threshold),
        "total_windows": total_windows,
        "inference_batch_size": batch_size,
        "summary_text": summary,
    }


def format_for_prompt(lstm_results: dict | None) -> str:
    """Format an auditable LSTM status section for the AI report.

    This deliberately reports both positive and negative detection outcomes.
    ``None`` means the LSTM could not produce a valid result; it must never be
    described as a benign verdict.
    """
    if lstm_results is None:
        return "\n".join(
            [
                "## LSTM 时序检测结果",
                "",
                "- **检测状态**：未完成",
                "- **说明**：未能构造可用的 LSTM 输入序列，或模型/特征提取不可用；这不等同于流量为良性。",
            ]
        )

    threshold = float(lstm_results.get("threshold", 0.0))
    lines = [
        "## LSTM 时序检测结果",
        "",
        "- **检测状态**：完成",
        f"- **告警阈值**：{threshold:.6f}",
    ]

    beacons = lstm_results.get("beacons", [])
    if beacons:
        lines.extend(
            [
                "",
                "| Source IP | Destination IP | Port | Proto | Confidence | Risk Level |",
                "|-----------|----------------|------|-------|------------|------------|",
            ]
        )
        for beacon in beacons[:20]:
            lines.append(
                f"| {beacon['src']} | {beacon['dst']} | {beacon['port']} | "
                f"{beacon.get('proto', '?')} | {beacon['confidence']}% | {beacon['risk']} |"
            )
        if len(beacons) > 20:
            lines.append(f"| *({len(beacons) - 20} more not shown)* |||||")

        lines.extend(
            [
                "",
                "以上通信组达到 LSTM C2 Beacon 告警阈值，应结合 RITA、Zeek 和资产上下文优先核查。",
            ]
        )
    else:
        lines.extend(
            [
                "",
                "**判定**：已完成 LSTM 时序分析，未发现达到告警阈值的 C2 Beacon 通信组。"
                "该结果表示“本次模型未命中”，不构成对流量绝对安全或无其他攻击行为的证明。",
            ]
        )

    return "\n".join(lines)


def _safe_float(value) -> float:
    if value in {"", "-", None}:
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
