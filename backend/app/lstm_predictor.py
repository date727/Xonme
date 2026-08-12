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


def _build_sequences(
    rows: list[dict],
    feature_cols: list[str],
    seq_len: int,
    group_cols: list[str],
    sort_col: str,
) -> tuple[np.ndarray, list[dict]]:
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for row in rows:
        key = tuple(row.get(col, "") for col in group_cols)
        groups[key].append(row)

    sequences = []
    conn_info: list[dict] = []
    skipped = 0

    for key, group_rows in groups.items():
        if len(group_rows) < seq_len:
            skipped += 1
            continue

        group_rows.sort(key=lambda r: _safe_float(r.get(sort_col, "0")))
        features = np.asarray(
            [_row_to_feature_vector(row, feature_cols) for row in group_rows],
            dtype=np.float32,
        )

        for start in range(len(features) - seq_len + 1):
            end = start + seq_len
            sequences.append(features[start:end])
            first = group_rows[start]
            conn_info.append(
                {
                    "src": first.get("src_ip", "?"),
                    "dst": first.get("dst_ip", "?"),
                    "port": first.get("dst_port", "?"),
                    "proto": first.get("ip_protocol", "?"),
                    "event_count": seq_len,
                    "flow_gap": _safe_float(first.get("flow_gap", "0")),
                    "gap_cv": _safe_float(first.get("gap_rolling_cv", "0")),
                }
            )

    logger.info(
        "LSTM: built %d sequences from %d groups (%d skipped with fewer than %d rows)",
        len(sequences),
        len(groups),
        skipped,
        seq_len,
    )

    if not sequences:
        return np.empty((0, seq_len, len(feature_cols)), dtype=np.float32), conn_info
    return np.asarray(sequences, dtype=np.float32), conn_info


def _extract_features(csv_text: str) -> Optional[tuple[np.ndarray, list[dict]]]:
    """Parse CSV text and build sequences exactly like the training pipeline."""
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

    sequences, conn_info = _build_sequences(rows, feature_cols, seq_len, group_cols, sort_col)
    if sequences.shape[0] == 0:
        logger.info("No groups had enough rows to build LSTM sequences; skipping detection")
        return None

    return sequences, conn_info


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


def predict_beacons(csv_text: str, threshold: float | None = None) -> Optional[dict]:
    """Run LSTM detection on LSTM feature CSV text."""
    extracted = _extract_features(csv_text)
    if extracted is None:
        return None

    sequences, conn_info = extracted
    if sequences.ndim != 3 or sequences.shape[0] == 0:
        return None

    n_rows, seq_len, feature_count = sequences.shape
    threshold = _default_threshold() if threshold is None else threshold

    try:
        flat = sequences.reshape(-1, feature_count)
        scaled = _scaler.transform(flat).reshape(n_rows, seq_len, feature_count)
    except Exception as exc:
        logger.warning("Feature scaling failed: %s", exc)
        return None

    try:
        probabilities = _keras_model.predict(scaled, verbose=0).flatten()
    except Exception as exc:
        logger.warning("LSTM prediction failed: %s", exc)
        return None

    beacons = []
    for i, probability in enumerate(probabilities):
        if probability >= threshold:
            info = conn_info[i]
            beacons.append(
                {
                    "src": info["src"],
                    "dst": info["dst"],
                    "port": info.get("port", "?"),
                    "proto": info.get("proto", "?"),
                    "confidence": round(float(probability) * 100, 1),
                    "risk": _risk_level(float(probability)),
                    "event_count": info["event_count"],
                    "flow_gap": round(info["flow_gap"], 3),
                    "gap_cv": round(info["gap_cv"], 3),
                }
            )

    beacons = _deduplicate_beacons(beacons)
    unique_connections = len(
        {(item["src"], item["dst"], item.get("port"), item.get("proto")) for item in conn_info}
    )
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

    logger.info("LSTM: %d/%d connection groups flagged", total_flagged, unique_connections)

    return {
        "beacons": beacons,
        "total_connections": unique_connections,
        "total_flagged": total_flagged,
        "threshold": float(threshold),
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
