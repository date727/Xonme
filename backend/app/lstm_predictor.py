"""
LSTM beacon detection module.

Loads a pre-trained Keras model, StandardScaler, and metadata,
parses RITA CSV output, constructs sequences, runs predictions,
and returns structured results.

All functions are non-blocking — failures produce None and log warnings,
so the analysis pipeline can continue with RITA data alone.
"""

import csv
import io
import json
import logging
from collections import defaultdict
from pathlib import Path
from typing import Optional

import numpy as np

# ---------------------------------------------------------------------------
# Lazy-loaded globals — loaded once on first call, never at import time
# ---------------------------------------------------------------------------
_keras_model = None
_scaler = None
_metadata = None
_load_attempted = False

MODELS_DIR = Path(__file__).resolve().parent / "models"

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Artifact loading
# ---------------------------------------------------------------------------

def _load_artifacts() -> bool:
    """Lazy-load Keras model, joblib scaler, and JSON metadata.

    Returns True when all three load successfully.
    Logs warnings on failure so the operator can diagnose missing deps.
    """
    global _keras_model, _scaler, _metadata, _load_attempted

    if _load_attempted:
        return _keras_model is not None

    _load_attempted = True

    # --- Keras model ---
    try:
        import keras  # noqa: F811
    except ImportError:
        logger.warning("keras not installed — LSTM detection disabled")
        return False

    model_path = MODELS_DIR / "beacon_lstm_model.keras"
    if not model_path.exists():
        logger.warning("Model file not found: %s — LSTM detection disabled", model_path)
        return False

    try:
        _keras_model = keras.models.load_model(str(model_path), compile=False)
    except Exception as exc:
        logger.warning("Failed to load Keras model: %s", exc)
        return False

    # --- StandardScaler ---
    try:
        import joblib  # noqa: F811
    except ImportError:
        logger.warning("joblib not installed — LSTM detection disabled")
        _keras_model = None
        return False

    scaler_path = MODELS_DIR / "scaler.pkl"
    if not scaler_path.exists():
        logger.warning("Scaler file not found: %s — LSTM detection disabled", scaler_path)
        _keras_model = None
        return False

    try:
        _scaler = joblib.load(str(scaler_path))
    except Exception as exc:
        logger.warning("Failed to load scaler: %s", exc)
        _keras_model = None
        return False

    # --- Metadata ---
    meta_path = MODELS_DIR / "model_metadata.json"
    if not meta_path.exists():
        logger.warning("Metadata file not found: %s — LSTM detection disabled", meta_path)
        _keras_model = None
        _scaler = None
        return False

    try:
        _metadata = json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("Failed to load metadata: %s", exc)
        _keras_model = None
        _scaler = None
        return False

    logger.info("LSTM artifacts loaded successfully")
    return True


# ---------------------------------------------------------------------------
# Feature extraction helpers
# ---------------------------------------------------------------------------

def _row_to_feature_vector(row: dict, feature_cols: list[str]) -> np.ndarray:
    """Extract 15 float features from a single CSV row.

    Missing / blank values are replaced with 0.0.
    """
    values = []
    for col in feature_cols:
        raw = row.get(col, "").strip()
        try:
            values.append(float(raw))
        except (ValueError, TypeError):
            values.append(0.0)
    return np.array(values, dtype=np.float32)


def _rows_to_feature_array(rows: list[dict], feature_cols: list[str]) -> np.ndarray:
    """Extract features from multiple rows.  Returns (N, 15)."""
    return np.array(
        [_row_to_feature_vector(r, feature_cols) for r in rows], dtype=np.float32
    )


# ---------------------------------------------------------------------------
# Sequence construction
# ---------------------------------------------------------------------------

def _build_sequences_from_timeseries(
    rows: list[dict],
    group_keys: list[str],
    feature_cols: list[str],
    seq_len: int,
) -> tuple[np.ndarray, list[dict]]:
    """Build (N, seq_len, 15) sequences from time-series RITA output.

    Groups rows by connection key, sorts by timestamp when available,
    then creates sliding windows of *seq_len* consecutive time steps.
    Connections with fewer than *seq_len* windows are skipped.
    """
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for row in rows:
        key = tuple(row.get(k, "") for k in group_keys)
        groups[key].append(row)

    sequences = []
    conn_info: list[dict] = []
    skipped = 0

    # Detect timestamp column
    ts_col = "ts" if "ts" in rows[0] else None

    for key, group_rows in groups.items():
        if len(group_rows) < seq_len:
            skipped += 1
            continue

        if ts_col:
            group_rows.sort(key=lambda r: float(r.get(ts_col, 0)))

        feats = _rows_to_feature_array(group_rows, feature_cols)

        # Sliding windows
        for start in range(len(feats) - seq_len + 1):
            seq = feats[start : start + seq_len]  # (seq_len, 15)
            sequences.append(seq)
            conn_info.append({
                "src": group_rows[start].get("src", "?"),
                "dst": group_rows[start].get("dst", "?"),
                "port": group_rows[start].get("port", "?"),
                "proto": group_rows[start].get("proto", "?"),
            })

    logger.info(
        "LSTM: built %d sequences from %d connections (%d skipped, < %d windows)",
        len(sequences),
        len(groups),
        skipped,
        seq_len,
    )
    return np.array(sequences, dtype=np.float32), conn_info


def _build_sequences_from_singletons(
    rows: list[dict],
    feature_cols: list[str],
    seq_len: int,
) -> tuple[np.ndarray, list[dict]]:
    """Build (N, seq_len, 15) sequences when each row is one connection.

    Repeats each row *seq_len* times to form a degenerate sequence.
    The LSTM can still classify effectively because the 15 features include
    frequency-domain histogram bins (iat_oresp_nf_*) that encode beacon-like
    patterns even without a real temporal axis.
    """
    sequences = []
    conn_info: list[dict] = []

    for row in rows:
        feats = _row_to_feature_vector(row, feature_cols)  # (15,)
        seq = np.tile(feats, (seq_len, 1))                  # (seq_len, 15)
        sequences.append(seq)
        conn_info.append({
            "src": row.get("src", "?"),
            "dst": row.get("dst", "?"),
            "port": row.get("port", "?"),
            "proto": row.get("proto", "?"),
        })

    logger.info("LSTM: built %d singleton sequences (one per connection)", len(sequences))
    return np.array(sequences, dtype=np.float32), conn_info


# ---------------------------------------------------------------------------
# Main extraction entry point
# ---------------------------------------------------------------------------

def _extract_features(csv_text: str) -> Optional[tuple[np.ndarray, list[dict]]]:
    """Parse RITA CSV and construct (N, seq_len, 15) feature sequences.

    Returns ``(sequences, conn_info)`` or ``None`` when features are missing,
    the CSV is empty, or no connection has enough data.
    """
    if not _load_artifacts():
        return None

    feature_cols: list[str] = _metadata["feature_cols"]
    seq_len: int = _metadata["seq_length"]

    raw_lines = csv_text.splitlines()
    start_idx = 0
    for i, line in enumerate(raw_lines):
        stripped = line.strip()
        if stripped and "," in stripped:
            start_idx = i
            break
    cleaned_csv_text = "\n".join(ln for ln in raw_lines[start_idx:] if ln.strip())

    reader = csv.DictReader(io.StringIO(cleaned_csv_text))
    rows = list(reader)

    if not rows:
        logger.warning("RITA CSV is empty — skipping LSTM detection")
        return None

    # Verify all 15 feature columns are present
    fieldnames = reader.fieldnames or []
    available = [c for c in feature_cols if c in fieldnames]
    if len(available) != len(feature_cols):
        missing = set(feature_cols) - set(fieldnames)
        # Heuristic: RITA summary output (Severity/Beacon Score/Source IP...) is
        # valid for RAG, but not the feature-matrix schema required by this LSTM.
        looks_like_rita_summary = any(
            name in fieldnames
            for name in ["Severity", "Beacon Score", "Source IP", "Destination IP"]
        )
        if looks_like_rita_summary:
            logger.info(
                "Skipping LSTM: received RITA summary CSV (no iat_oresp_* model features). "
                "This is expected unless a model-feature export is provided."
            )
        else:
            logger.warning(
                "RITA CSV missing %d/%d feature columns: %s — skipping LSTM",
                len(missing),
                len(feature_cols),
                missing,
            )
        return None

    # Detect connection-grouping keys
    possible_keys = ["src", "dst", "proto", "port", "uid", "id_orig_h", "id_resp_h"]
    group_keys = [k for k in possible_keys if k in fieldnames]

    # Decide strategy: time-series vs singleton
    if group_keys and len(rows) > len(
        set(tuple(r.get(k, "") for k in group_keys) for r in rows)
    ):
        sequences, conn_info = _build_sequences_from_timeseries(
            rows, group_keys, feature_cols, seq_len
        )
        # Some datasets have one row per connection and cannot form seq_len windows.
        # Fall back to singleton expansion so inference can still proceed.
        if sequences.size == 0:
            logger.info(
                "No time-series windows built (seq_len=%d); falling back to singleton mode",
                seq_len,
            )
            return _build_sequences_from_singletons(rows, feature_cols, seq_len)
        return sequences, conn_info

    return _build_sequences_from_singletons(rows, feature_cols, seq_len)


# ---------------------------------------------------------------------------
# Prediction
# ---------------------------------------------------------------------------

def _risk_level(probability: float) -> str:
    """Map a prediction probability to a human-readable risk label."""
    if probability >= 0.9:
        return "Critical"
    elif probability >= 0.75:
        return "High"
    elif probability >= 0.6:
        return "Medium"
    return "Low"


def _deduplicate_beacons(beacons: list[dict]) -> list[dict]:
    """Keep only the highest-confidence prediction per unique connection."""
    seen: dict[tuple, dict] = {}
    for b in beacons:
        key = (b["src"], b["dst"], b.get("port"), b.get("proto"))
        if key not in seen or b["confidence"] > seen[key]["confidence"]:
            seen[key] = b
    return sorted(seen.values(), key=lambda x: x["confidence"], reverse=True)


def predict_beacons(csv_text: str, threshold: float = 0.5) -> Optional[dict]:
    """Run LSTM beacon detection on RITA CSV output.

    Parameters
    ----------
    csv_text:
        Raw stdout from ``rita view --stdout``.
    threshold:
        Probability above which a connection is flagged as a beacon.

    Returns
    -------
    dict or None
        A results dictionary on success, ``None`` if any prerequisite fails
        (missing model, incompatible CSV, prediction error, …).
    """
    extracted = _extract_features(csv_text)
    if extracted is None:
        return None

    sequences, conn_info = extracted  # (N, seq_len, 15)  and  list[dict]
    if sequences.ndim != 3 or sequences.shape[0] == 0:
        logger.info("No valid LSTM sequences after feature extraction — skipping prediction")
        return None

    N, T, F = sequences.shape

    # --- Scale features ---
    # The scaler was fit on 2-D (samples, 15) data.  Reshape, transform,
    # then restore the sequence dimension.
    try:
        flat = sequences.reshape(-1, F)               # (N*T, 15)
        flat_scaled = _scaler.transform(flat)          # (N*T, 15)
        sequences_scaled = flat_scaled.reshape(N, T, F)  # (N, T, 15)
    except Exception as exc:
        logger.warning("Feature scaling failed: %s", exc)
        return None

    # --- LSTM inference ---
    try:
        raw = _keras_model.predict(sequences_scaled, verbose=0)
        probabilities = raw.flatten()  # shape (N,)  values in [0, 1]
    except Exception as exc:
        logger.warning("LSTM prediction failed: %s", exc)
        return None

    # --- Build results ---
    beacons = []
    for i, prob in enumerate(probabilities):
        if prob >= threshold:
            info = conn_info[i]
            beacons.append({
                "src": info["src"],
                "dst": info["dst"],
                "port": info.get("port", "?"),
                "proto": info.get("proto", "?"),
                "confidence": round(float(prob) * 100, 1),
                "risk": _risk_level(prob),
            })

    beacons = _deduplicate_beacons(beacons)

    # Count unique connections
    unique_connections = len({
        (c["src"], c["dst"], c.get("port"), c.get("proto")) for c in conn_info
    })

    total_flagged = len(beacons)

    if total_flagged > 0:
        summary = (
            f"The LSTM beacon detection model analyzed {unique_connections} connections "
            f"and flagged **{total_flagged}** as potential C2 beacons."
        )
    else:
        summary = (
            f"The LSTM beacon detection model analyzed {unique_connections} connections "
            f"and found no beacon-like activity."
        )

    logger.info("LSTM: %d/%d connections flagged", total_flagged, unique_connections)

    return {
        "beacons": beacons,
        "total_connections": unique_connections,
        "total_flagged": total_flagged,
        "summary_text": summary,
    }


# ---------------------------------------------------------------------------
# AI prompt formatting
# ---------------------------------------------------------------------------

def format_for_prompt(lstm_results: dict) -> str:
    """Convert prediction results into a Markdown section for the LLM prompt.

    Parameters
    ----------
    lstm_results:
        The dictionary returned by :func:`predict_beacons`.

    Returns
    -------
    str
        A Markdown-formatted section ready to prepend to the AI prompt.
    """
    lines = [
        "## LSTM Beacon Detection Results",
        "",
        lstm_results["summary_text"],
    ]

    beacons = lstm_results.get("beacons", [])
    if beacons:
        # Cap at top 20 to keep the prompt focused
        top = beacons[:20]
        lines.extend([
            "",
            "| Source IP | Destination IP | Port | Proto | Confidence | Risk Level |",
            "|-----------|---------------|------|-------|------------|------------|",
        ])
        for b in top:
            lines.append(
                f"| {b['src']} | {b['dst']} | {b['port']} | {b.get('proto', '?')} "
                f"| {b['confidence']}% | {b['risk']} |"
            )
        if len(beacons) > 20:
            lines.append(f"| … | … | … | … | … | … |")
            lines.append(f"| *({len(beacons) - 20} more not shown)* |||||")

        lines.extend([
            "",
            "Please prioritize these flagged connections in your analysis. "
            "Consider whether they exhibit beaconing behavior (periodic communication "
            "patterns indicative of C2 command-and-control) and recommend specific "
            "investigation steps for any high-confidence matches.",
        ])

    return "\n".join(lines)
