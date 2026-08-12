"""Load explicit train/validation/test feature CSVs and create LSTM samples."""
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from pandas.errors import EmptyDataError

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from config import FEATURE_COLS, FEATURE_DATA_DIR, GROUP_COLS, MAX_WINDOWS_PER_GROUP, SCALER_PATH, SEQ_LENGTH, SORT_COL, SPLITS


def _validate_columns(df: pd.DataFrame, labeled: bool = True) -> None:
    required = set(FEATURE_COLS + GROUP_COLS + [SORT_COL])
    if labeled:
        required.add("label")
    missing = sorted(required - set(df.columns))
    if missing:
        raise KeyError(f"Feature CSV missing required columns: {missing}")


def _clean(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    for column in FEATURE_COLS:
        df[column] = pd.to_numeric(df[column], errors="coerce")
    df[FEATURE_COLS] = df[FEATURE_COLS].fillna(df[FEATURE_COLS].median(numeric_only=True)).fillna(0.0)
    return df


def load_split(split: str) -> pd.DataFrame:
    if split not in SPLITS:
        raise ValueError(f"Unknown split {split!r}; expected one of {SPLITS}")
    split_dir = FEATURE_DATA_DIR / split
    files = sorted(split_dir.glob("*.csv"))
    if not files:
        raise FileNotFoundError(f"No generated feature CSV files in {split_dir}. Run prepare_pcap_dataset.py first.")
    frames = []
    for path in files:
        # A PCAP without TCP packets produces an intentionally empty derived
        # CSV. It is retained for coverage reporting but cannot be a sample.
        if path.stat().st_size == 0:
            continue
        try:
            frame = pd.read_csv(path)
        except EmptyDataError:
            continue
        if frame.empty:
            continue
        _validate_columns(frame)
        frames.append(frame)
    if not frames:
        raise ValueError(f"No non-empty feature CSV files in {split_dir}.")
    return _clean(pd.concat(frames, ignore_index=True))


def build_sequences(
    df: pd.DataFrame,
    seq_length: int = SEQ_LENGTH,
    max_windows_per_group: int = MAX_WINDOWS_PER_GROUP,
):
    """Build windows only within one PCAP and one canonical communication group."""
    _validate_columns(df, labeled="label" in df.columns)
    has_labels = "label" in df.columns
    X: list[np.ndarray] = []
    y: list[int] = []
    group_keys: list[str] = []
    window_metadata: list[dict[str, object]] = []
    stats = {"groups": 0, "short_groups": 0, "mixed_label_windows": 0, "capped_windows": 0}

    for key, group in df.groupby(GROUP_COLS, sort=False, dropna=False):
        stats["groups"] += 1
        group = group.sort_values(SORT_COL, kind="mergesort")
        if len(group) < seq_length:
            stats["short_groups"] += 1
            continue
        labels = group["label"].to_numpy(dtype=np.int64) if has_labels else None
        features = group[FEATURE_COLS].to_numpy(dtype=np.float32)
        group_id = "|".join(map(str, key))
        window_count = len(group) - seq_length + 1
        selected_starts = range(window_count)
        if max_windows_per_group and window_count > max_windows_per_group:
            # Evenly sample across the whole capture rather than retaining only
            # its beginning. The group itself never crosses data splits.
            selected_starts = np.linspace(0, window_count - 1, max_windows_per_group, dtype=int)
            stats["capped_windows"] += window_count - max_windows_per_group
        for start in selected_starts:
            end = start + seq_length
            if labels is not None and len(np.unique(labels[start:end])) != 1:
                stats["mixed_label_windows"] += 1
                continue
            X.append(features[start:end])
            y.append(int(labels[start]) if labels is not None else 0)
            group_keys.append(group_id)
            first = group.iloc[start]
            last = group.iloc[end - 1]
            window_metadata.append({
                "source_file": str(first["source_file"]), "src_ip": str(first["src_ip"]),
                "dst_ip": str(first["dst_ip"]), "dst_port": str(first["dst_port"]),
                "ip_protocol": str(first["ip_protocol"]), "window_start_time": float(first[SORT_COL]),
                "window_end_time": float(last[SORT_COL]), "flow_gap": float(first["flow_gap"]),
                "gap_rolling_cv": float(first["gap_rolling_cv"]),
            })
    if not X:
        raise ValueError(f"No usable sequences. Statistics: {stats}")
    return np.asarray(X, dtype=np.float32), np.asarray(y, dtype=np.int64), np.asarray(group_keys), window_metadata, stats


def load_all_splits():
    prepared = {}
    for split in SPLITS:
        df = load_split(split)
        X, y, groups, metadata, stats = build_sequences(df)
        prepared[split] = (X, y, groups, metadata, stats)
        print(f"{split}: rows={len(df)}, sequences={len(X)}, benign={int((y == 0).sum())}, malicious={int((y == 1).sum())}, {stats}")
    return prepared


def fit_scaler(X_train: np.ndarray) -> StandardScaler:
    scaler = StandardScaler()
    scaler.fit(X_train.reshape(-1, X_train.shape[-1]))
    joblib.dump(scaler, SCALER_PATH)
    return scaler


def scale_sequences(X: np.ndarray, scaler: StandardScaler) -> np.ndarray:
    return scaler.transform(X.reshape(-1, X.shape[-1])).reshape(X.shape)


def load_scaler():
    if not SCALER_PATH.exists():
        raise FileNotFoundError(f"Scaler not found at {SCALER_PATH}; train the model first.")
    return joblib.load(SCALER_PATH)
