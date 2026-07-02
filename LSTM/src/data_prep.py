"""Data loading and sequence preparation for ARES/Zeek CSV files."""
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler


_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from config import (  # noqa: E402
    BENIGN_DIR,
    FEATURE_COLS,
    GROUP_COLS,
    MALICIOUS_DIR,
    SCALER_PATH,
    SEQ_LENGTH,
    SORT_COL,
)


def _read_csv(csv_path: Path, label: int | None = None) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    df["source_file"] = csv_path.name
    if label is not None:
        df["label"] = label
    return df


def _fill_missing_values(df: pd.DataFrame, feature_cols=FEATURE_COLS) -> pd.DataFrame:
    df = df.copy()
    for col in feature_cols:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    df[feature_cols] = df[feature_cols].fillna(df[feature_cols].median(numeric_only=True))
    df[feature_cols] = df[feature_cols].fillna(0)
    return df


def _validate_columns(df: pd.DataFrame, feature_cols=FEATURE_COLS, for_training=True) -> None:
    required = set(feature_cols + GROUP_COLS + [SORT_COL])
    if for_training:
        required.add("label")
    missing = sorted(required - set(df.columns))
    if missing:
        raise KeyError(f"CSV missing required columns: {missing}")


def load_data() -> pd.DataFrame:
    """Load all training CSV files and assign labels from directory names."""
    dfs = []

    benign_files = sorted(BENIGN_DIR.glob("*.csv"))
    if not benign_files:
        raise FileNotFoundError(f"No benign CSV files found in {BENIGN_DIR}")
    for csv_path in benign_files:
        dfs.append(_read_csv(csv_path, label=0))

    malicious_files = sorted(MALICIOUS_DIR.glob("*.csv"))
    if not malicious_files:
        raise FileNotFoundError(f"No Cobalt Strike CSV files found in {MALICIOUS_DIR}")
    for csv_path in malicious_files:
        dfs.append(_read_csv(csv_path, label=1))

    combined = pd.concat(dfs, ignore_index=True)
    _validate_columns(combined, for_training=True)
    return _fill_missing_values(combined)


def build_sequences(df: pd.DataFrame, seq_length=SEQ_LENGTH, feature_cols=FEATURE_COLS):
    """
    Build sliding-window LSTM samples.

    Rows are grouped by source file and service-level communication tuple, then
    ordered by start_time. source_file is part of the group key so sequences do
    not cross capture files.
    """
    _validate_columns(df, feature_cols=feature_cols, for_training="label" in df.columns)

    X, y, groups = [], [], []
    has_labels = "label" in df.columns
    grouped = df.groupby(GROUP_COLS, sort=False, dropna=False)

    for group_id, (_, group) in enumerate(grouped):
        group = group.sort_values(SORT_COL, kind="mergesort")
        features = group[feature_cols].to_numpy(dtype=np.float32)

        n_rows = len(features)
        if n_rows < seq_length:
            continue

        labels = group["label"].to_numpy() if has_labels else None
        for start in range(n_rows - seq_length + 1):
            end = start + seq_length
            X.append(features[start:end])
            if has_labels:
                y.append(1 if np.mean(labels[start:end]) > 0.5 else 0)
            else:
                y.append(0)
            groups.append(group_id)

    if not X:
        raise ValueError(
            f"No sequences generated. Each group needs at least {seq_length} rows. "
            f"Current group count: {df.groupby(GROUP_COLS, dropna=False).ngroups}"
        )

    return np.asarray(X, dtype=np.float32), np.asarray(y, dtype=np.int64), np.asarray(groups)


def prepare_data():
    """Load training data and return unscaled X, y, groups."""
    df = load_data()
    group_count = df.groupby(GROUP_COLS, dropna=False).ngroups
    print(f"Rows: {len(df)}, groups: {group_count}")

    X, y, groups = build_sequences(df)
    print(f"Sequences: {len(X)}, sequence shape: {X.shape[1:]}")
    print(f"Labels: benign={np.sum(y == 0)}, cs={np.sum(y == 1)}")
    return X, y, groups


def fit_transform_sequences(X_train: np.ndarray, X_test: np.ndarray):
    """Fit a StandardScaler on training sequences and transform train/test."""
    scaler = StandardScaler()

    train_shape = X_train.shape
    test_shape = X_test.shape
    X_train_scaled = scaler.fit_transform(X_train.reshape(-1, X_train.shape[-1])).reshape(train_shape)
    X_test_scaled = scaler.transform(X_test.reshape(-1, X_test.shape[-1])).reshape(test_shape)

    joblib.dump(scaler, SCALER_PATH)
    print(f"Scaler saved to {SCALER_PATH}")
    return X_train_scaled, X_test_scaled, scaler


def load_scaler():
    if not SCALER_PATH.exists():
        raise FileNotFoundError(f"Scaler not found at {SCALER_PATH}. Train the model first.")
    return joblib.load(SCALER_PATH)


def prepare_single_csv(csv_path, scaler, seq_length=SEQ_LENGTH, feature_cols=FEATURE_COLS):
    """Prepare one CSV for prediction using the saved scaler."""
    csv_path = Path(csv_path)
    df = _read_csv(csv_path)
    _validate_columns(df, feature_cols=feature_cols, for_training=False)
    df = _fill_missing_values(df, feature_cols=feature_cols)

    X, _, _ = build_sequences(df, seq_length=seq_length, feature_cols=feature_cols)
    original_shape = X.shape
    return scaler.transform(X.reshape(-1, X.shape[-1])).reshape(original_shape)


if __name__ == "__main__":
    X, y, groups = prepare_data()
    print(f"X shape: {X.shape}, y shape: {y.shape}, unique groups: {len(np.unique(groups))}")
