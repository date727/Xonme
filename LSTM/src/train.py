"""Train the LSTM binary classifier."""
import json
import sys
from pathlib import Path

import numpy as np
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.utils.class_weight import compute_class_weight
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint


_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from config import (  # noqa: E402
    BATCH_SIZE,
    EPOCHS,
    FEATURE_COLS,
    GROUP_COLS,
    LOGS_DIR,
    METADATA_PATH,
    MODEL_PATH,
    SEQ_LENGTH,
    SORT_COL,
)
from data_prep import fit_transform_sequences, prepare_data  # noqa: E402
from model import build_lstm_model  # noqa: E402


def _split_data(X, y, groups):
    unique_groups = np.unique(groups)
    use_group_split = len(unique_groups) >= 4

    if use_group_split:
        splitter = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
        train_idx, test_idx = next(splitter.split(X, y, groups))
        X_train, X_test = X[train_idx], X[test_idx]
        y_train, y_test = y[train_idx], y[test_idx]

        if len(np.unique(y_train)) == 2 and len(np.unique(y_test)) == 2:
            return X_train, X_test, y_train, y_test, "group"

        print("Group split lost one class; falling back to stratified random split.")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    return X_train, X_test, y_train, y_test, "stratified"


def train():
    print("=" * 60)
    print("Loading data")
    print("=" * 60)
    X, y, groups = prepare_data()

    if len(X) < 20:
        print(f"Only {len(X)} sequences generated; add more data before training.")
        return None

    X_train, X_test, y_train, y_test, split_name = _split_data(X, y, groups)
    X_train, X_test, _ = fit_transform_sequences(X_train, X_test)

    print(f"Split: {split_name}")
    print(f"Train sequences: {len(X_train)}, test sequences: {len(X_test)}")
    print(f"Train labels: benign={np.sum(y_train == 0)}, cs={np.sum(y_train == 1)}")
    print(f"Test labels: benign={np.sum(y_test == 0)}, cs={np.sum(y_test == 1)}")

    model = build_lstm_model(input_shape=(SEQ_LENGTH, X.shape[2]))
    model.summary()

    class_weight_values = compute_class_weight(
        class_weight="balanced", classes=np.unique(y_train), y=y_train
    )
    class_weight = {
        int(cls): float(weight)
        for cls, weight in zip(np.unique(y_train), class_weight_values)
    }
    print(f"Class weights: {class_weight}")

    callbacks = [
        EarlyStopping(
            monitor="val_loss",
            patience=3,
            restore_best_weights=True,
            verbose=1,
        ),
        ModelCheckpoint(
            filepath=str(MODEL_PATH),
            save_best_only=True,
            monitor="val_loss",
            verbose=1,
        ),
    ]

    print("=" * 60)
    print("Training")
    print("=" * 60)
    history = model.fit(
        X_train,
        y_train,
        epochs=EPOCHS,
        batch_size=BATCH_SIZE,
        validation_split=0.2,
        class_weight=class_weight,
        callbacks=callbacks,
        verbose=1,
    )

    history_file = LOGS_DIR / "training_history.json"
    with open(history_file, "w", encoding="utf-8") as f:
        json.dump({k: [float(v) for v in vals] for k, vals in history.history.items()}, f, indent=2)
    print(f"Training history saved to {history_file}")

    metadata = {
        "feature_cols": FEATURE_COLS,
        "seq_length": SEQ_LENGTH,
        "group_cols": GROUP_COLS,
        "sort_col": SORT_COL,
        "input_shape": list(X.shape[1:]),
        "labels": {"0": "benign", "1": "cs"},
        "split": split_name,
    }
    with open(METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print(f"Model metadata saved to {METADATA_PATH}")

    print("=" * 60)
    print("Evaluation")
    print("=" * 60)
    loss, keras_acc = model.evaluate(X_test, y_test, verbose=1)
    probs = model.predict(X_test, verbose=0).ravel()
    preds = (probs >= 0.5).astype(int)

    print(f"Test loss: {loss:.4f}, Keras accuracy: {keras_acc:.4f}")
    print(f"Accuracy: {accuracy_score(y_test, preds):.4f}")
    print("Confusion matrix:")
    print(confusion_matrix(y_test, preds))
    print("Classification report:")
    print(classification_report(y_test, preds, target_names=["benign", "cs"], zero_division=0))

    return model


if __name__ == "__main__":
    train()
