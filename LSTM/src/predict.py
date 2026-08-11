"""Predict one CSV or batch-validate the training CSV folders."""
import json
import sys
from pathlib import Path

import numpy as np
from tensorflow.keras.models import load_model as keras_load_model


_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from config import (  # noqa: E402
    BENIGN_DIR,
    FEATURE_COLS,
    MALICIOUS_DIR,
    METADATA_PATH,
    MODEL_PATH,
    SEQ_LENGTH,
)
from data_prep import load_scaler, prepare_single_csv  # noqa: E402


def load_model():
    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"Model not found at {MODEL_PATH}. Train the model first.")
    return keras_load_model(str(MODEL_PATH))


def predict_csv(csv_path, model=None, scaler=None, verbose=True):
    csv_path = Path(csv_path)
    if not csv_path.exists():
        raise FileNotFoundError(f"CSV not found: {csv_path}")

    if model is None:
        model = load_model()
    if scaler is None:
        scaler = load_scaler()

    X = prepare_single_csv(csv_path, scaler, seq_length=SEQ_LENGTH, feature_cols=FEATURE_COLS)

    probs = model.predict(X, verbose=0).ravel()
    predictions = (probs >= 0.5).astype(int)
    mean_prob = float(np.mean(probs))
    malicious_ratio = float(np.mean(predictions))
    predicted_label = 1 if malicious_ratio >= 0.5 else 0
    verdict = "CS" if predicted_label == 1 else "BENIGN"

    if verbose:
        print(f"CSV: {csv_path}")
        print(f"Sequences: {len(X)}, shape: {X.shape[1:]}")
        print(f"Mean CS probability: {mean_prob:.4f}")
        print(f"CS sequence ratio: {malicious_ratio:.2%} ({int(np.sum(predictions))}/{len(predictions)})")
        print(f"Verdict: {verdict}")

        if METADATA_PATH.exists():
            with open(METADATA_PATH, "r", encoding="utf-8") as f:
                metadata = json.load(f)
            print(f"Model features: {len(metadata.get('feature_cols', []))}")

    return {
        "csv_path": str(csv_path),
        "sequence_count": int(len(X)),
        "mean_prob": mean_prob,
        "cs_sequence_ratio": malicious_ratio,
        "cs_sequence_count": int(np.sum(predictions)),
        "predicted_label": predicted_label,
        "verdict": verdict,
        "sequence_predictions": predictions,
        "sequence_probabilities": probs,
    }


def validate_training_set():
    """Run prediction on every CSV under csv_comb/benign and csv_comb/cs."""
    model = load_model()
    scaler = load_scaler()

    csv_items = (
        [(path, 0) for path in sorted(BENIGN_DIR.glob("*.csv"))]
        + [(path, 1) for path in sorted(MALICIOUS_DIR.glob("*.csv"))]
    )
    if not csv_items:
        raise FileNotFoundError(f"No CSV files found in {BENIGN_DIR} or {MALICIOUS_DIR}")

    rows = []
    true_file_labels = []
    pred_file_labels = []
    true_sequence_labels = []
    pred_sequence_labels = []

    print("=" * 100)
    print("Batch validation on training CSV folders")
    print("=" * 100)
    print(f"{'expected':<8} {'pred':<6} {'ok':<3} {'seq':>6} {'mean_prob':>10} {'cs_ratio':>9}  file")

    skipped = []
    for csv_path, expected_label in csv_items:
        try:
            result = predict_csv(csv_path, model=model, scaler=scaler, verbose=False)
        except ValueError as exc:
            expected_name = "CS" if expected_label == 1 else "BENIGN"
            reason = str(exc)
            skipped.append({"file": csv_path.name, "expected": expected_name, "reason": reason})
            print(
                f"{expected_name:<8} {'SKIP':<6} {'-':<3} "
                f"{0:>6} {'-':>10} {'-':>9}  {csv_path.name}  ({reason})"
            )
            continue

        predicted_label = result["predicted_label"]
        ok = predicted_label == expected_label

        true_file_labels.append(expected_label)
        pred_file_labels.append(predicted_label)
        true_sequence_labels.extend([expected_label] * result["sequence_count"])
        pred_sequence_labels.extend(result["sequence_predictions"].tolist())

        expected_name = "CS" if expected_label == 1 else "BENIGN"
        pred_name = "CS" if predicted_label == 1 else "BENIGN"
        ok_name = "yes" if ok else "no"

        print(
            f"{expected_name:<8} {pred_name:<6} {ok_name:<3} "
            f"{result['sequence_count']:>6} {result['mean_prob']:>10.4f} "
            f"{result['cs_sequence_ratio']:>8.2%}  {csv_path.name}"
        )

        rows.append(
            {
                "file": csv_path.name,
                "expected": expected_name,
                "predicted": pred_name,
                "correct": ok,
                "sequence_count": result["sequence_count"],
                "mean_prob": result["mean_prob"],
                "cs_sequence_ratio": result["cs_sequence_ratio"],
            }
        )

    if not rows:
        raise ValueError("No CSV files generated sequences; nothing to validate.")

    true_file_labels = np.asarray(true_file_labels)
    pred_file_labels = np.asarray(pred_file_labels)
    true_sequence_labels = np.asarray(true_sequence_labels)
    pred_sequence_labels = np.asarray(pred_sequence_labels)

    file_accuracy = float(np.mean(true_file_labels == pred_file_labels))
    sequence_accuracy = float(np.mean(true_sequence_labels == pred_sequence_labels))
    file_confusion = _confusion_counts(true_file_labels, pred_file_labels)
    sequence_confusion = _confusion_counts(true_sequence_labels, pred_sequence_labels)

    print("=" * 100)
    print("Summary")
    print(f"Validated files: {len(rows)}")
    print(f"Skipped files: {len(skipped)}")
    print(f"File-level accuracy: {file_accuracy:.4f}")
    print(f"Sequence-level accuracy: {sequence_accuracy:.4f}")
    print("File-level confusion matrix [[benign->benign, benign->cs], [cs->benign, cs->cs]]:")
    print(file_confusion)
    print("Sequence-level confusion matrix [[benign->benign, benign->cs], [cs->benign, cs->cs]]:")
    print(sequence_confusion)
    if skipped:
        print("Skipped files:")
        for item in skipped:
            print(f"  {item['expected']:<8} {item['file']}: {item['reason']}")
    print("=" * 100)

    return rows, skipped


def _confusion_counts(y_true, y_pred):
    matrix = np.zeros((2, 2), dtype=int)
    for true_label, pred_label in zip(y_true, y_pred):
        matrix[int(true_label), int(pred_label)] += 1
    return matrix


if __name__ == "__main__":
    try:
        if len(sys.argv) >= 2:
            predict_csv(sys.argv[1])
        else:
            validate_training_set()
    except Exception as exc:
        print(f"Error: {exc}")
        sys.exit(1)
