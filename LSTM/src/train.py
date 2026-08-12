"""Reproducible repeated training for the all-TCP C2 beacon LSTM.

Five pre-declared random seeds are trained on the same manifest-defined splits.
Validation data alone selects the deployment model and its threshold.  The
sealed test split is evaluated for every independent run only to report
stability (mean +/- standard deviation), never to choose a model.
"""
import json
import shutil
import sys
from pathlib import Path
import argparse

import numpy as np
import tensorflow as tf
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.utils.class_weight import compute_class_weight
from tensorflow.keras import backend as keras_backend
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from config import (
    BATCH_SIZE, C2_CLASS_WEIGHT_MULTIPLIER, EPOCHS, FEATURE_COLS, GROUP_COLS, LOGS_DIR, MAX_VALIDATION_FPR,
    METADATA_PATH, MODEL_PATH, RUN_SEEDS, SEQ_LENGTH, SORT_COL, TARGET_RECALL,
    THRESHOLD_PATH,
)
from data_prep import fit_scaler, load_all_splits, scale_sequences
from model import build_lstm_model


def _evaluate(y_true: np.ndarray, probabilities: np.ndarray, threshold: float) -> dict:
    predictions = (probabilities >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, predictions, labels=[0, 1]).ravel()
    recall = float(tp / (tp + fn)) if tp + fn else 0.0
    fpr = float(fp / (fp + tn)) if fp + tn else 0.0
    precision = float(tp / (tp + fp)) if tp + fp else 0.0
    f1 = float(2 * precision * recall / (precision + recall)) if precision + recall else 0.0
    return {
        "threshold": float(threshold), "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "recall": recall, "fpr": fpr, "precision": precision, "f1": f1,
    }


def _aggregate_groups(y_true: np.ndarray, probabilities: np.ndarray, groups: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Use max window score as the operational C2 communication-group score."""
    grouped: dict[str, list[int]] = {}
    for index, group in enumerate(groups):
        grouped.setdefault(str(group), []).append(index)
    group_labels, group_probabilities = [], []
    for indexes in grouped.values():
        labels = np.unique(y_true[indexes])
        if len(labels) != 1:
            raise ValueError("A communication group contains mixed labels; it cannot be evaluated safely.")
        group_labels.append(int(labels[0]))
        group_probabilities.append(float(np.max(probabilities[indexes])))
    return np.asarray(group_labels, dtype=np.int64), np.asarray(group_probabilities, dtype=np.float32)


def _choose_threshold(y_true: np.ndarray, probabilities: np.ndarray) -> tuple[float, dict]:
    """Choose a threshold from validation results only.

    Among thresholds satisfying Recall >= 98% and FPR <= 5%, select the
    highest threshold.  If that target is infeasible, prefer recall, then lower
    FPR, then the higher threshold.  This fallback is recorded explicitly.
    """
    candidates: list[tuple[float, dict]] = []
    for threshold in np.unique(np.r_[0.0, probabilities, 1.0]):
        candidates.append((float(threshold), _evaluate(y_true, probabilities, float(threshold))))
    feasible = [(threshold, metric) for threshold, metric in candidates if metric["recall"] >= TARGET_RECALL and metric["fpr"] <= MAX_VALIDATION_FPR]
    if feasible:
        threshold, metric = max(feasible, key=lambda item: item[0])
        selection = {"target_recall_met": True, "target_fpr_met": True, "selection_mode": "constraints_met"}
    else:
        threshold, metric = max(candidates, key=lambda item: (item[1]["recall"], -item[1]["fpr"], item[0]))
        selection = {
            "target_recall_met": metric["recall"] >= TARGET_RECALL,
            "target_fpr_met": metric["fpr"] <= MAX_VALIDATION_FPR,
            "selection_mode": "recall_then_fpr_fallback",
        }
    return threshold, {**selection, "validation_recall": metric["recall"], "validation_fpr": metric["fpr"]}


def _selection_key(run: dict) -> tuple:
    """Pre-registered deployment criterion; no test result is included."""
    val = run["validation_windows"]
    targets_met = int(val["recall"] >= TARGET_RECALL and val["fpr"] <= MAX_VALIDATION_FPR)
    return (targets_met, val["recall"], -val["fpr"], val["f1"], -run["best_val_loss"], run["seed"])


def _summary(runs: list[dict], section: str = "test_groups") -> dict:
    return {
        metric: {
            "mean": float(np.mean([run[section][metric] for run in runs])),
            "std": float(np.std([run[section][metric] for run in runs], ddof=1)) if len(runs) > 1 else 0.0,
        }
        for metric in ("recall", "fpr", "precision", "f1")
    }


def _print_final_report(final_run: dict, stability: dict) -> None:
    print("=" * 72)


def finalize_existing_runs() -> dict:
    """Select a deployment artifact from individually completed seed runs.

    This supports long data-preparation/training jobs being executed one seed
    at a time without changing the validation-only model-selection rule.
    """
    seed_report_dir = LOGS_DIR / "seed_runs"
    runs = [json.loads(path.read_text(encoding="utf-8")) for path in sorted(seed_report_dir.glob("seed_*.json"))]
    if not runs:
        raise FileNotFoundError(f"No seed reports found under {seed_report_dir}")
    selected = max(runs, key=_selection_key)
    shutil.copy2(_PROJECT_ROOT / selected["candidate_model"], MODEL_PATH)
    group_stability = _summary(runs)
    window_stability = _summary(runs, "test_windows")
    report = {
        "selection_policy": "validation_only: constraints(recall>=0.98,fpr<=0.05), then recall, lower FPR, F1, lower val_loss",
        "seeds": [run["seed"] for run in runs], "runs": runs,
        "selected_seed": selected["seed"], "selected_validation_windows": selected["validation_windows"],
        "selected_validation_groups": selected["validation_groups"], "selected_test_groups": selected["test_groups"],
        "selected_test_windows": selected["test_windows"], "test_group_stability": group_stability,
        "test_window_stability": window_stability,
    }
    (LOGS_DIR / "repeated_training_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (LOGS_DIR / "evaluation.json").write_text(json.dumps({
        "validation_windows": selected["validation_windows"], "validation_groups": selected["validation_groups"],
        "test_windows": selected["test_windows"], "test_groups": selected["test_groups"],
        "test_group_stability": group_stability, "test_window_stability": window_stability,
    }, indent=2), encoding="utf-8")
    THRESHOLD_PATH.write_text(json.dumps({
        "threshold": selected["validation_windows"]["threshold"], "selected_on": "validation_window",
        "target_recall": TARGET_RECALL, "maximum_fpr": MAX_VALIDATION_FPR,
        "c2_class_weight_multiplier": C2_CLASS_WEIGHT_MULTIPLIER,
        **selected["threshold_selection"], "selected_seed": selected["seed"],
    }, indent=2), encoding="utf-8")
    METADATA_PATH.write_text(json.dumps({
        "feature_cols": FEATURE_COLS, "seq_length": SEQ_LENGTH, "group_cols": GROUP_COLS,
        "sort_col": SORT_COL, "input_shape": [SEQ_LENGTH, len(FEATURE_COLS)],
        "labels": {"0": "benign", "1": "c2"}, "scope": "all_tcp_connection_beacon",
        "selected_seed": selected["seed"],
        "selection_policy": report["selection_policy"],
    }, indent=2), encoding="utf-8")
    print(f"Finalized validation-selected seed={selected['seed']}; test-window recall={selected['test_windows']['recall']:.4f}")
    return report
    print(f"Deployment run selected ONLY by validation: seed={final_run['seed']}")
    print(f"Validation communication groups: {final_run['validation_groups']}")
    print(f"Sealed test communication groups: {final_run['test_groups']}")
    print(f"Sealed test windows: {final_run['test_windows']}")
    print("Repeated group-level test stability (mean +/- sample std; not selection criterion):")
    for metric, values in stability.items():
        print(f"  {metric}: {values['mean']:.4f} +/- {values['std']:.4f}")
    print("Classification report for validation-selected model on the sealed test split:")
    print(classification_report(final_run["test_group_labels"], final_run["test_group_predictions"], target_names=["benign", "c2"], zero_division=0))
    print("=" * 72)


def train(seeds: tuple[int, ...] = RUN_SEEDS) -> dict:
    datasets = load_all_splits()
    X_train, y_train, train_groups, _, _ = datasets["train"]
    X_val, y_val, val_groups, _, _ = datasets["val"]
    X_test, y_test, test_groups, test_metadata, _ = datasets["test"]
    for name, labels in (("train", y_train), ("val", y_val), ("test", y_test)):
        if len(np.unique(labels)) != 2:
            raise ValueError(f"{name} split must contain both classes; found {np.unique(labels).tolist()}")

    scaler = fit_scaler(X_train)
    X_train, X_val, X_test = (scale_sequences(X, scaler) for X in (X_train, X_val, X_test))
    weights = compute_class_weight(class_weight="balanced", classes=np.unique(y_train), y=y_train)
    class_weight = {int(label): float(weight) for label, weight in zip(np.unique(y_train), weights)}
    class_weight[1] *= C2_CLASS_WEIGHT_MULTIPLIER
    print(f"Class weights (balanced baseline): {class_weight}")
    candidate_dir = LOGS_DIR / "candidate_models"
    candidate_dir.mkdir(exist_ok=True)
    all_runs: list[dict] = []

    for seed in seeds:
        print(f"\n{'=' * 20} run seed={seed} {'=' * 20}")
        keras_backend.clear_session()
        tf.keras.utils.set_random_seed(seed)
        try:
            tf.config.experimental.enable_op_determinism()
        except (AttributeError, RuntimeError):
            pass
        candidate_path = candidate_dir / f"beacon_lstm_seed_{seed}.keras"
        model = build_lstm_model(input_shape=(SEQ_LENGTH, len(FEATURE_COLS)))
        history = model.fit(
            X_train, y_train, validation_data=(X_val, y_val), epochs=EPOCHS,
            batch_size=BATCH_SIZE, class_weight=class_weight,
            callbacks=[
                EarlyStopping(monitor="val_loss", patience=4, restore_best_weights=True, verbose=1),
                ModelCheckpoint(filepath=str(candidate_path), save_best_only=True, monitor="val_loss", verbose=0),
            ],
            # Epoch-level output keeps unattended batch runs compact and avoids
            # terminal-output timeouts; it does not change optimization.
            verbose=2,
        )
        val_probs = model.predict(X_val, verbose=0).ravel()
        threshold, threshold_selection = _choose_threshold(y_val, val_probs)
        test_probs = model.predict(X_test, verbose=0).ravel()
        val_group_y, val_group_probs = _aggregate_groups(y_val, val_probs, val_groups)
        test_group_y, test_group_probs = _aggregate_groups(y_test, test_probs, test_groups)
        val_metrics = _evaluate(val_group_y, val_group_probs, threshold)
        test_metrics = _evaluate(test_group_y, test_group_probs, threshold)
        val_window_metrics = _evaluate(y_val, val_probs, threshold)
        test_window_metrics = _evaluate(y_test, test_probs, threshold)
        run = {
            "seed": seed, "candidate_model": str(candidate_path.relative_to(_PROJECT_ROOT)),
            "best_val_loss": float(min(history.history["val_loss"])),
            "epochs_completed": len(history.history["loss"]), "threshold_selection": threshold_selection,
            "validation_groups": val_metrics, "test_groups": test_metrics,
            "validation_windows": val_window_metrics, "test_windows": test_window_metrics,
            "history": {key: [float(value) for value in values] for key, values in history.history.items()},
            # Retained only in memory, so the final report can explain its test outcome.
            "test_group_labels": test_group_y, "test_group_predictions": (test_group_probs >= threshold).astype(int),
            "test_metadata": test_metadata, "test_probabilities": test_probs,
        }
        print(f"seed={seed}: validation={val_metrics}; test={test_metrics}")
        all_runs.append(run)

    selected = max(all_runs, key=_selection_key)
    shutil.copy2(_PROJECT_ROOT / selected["candidate_model"], MODEL_PATH)
    stability = _summary(all_runs)
    window_stability = _summary(all_runs, "test_windows")
    false_negatives = []
    for index, (label, prediction) in enumerate(zip(y_test, (selected["test_probabilities"] >= selected["validation_windows"]["threshold"]).astype(int))):
        if label == 1 and prediction == 0:
            false_negatives.append({**selected["test_metadata"][index], "probability": float(selected["test_probabilities"][index])})
    serializable_runs = [{key: value for key, value in run.items() if key not in {"test_group_labels", "test_group_predictions", "test_metadata", "test_probabilities"}} for run in all_runs]
    report = {
        "selection_policy": "validation_only: constraints(recall>=0.98,fpr<=0.05), then recall, lower FPR, F1, lower val_loss",
        "seeds": list(seeds), "runs": serializable_runs,
        "selected_seed": selected["seed"], "selected_validation_windows": selected["validation_windows"], "selected_validation_groups": selected["validation_groups"],
        "selected_test_groups": selected["test_groups"], "selected_test_windows": selected["test_windows"],
        "test_group_stability": stability, "test_window_stability": window_stability,
    }
    (LOGS_DIR / "repeated_training_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    seed_report_dir = LOGS_DIR / "seed_runs"
    seed_report_dir.mkdir(exist_ok=True)
    for run in serializable_runs:
        (seed_report_dir / f"seed_{run['seed']}.json").write_text(json.dumps(run, indent=2), encoding="utf-8")
    import pandas as pd
    pd.DataFrame(false_negatives).to_csv(LOGS_DIR / "test_false_negative_windows.csv", index=False)
    (LOGS_DIR / "training_history.json").write_text(json.dumps(selected["history"], indent=2), encoding="utf-8")
    (LOGS_DIR / "evaluation.json").write_text(json.dumps({"validation_groups": selected["validation_groups"], "test_groups": selected["test_groups"], "test_windows": selected["test_windows"], "test_group_stability": stability, "test_window_stability": window_stability}, indent=2), encoding="utf-8")
    THRESHOLD_PATH.write_text(json.dumps({"threshold": selected["validation_windows"]["threshold"], "selected_on": "validation_window", "target_recall": TARGET_RECALL, "maximum_fpr": MAX_VALIDATION_FPR, "c2_class_weight_multiplier": C2_CLASS_WEIGHT_MULTIPLIER, **selected["threshold_selection"], "selected_seed": selected["seed"]}, indent=2), encoding="utf-8")
    metadata = {
        "feature_cols": FEATURE_COLS, "seq_length": SEQ_LENGTH, "group_cols": GROUP_COLS,
        "sort_col": SORT_COL, "input_shape": [SEQ_LENGTH, len(FEATURE_COLS)],
        "labels": {"0": "benign", "1": "c2"}, "scope": "all_tcp_connection_beacon",
        "selected_seed": selected["seed"],
        "selection_policy": report["selection_policy"],
    }
    METADATA_PATH.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    _print_final_report(selected, stability)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Repeated, validation-selected C2 LSTM training")
    parser.add_argument("--seeds", type=int, nargs="+", default=list(RUN_SEEDS), help="Pre-registered random seed(s) to run")
    parser.add_argument("--finalize", action="store_true", help="Select the deployment model from saved per-seed reports")
    args = parser.parse_args()
    finalize_existing_runs() if args.finalize else train(tuple(args.seeds))
