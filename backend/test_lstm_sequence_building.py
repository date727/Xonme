"""Regression tests for full-window, batched online LSTM inference."""

import csv
import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app import lstm_predictor


class IdentityScaler:
    def transform(self, values):
        return values


class LastValueModel:
    """Give the final window a high score and record actual batch sizes."""

    def __init__(self):
        self.batch_sizes = []

    def predict(self, values, verbose=0):
        self.batch_sizes.append(len(values))
        scores = np.full(len(values), 0.01, dtype=np.float32)
        scores[np.max(values[:, :, 0], axis=1) >= 219] = 0.999
        return scores.reshape(-1, 1)


def feature_csv(row_count=220):
    output = io.StringIO()
    fields = [
        "source_file", "src_ip", "dst_ip", "dst_port", "ip_protocol",
        "start_time", "feature",
    ]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for index in range(row_count):
        writer.writerow({
            "source_file": "capture.pcap", "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2", "dst_port": "443", "ip_protocol": "tcp",
            "start_time": index, "feature": index,
        })
    return output.getvalue()


class LSTMSequenceBuildingTests(unittest.TestCase):
    def setUp(self):
        self.model = LastValueModel()
        self.metadata = {
            "feature_cols": ["feature"], "seq_length": 10,
            "group_cols": ["source_file", "src_ip", "dst_ip", "dst_port", "ip_protocol"],
            "sort_col": "start_time",
            # This is audit-only training metadata and must never cap online inference.
            "training_window_sampling": {
                "max_windows_per_group": 1,
                "strategy": "uniform",
            },
        }
        self.patches = [
            patch.object(lstm_predictor, "_load_artifacts", return_value=True),
            patch.object(lstm_predictor, "_metadata", self.metadata),
            patch.object(lstm_predictor, "_scaler", IdentityScaler()),
            patch.object(lstm_predictor, "_keras_model", self.model),
        ]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()

    def test_all_windows_are_evaluated_in_bounded_batches(self):
        result = lstm_predictor.predict_beacons(
            feature_csv(), threshold="0.99", batch_size=32
        )
        self.assertEqual(result["total_windows"], 211)
        self.assertEqual(sum(self.model.batch_sizes), 211)
        self.assertTrue(all(size <= 32 for size in self.model.batch_sizes))
        self.assertGreater(len(self.model.batch_sizes), 1)

    def test_high_risk_window_after_first_200_is_not_missed(self):
        result = lstm_predictor.predict_beacons(
            feature_csv(), threshold=0.99, batch_size=32
        )
        self.assertEqual(result["total_flagged"], 1)
        self.assertEqual(result["beacons"][0]["confidence"], 99.9)

    def test_invalid_thresholds_are_rejected(self):
        for value in ("not-a-number", -0.1, 1.1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                lstm_predictor.predict_beacons(feature_csv(10), threshold=value)

    def test_non_positive_batch_size_is_rejected(self):
        with self.assertRaises(ValueError):
            list(lstm_predictor._iter_sequence_batches([], ["feature"], 10, 0))


if __name__ == "__main__":
    unittest.main()
