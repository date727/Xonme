"""Tests for deterministic LSTM report sections."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.lstm_predictor import format_for_prompt


class LSTMReportingTests(unittest.TestCase):
    def test_no_beacon_result_is_reported_as_completed_not_absolute_safety(self):
        text = format_for_prompt({
            "threshold": 0.99,
            "total_connections": 3,
            "total_flagged": 0,
            "beacons": [],
        })
        self.assertIn("检测状态**：完成", text)
        self.assertIn("未发现达到告警阈值", text)
        self.assertIn("不构成对流量绝对安全", text)
        self.assertNotIn("达到阈值的可疑通信组数", text)

    def test_beacon_result_includes_risk_level(self):
        text = format_for_prompt({
            "threshold": 0.99,
            "total_connections": 1,
            "total_flagged": 1,
            "beacons": [{
                "src": "10.0.0.1", "dst": "203.0.113.10", "port": "443",
                "proto": "tcp", "confidence": 99.9, "risk": "Critical",
            }],
        })
        self.assertIn("Risk Level", text)
        self.assertIn("Critical", text)

    def test_unavailable_result_is_not_described_as_benign(self):
        text = format_for_prompt(None)
        self.assertIn("检测状态**：未完成", text)
        self.assertIn("不等同于流量为良性", text)


if __name__ == "__main__":
    unittest.main()
