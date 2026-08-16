"""Regression tests for protocol-safe RITA/LSTM threat merging."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.threat_feature_merger import merge_threat_features


class ThreatFeatureMergerTests(unittest.TestCase):
    def test_same_endpoint_different_protocols_are_not_merged(self):
        rita = [{
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "dst_port": "53",
            "protocol": "udp",
            "threat_category": "medium",
        }]
        lstm = {"beacons": [{
            "src": "10.0.0.1",
            "dst": "10.0.0.2",
            "port": "53",
            "proto": "tcp",
            "confidence": 99.0,
            "risk": "Critical",
        }]}

        merged = merge_threat_features(rita, lstm)

        self.assertEqual(len(merged), 2)
        self.assertEqual({item["protocol"] for item in merged}, {"tcp", "udp"})

    def test_missing_rita_protocol_remains_backward_compatible(self):
        rita = [{
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "dst_port": "443",
            "threat_category": "medium",
        }]
        lstm = {"beacons": [{
            "src": "10.0.0.1",
            "dst": "10.0.0.2",
            "port": "443",
            "proto": "tcp",
            "confidence": 99.0,
            "risk": "Critical",
        }]}

        merged = merge_threat_features(rita, lstm)

        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["detection_sources"], ["RITA", "LSTM"])
        self.assertEqual(merged[0]["protocol"], "tcp")

    def test_lstm_critical_promotes_existing_rita_low_risk(self):
        rita = [{
            "src_ip": "192.168.56.5",
            "dst_ip": "192.168.56.4",
            "dst_port": "80",
            "protocol": "tcp",
            "threat_category": "low",
        }]
        lstm = {"beacons": [{
            "src": "192.168.56.5",
            "dst": "192.168.56.4",
            "port": "80",
            "proto": "tcp",
            "confidence": 100.0,
            "risk": "Critical",
        }]}

        merged = merge_threat_features(rita, lstm)

        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["threat_category"], "high")
        self.assertEqual(merged[0]["lstm_risk"], "Critical")


if __name__ == "__main__":
    unittest.main()
