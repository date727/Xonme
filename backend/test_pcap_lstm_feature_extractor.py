"""Unit tests for all-TCP LSTM timing feature calculation."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.pcap_lstm_feature_extractor import (
    _Connection,
    _add_flow_features,
    _packet_iat_features,
    _should_start_new_connection,
)


class IatFeatureTests(unittest.TestCase):
    def test_uses_real_adjacent_timestamp_deltas(self):
        features = _packet_iat_features([10.0, 10.2, 11.0, 11.5])
        self.assertAlmostEqual(features["packet_iat_min"], 0.2)
        self.assertAlmostEqual(features["packet_iat_max"], 0.8)
        self.assertAlmostEqual(features["packet_iat_mean"], 0.5)
        self.assertAlmostEqual(features["packet_iat_stddev"], (0.06) ** 0.5)
        self.assertAlmostEqual(features["packet_iat_0"], 0.2)
        self.assertAlmostEqual(features["packet_iat_1"], 0.8)
        self.assertAlmostEqual(features["packet_iat_2"], 0.5)
        self.assertEqual(features["packet_iat_3"], 0.0)

    def test_connection_gap_does_not_cross_groups(self):
        base = {"source_file": "a", "src_ip": "1", "dst_ip": "2", "dst_port": 9001, "ip_protocol": "tcp"}
        rows = [dict(base, start_time=10.0), dict(base, start_time=16.0), dict(base, start_time=25.0)]
        _add_flow_features(rows)
        self.assertEqual(rows[0]["flow_gap"], 0.0)
        self.assertEqual(rows[1]["flow_gap"], 6.0)
        self.assertEqual(rows[2]["flow_gap"], 9.0)
        self.assertGreater(rows[2]["gap_rolling_std"], 0.0)

    def test_retransmitted_syn_does_not_split_connection(self):
        connection = _Connection("a", "1", 1234, "2", 443, 1.0, syn_sequence=100)
        connection.add_packet(10.0, True, 60)
        self.assertFalse(_should_start_new_connection(connection, 11.0, True, 100))

    def test_new_syn_after_close_or_sequence_change_starts_connection(self):
        connection = _Connection("a", "1", 1234, "2", 443, 1.0, syn_sequence=100)
        connection.add_packet(10.0, True, 60)
        self.assertTrue(_should_start_new_connection(connection, 11.0, True, 200))
        connection.closed = True
        self.assertTrue(_should_start_new_connection(connection, 11.0, True, 100))


if __name__ == "__main__":
    unittest.main()
