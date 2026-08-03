"""Unit tests for PCAP timestamp-derived LSTM timing features."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.pcap_lstm_feature_extractor import _iat_features


class IatFeatureTests(unittest.TestCase):
    def test_uses_real_adjacent_timestamp_deltas(self):
        features = _iat_features([10.0, 10.2, 11.0, 11.5])

        self.assertAlmostEqual(features["iat_oresp_total"], 1.5)
        self.assertAlmostEqual(features["iat_oresp_min"], 0.2)
        self.assertAlmostEqual(features["iat_oresp_max"], 0.8)
        self.assertAlmostEqual(features["iat_oresp_mean"], 0.5)
        self.assertAlmostEqual(features["iat_oresp_stddev"], (0.06) ** 0.5)
        self.assertAlmostEqual(features["iat_oresp_nf_0"], 0.2)
        self.assertAlmostEqual(features["iat_oresp_nf_1"], 0.8)
        self.assertAlmostEqual(features["iat_oresp_nf_2"], 0.5)
        self.assertEqual(features["iat_oresp_nf_3"], 0.0)

    def test_single_packet_has_zero_timing_features(self):
        features = _iat_features([10.0])
        self.assertTrue(all(features[name] == 0.0 for name in features))


if __name__ == "__main__":
    unittest.main()
