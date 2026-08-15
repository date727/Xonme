"""Tests that detection persistence is independent from optional RAG."""

import asyncio
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from app import main
except ModuleNotFoundError as exc:
    if exc.name not in {"sqlalchemy", "fastapi", "dotenv", "pydantic"}:
        raise
    main = None
    MISSING_BACKEND_DEPENDENCY = exc.name
else:
    MISSING_BACKEND_DEPENDENCY = None


class FakeExtractor:
    def __init__(self, csv_text):
        self.csv_text = csv_text

    def extract_all(self):
        return [{
            "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
            "dst_port": "443", "protocol": "tcp", "threat_category": "high",
        }]


@unittest.skipIf(
    main is None,
    f"local backend dependency unavailable: {MISSING_BACKEND_DEPENDENCY}",
)
class PipelineDecouplingTests(unittest.TestCase):
    def test_endpoint_normalization_supports_ipv4_and_mapped_ipv6(self):
        self.assertEqual(main._canonical_endpoint("192.168.56.5"), "192.168.56.5")
        self.assertEqual(main._canonical_endpoint("::ffff:192.168.56.5"), "192.168.56.5")

    def test_detection_merge_runs_when_rag_is_unavailable(self):
        with (
            patch.object(main, "ThreatFeatureExtractor", FakeExtractor),
            patch.object(main, "_RAG_AVAILABLE", False),
        ):
            threats = main._merge_detection_results(
                "rita,csv", rita_ok=True, lstm_results=None
            )
            context, results = main._run_optional_attribution(threats)
        self.assertEqual(len(threats), 1)
        self.assertEqual(threats[0]["detection_sources"], ["RITA"])
        self.assertIsNone(context)
        self.assertEqual(results, [])

    def test_detection_merge_uses_rita_view_evidence_when_mixtape_is_unavailable(self):
        class CsvEvidenceExtractor(FakeExtractor):
            def extract_display_evidence(self):
                return {
                    ("10.0.0.1", "10.0.0.2", "443"): {
                        "timestamp_score": 0.8,
                        "connection_count": 15,
                        "evidence_source": "rita_view_csv",
                    }
                }

        with patch.object(main, "ThreatFeatureExtractor", CsvEvidenceExtractor):
            threats = main._merge_detection_results(
                "rita,csv", rita_ok=True, lstm_results=None
            )
        self.assertEqual(threats[0]["rita"]["timestamp_score"], 0.8)
        self.assertEqual(threats[0]["rita"]["connection_count"], 15)
        self.assertEqual(threats[0]["rita"]["evidence_source"], "rita_view_csv")

    def test_wildcard_rita_evidence_survives_lstm_destination_alignment(self):
        class WildcardEvidenceExtractor(FakeExtractor):
            def extract_all(self):
                return [{
                    "src_ip": "10.0.0.1", "dst_ip": "::", "dst_port": "443",
                    "protocol": "", "threat_category": "high",
                }]

            def extract_display_evidence(self):
                return {("10.0.0.1", "::", "443"): {"timestamp_score": 0.8}}

        lstm = {"total_flagged": 1, "beacons": [{
            "src": "10.0.0.1", "dst": "10.0.0.2", "port": "443",
            "proto": "tcp", "confidence": 99,
        }]}
        with patch.object(main, "ThreatFeatureExtractor", WildcardEvidenceExtractor):
            threats = main._merge_detection_results("rita,csv", rita_ok=True, lstm_results=lstm)
        self.assertEqual(threats[0]["dst_ip"], "10.0.0.2")
        self.assertEqual(threats[0]["rita"]["timestamp_score"], 0.8)

    def test_rita_v5_score_columns_are_mapped_for_the_dashboard(self):
        from app import rita_feature_exporter

        row = {
            "src": "192.168.56.5", "dst": "::",
            "port_proto_service": ["80:tcp:http"], "count": 15,
            "ts_score": 0.91, "ds_score": 0.82, "dur_score": 0.73,
            "hist_score": 0.64, "ts_intervals": [10, 11],
            "ts_interval_counts": [8, 6], "total_duration": 18.5,
            "ds_sizes": [512, 1024], "ds_size_counts": [9, 6],
            "total_bytes": 1024, "long_conn_score": 0.0,
            "c2_over_dns_score": 0.0, "subdomain_count": 0,
            "threat_intel_score": 0.0,
        }
        completed = SimpleNamespace(stdout=json.dumps(row), stderr="", returncode=0)
        with patch.object(rita_feature_exporter.subprocess, "run", return_value=completed) as run:
            evidence = rita_feature_exporter.export_rita_connection_evidence("run_test")
        args = run.call_args.args[0]
        query = args[-1]
        self.assertIn("ts_score,ds_score,dur_score,hist_score", query)
        self.assertIn("ds_sizes,ds_size_counts", query)
        self.assertNotIn("SELECT *", query)
        detail = evidence[("192.168.56.5", "::", "80")]
        self.assertEqual(detail["timestamp_score"], 0.91)
        self.assertEqual(detail["datasize_score"], 0.82)
        self.assertEqual(detail["duration_score"], 0.73)
        self.assertEqual(detail["histogram_score"], 0.64)
        self.assertEqual(detail["ds_sizes"], [512.0, 1024.0])
        self.assertEqual(detail["ds_size_counts"], [9.0, 6.0])

    def test_clickhouse_ipv4_mapped_source_matches_rita_csv_source(self):
        from app import rita_feature_exporter

        row = {
            "src": "::ffff:192.168.56.5", "dst": "::",
            "port_proto_service": ["80:tcp:http"], "count": 15,
            "ts_score": 0.071, "ds_score": 1, "dur_score": 1,
            "hist_score": 0, "ts_intervals": [0, 1, 9],
            "ts_interval_counts": [1, 2, 4], "total_duration": 228.518504,
            "total_bytes": 0, "long_conn_score": 0,
            "c2_over_dns_score": 0, "subdomain_count": 0,
            "threat_intel_score": 0,
        }
        completed = SimpleNamespace(stdout=json.dumps(row), stderr="", returncode=0)
        with patch.object(rita_feature_exporter.subprocess, "run", return_value=completed):
            evidence = rita_feature_exporter.export_rita_connection_evidence("run_test")
        detail = evidence[("192.168.56.5", "::", "80")]
        self.assertEqual(detail["connection_count"], 15)
        self.assertEqual(detail["timestamp_score"], 0.071)
        self.assertEqual(detail["total_duration"], 228.518504)

    def test_zeek_connection_sequence_uses_real_conn_timestamps_and_bytes(self):
        conn_log = (
            "#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
            "100.0\t192.168.56.5\t50000\t198.51.100.8\t80\ttcp\n"
            "104.0\t192.168.56.5\t50001\t198.51.100.8\t80\ttcp\n"
            "112.0\t192.168.56.5\t50002\t198.51.100.8\t80\ttcp\n"
        )
        threats = [{
            "src_ip": "192.168.56.5", "dst_ip": "198.51.100.8",
            "dst_port": "80", "rita": {},
        }]
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "conn.log"
            path.write_text(conn_log, encoding="utf-8")
            main._add_zeek_connection_series(threats, Path(temp_dir))
        sequence = threats[0]["rita"]["connection_sequence"]
        self.assertEqual(sequence["indexes"], [1, 2, 3])
        self.assertEqual(sequence["interval_seconds"], [0.0, 4.0, 8.0])
        self.assertEqual(sequence["frequency_per_minute"], [0.0, 15.0, 7.5])
        self.assertEqual(sequence["total_bytes"], [0, 0, 0])

    def test_history_dashboard_prefers_database_result(self):
        stored_dashboard = {"schema_version": 1, "threats": [{"src_ip": "10.0.0.1"}]}
        record = {
            "id": 7, "original_filename": "sample.pcap", "file_size": 100,
            "status": "completed", "created_at": None, "completed_at": None,
            "report_markdown": "report", "result_json": stored_dashboard,
            "storage_path": "missing-path-that-must-not-be-read",
        }
        with (
            patch.object(main, "get_analysis_record_for_user", return_value=record),
            patch.object(main, "_owned_task_root") as owned_root,
        ):
            response = asyncio.run(
                main.get_saved_analysis_dashboard(7, SimpleNamespace(id=3))
            )
        self.assertEqual(response["dashboard"], stored_dashboard)
        owned_root.assert_not_called()


if __name__ == "__main__":
    unittest.main()
