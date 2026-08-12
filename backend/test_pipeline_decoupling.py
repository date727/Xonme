"""Tests that detection persistence is independent from optional RAG."""

import asyncio
import sys
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
