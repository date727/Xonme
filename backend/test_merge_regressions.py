"""Static contracts for merge-sensitive analysis wiring."""

import re
import unittest
from pathlib import Path


MAIN_SOURCE = (Path(__file__).parent / "app" / "main.py").read_text(encoding="utf-8")


class MergeRegressionTests(unittest.TestCase):
    def test_regular_analysis_keeps_rag_context_and_structured_results(self):
        regular_analysis = MAIN_SOURCE[
            MAIN_SOURCE.index("async def analyze_pcap(") :
            MAIN_SOURCE.index('@app.post("/analyze/stream")')
        ]
        self.assertRegex(
            regular_analysis,
            re.compile(
                r"rag_context,\s*rag_results\s*=\s*"
                r"_run_optional_attribution\(merged_features\)"
            ),
        )
        self.assertIn("rag_results=rag_results", regular_analysis)


if __name__ == "__main__":
    unittest.main()
