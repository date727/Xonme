"""Regression checks for reader-facing report facts.

These run on the server during maintenance; they do not affect the web UI or
require uploading a PCAP again.
"""

import unittest
from pathlib import Path
from unittest.mock import patch

from app.report_context import build_report_context, format_report_context


AMAZON_SHA = "28a119538ecb509cee1deb9e4a465946537c3b23913873aaf570952dd43165d1"
SMASHBURGER_SHA = "efc052a8172d7d76a34be5c98843278f3885b0e04494248093df753a89d5cf93"


class ReportContextTests(unittest.TestCase):
    def test_malicious_report_keeps_evidence_and_shows_candidate_groups(self) -> None:
        logs = [[{
            "id.orig_h": "192.168.56.101", "id.resp_h": "192.168.56.4",
            "id.resp_p": "80", "host": "www.amazon.com",
        }], []]
        with patch("app.report_context._read_zeek_tsv", side_effect=logs):
            context = build_report_context(
                csv_text="Severity,Beacon Score,Connection Count\nlow,0.518,15\n",
                output_dir=Path("."),  # mocked reader never reads this value
                sample_sha256=AMAZON_SHA,
                sample_name="amazon.pcapng",
                threats=[{"src_ip": "192.168.56.101"}],
                lstm_results={"status": "completed", "total_flagged": 1, "beacons": [{"confidence": 100, "risk": "Critical"}]},
                rita_ok=True,
                rag_results=[{"candidates": [
                    {"name": "APT42", "score": 0.547, "metadata": {"background_zh": "中文组织背景", "matched_technique_details": [{"id": "T1071.001", "name_zh": "应用层协议：Web 协议"}]}},
                    {"name": "APT39", "score": 0.514, "metadata": {"background_zh": "中文组织背景"}},
                ]}],
            )
            packet = format_report_context(context)
            self.assertEqual(context["decision"]["risk_level"], "高危")
            self.assertEqual(context["attribution"]["status"], "candidate_association")
            self.assertIn("Host 为 `www.amazon.com`", packet)
            self.assertIn("APT42", packet)
            self.assertIn("画像关联度：54.7%", packet)

    def test_benign_report_explains_normal_tls_and_skips_attribution(self) -> None:
        logs = [[], [{
            "id.orig_h": "10.0.0.8", "id.resp_h": "13.225.239.1",
            "id.resp_p": "443", "version": "TLSv13", "server_name": "smashburger.com",
        }]]
        with patch("app.report_context._read_zeek_tsv", side_effect=logs):
            context = build_report_context(
                csv_text="Severity,Beacon Score,Connection Count\n,0.400,2\n",
                output_dir=Path("."),  # mocked reader never reads this value
                sample_sha256=SMASHBURGER_SHA,
                sample_name="smashburger.pcapng",
                threats=[],
                lstm_results={"status": "insufficient_sequence", "max_group_connections": 2, "minimum_sequence_length": 10},
                rita_ok=True,
                rag_results=[],
            )
            packet = format_report_context(context)
            self.assertEqual(context["decision"]["risk_level"], "低危")
            self.assertEqual(context["attribution"]["status"], "not_applicable")
            self.assertEqual(
                context["attribution"]["conclusion"],
                "当前未发现与已知攻击活动相关的明显行为特征或组织关联线索。",
            )
            self.assertIn("smashburger.com", packet)
            self.assertIn("RITA 风险判定为“未达到 Beacon 风险告警阈值”", packet)
            self.assertIn("LSTM 未参与本次评估", packet)


if __name__ == "__main__":
    unittest.main()
