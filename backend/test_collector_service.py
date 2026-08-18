import hashlib
import sys
import unittest
from pathlib import Path


BACKEND_ROOT = Path(__file__).resolve().parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

try:
    from app import collector_service
except ImportError:
    collector_service = None


@unittest.skipIf(collector_service is None, "collector cloud dependencies are not installed")
class CollectorServiceTests(unittest.TestCase):
    def test_token_hash_does_not_store_plain_token(self):
        token = "one-time-secret-token"
        digest = collector_service._hash_token(token)
        self.assertEqual(digest, hashlib.sha256(token.encode()).hexdigest())
        self.assertNotIn(token, digest)

    def test_safe_filename_removes_paths_and_rejects_suffix(self):
        self.assertEqual(collector_service._safe_filename(r"C:\\temp\\capture.pcapng"), "capture.pcapng")
        with self.assertRaises(Exception):
            collector_service._safe_filename("capture.exe")

    def test_sse_parser_retains_partial_event(self):
        parsed, remainder = collector_service._parse_sse_blocks(
            'event: step\ndata: zeek\n\nevent: result\ndata: {"ok":'
        )
        self.assertEqual(parsed, [("step", "zeek")])
        self.assertTrue(remainder.startswith("event: result"))

    def test_magic_numbers_cover_pcap_and_pcapng(self):
        self.assertIn(b"\xd4\xc3\xb2\xa1", collector_service.PCAP_MAGIC)
        self.assertIn(b"\x0a\x0d\x0d\x0a", collector_service.PCAP_MAGIC)


if __name__ == "__main__":
    unittest.main()
