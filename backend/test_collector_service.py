import hashlib
import io
import os
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

try:
    from fastapi import UploadFile
except ImportError:
    UploadFile = None


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


@unittest.skipIf(
    collector_service is None or UploadFile is None,
    "collector cloud dependencies are not installed",
)
class CollectorChunkTests(unittest.TestCase):
    def setUp(self):
        from app import database

        self.temp = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp.name) / "collector.sqlite3"
        self.upload_path = Path(self.temp.name) / "uploads"
        self.env = patch.dict(os.environ, {"DATABASE_URL": f"sqlite:///{self.database_path.as_posix()}"})
        self.env.start()
        database.initialise_database()
        with database.get_session_factory()() as db:
            user = database.User(
                username="collector-test",
                email="collector@example.test",
                password_hash="unused",
            )
            db.add(user)
            db.commit()
            db.refresh(user)
            self.user_id = user.id
        self.upload_dir = patch.object(collector_service, "COLLECTOR_UPLOAD_DIR", self.upload_path)
        self.upload_dir.start()

    def tearDown(self):
        self.upload_dir.stop()
        self.env.stop()
        self.temp.cleanup()

    @staticmethod
    def _upload(content: bytes) -> UploadFile:
        return UploadFile(filename="chunk.pcapng", file=io.BytesIO(content))

    def _session(self):
        from app import database

        with database.get_session_factory()() as db:
            user = db.get(database.User, self.user_id)
            db.expunge(user)
        return collector_service.create_collector_session(user, "deepseek-v4-flash")

    def test_chunk_retry_is_idempotent_and_conflict_is_rejected(self):
        record, token = self._session()
        content = b"\x0a\x0d\x0d\x0a" + b"test-chunk"
        digest = hashlib.sha256(content).hexdigest()
        with patch.object(collector_service._EXECUTOR, "submit"):
            first = collector_service.save_collector_chunk(record.id, token, 0, self._upload(content), digest)
            second = collector_service.save_collector_chunk(record.id, token, 0, self._upload(content), digest)
        self.assertFalse(first[1])
        self.assertTrue(second[1])
        self.assertEqual(second[2:], (1, len(content)))
        with self.assertRaises(Exception):
            collector_service.save_collector_chunk(record.id, token, 0, self._upload(content), "f" * 64)

    def test_finalize_requires_contiguous_manifest_and_is_idempotent(self):
        from app import database

        record, token = self._session()
        content = b"\x0a\x0d\x0d\x0a" + b"final"
        digest = hashlib.sha256(content).hexdigest()
        with patch.object(collector_service._EXECUTOR, "submit") as submit:
            collector_service.save_collector_chunk(record.id, token, 0, self._upload(content), digest)
            finalized = collector_service.finalize_collector_session(
                record.id, token, total_chunks=1, total_bytes=len(content)
            )
            repeated = collector_service.finalize_collector_session(
                record.id, token, total_chunks=1, total_bytes=len(content)
            )
        self.assertEqual(finalized.status, "finalizing")
        self.assertEqual(repeated.status, "finalizing")
        self.assertEqual(submit.call_count, 2)  # realtime detection plus one merge task
        with database.get_session_factory()() as db:
            stored = db.get(database.CollectorSession, record.id)
            stored.status = "receiving"
            db.commit()
        with self.assertRaises(Exception):
            collector_service.finalize_collector_session(
                record.id, token, total_chunks=2, total_bytes=len(content)
            )

    def test_merge_copies_chunk_paths_before_database_session_closes(self):
        from app import database

        record, token = self._session()
        content = b"\x0a\x0d\x0d\x0a" + b"merge"
        digest = hashlib.sha256(content).hexdigest()
        with patch.object(collector_service._EXECUTOR, "submit"):
            collector_service.save_collector_chunk(
                record.id, token, 0, self._upload(content), digest
            )
            collector_service.finalize_collector_session(
                record.id, token, total_chunks=1, total_bytes=len(content)
            )
        with patch.object(collector_service, "_run_analysis") as analyze:
            collector_service._merge_and_analyze(record.id)
        analyze.assert_called_once_with(record.id)
        with database.get_session_factory()() as db:
            stored = db.get(database.CollectorSession, record.id)
            self.assertEqual(stored.status, "queued")
            self.assertTrue(Path(stored.storage_path).is_file())


if __name__ == "__main__":
    unittest.main()
