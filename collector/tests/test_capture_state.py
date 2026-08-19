import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    import capture_state
except ImportError:
    capture_state = None


@unittest.skipIf(capture_state is None, "collector runtime dependencies are not installed")
class CaptureStateTests(unittest.TestCase):
    def test_uploaded_chunk_is_deleted_only_after_cloud_ack(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "capture.pcapng"
            chunk = root / "capture_00001.pcapng"
            content = b"\x0a\x0d\x0d\x0a" + b"payload"
            chunk.write_bytes(content)
            task = capture_state.CaptureTask(
                capture_id="capture-id",
                cloud_session_id="00000000-0000-0000-0000-000000000001",
                upload_token="token-value-with-enough-characters",
                output_path=output,
                max_duration_seconds=60,
                max_file_size_mb=100,
            )
            task.file_sequences[chunk] = 0
            task.next_sequence = 1
            coordinator = capture_state.CaptureCoordinator()
            with patch.object(capture_state, "upload_chunk", return_value={"accepted": True}) as upload:
                coordinator._upload_files(task, [chunk], capture_running=True)
            self.assertFalse(chunk.exists())
            self.assertEqual(task.uploaded_chunks, 1)
            self.assertEqual(task.uploaded_bytes, len(content))
            self.assertEqual(upload.call_args.args[3], 0)

    def test_failed_chunk_remains_for_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            chunk = root / "capture_00001.pcapng"
            chunk.write_bytes(b"\x0a\x0d\x0d\x0a" + b"payload")
            task = capture_state.CaptureTask(
                capture_id="capture-id",
                cloud_session_id="00000000-0000-0000-0000-000000000001",
                upload_token="token-value-with-enough-characters",
                output_path=root / "capture.pcapng",
                max_duration_seconds=60,
                max_file_size_mb=100,
            )
            task.file_sequences[chunk] = 0
            coordinator = capture_state.CaptureCoordinator()
            with patch.object(capture_state, "upload_chunk", side_effect=RuntimeError("offline")), patch.object(capture_state.time, "sleep"):
                with self.assertRaises(RuntimeError):
                    coordinator._upload_files(task, [chunk], capture_running=True)
            self.assertTrue(chunk.exists())
            self.assertEqual(task.uploaded_chunks, 0)
