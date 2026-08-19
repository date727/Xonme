"""Regression tests for analysis lifetime after an SSE disconnect."""

import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.stream_lifecycle import run_stream_in_background


class StreamLifecycleTests(unittest.TestCase):
    def test_disconnect_does_not_stop_background_producer(self):
        completed = threading.Event()
        continue_analysis = threading.Event()

        def producer():
            yield "event: step\ndata: zeek\n\n"
            continue_analysis.wait(1)
            completed.set()
            yield "event: result\ndata: done\n\n"

        relay = run_stream_in_background(producer(), "refresh-test")
        self.assertIn("zeek", next(relay))
        relay.close()
        continue_analysis.set()
        self.assertTrue(completed.wait(1), "analysis stopped with the browser stream")


if __name__ == "__main__":
    unittest.main()
