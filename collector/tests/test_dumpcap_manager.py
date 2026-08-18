import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import dumpcap_manager


class DumpcapManagerTests(unittest.TestCase):
    def test_interface_output_is_structured(self):
        completed = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="1. \\Device\\NPF_{ABC} (Intel(R) Wi-Fi 6 AX201)\n2. \\Device\\NPF_{DEF} (Realtek Ethernet)\n",
            stderr="",
        )
        with patch.object(dumpcap_manager.subprocess, "run", return_value=completed):
            interfaces = dumpcap_manager.list_interfaces(Path("dumpcap.exe"))
        self.assertEqual([item.id for item in interfaces], ["1", "2"])
        self.assertIn("Wi-Fi", interfaces[0].display_name)
        self.assertIn("以太网", interfaces[1].display_name)

    def test_start_uses_argument_array_and_no_shell(self):
        process = Mock()
        process.poll.return_value = None
        with tempfile_context() as output:
            with patch.object(dumpcap_manager.subprocess, "Popen", return_value=process) as popen, patch.object(dumpcap_manager.time, "sleep"):
                dumpcap_manager.start_dumpcap(Path("dumpcap.exe"), "1", "tcp or udp", 60, 100, output)
        args, kwargs = popen.call_args
        self.assertIsInstance(args[0], list)
        self.assertNotIn("shell", kwargs)
        self.assertIn("duration:60", args[0])
        self.assertIn("filesize:102400", args[0])

    def test_access_probe_opens_only_the_selected_interface(self):
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="DLT_EN10MB", stderr="")
        with patch.object(dumpcap_manager.subprocess, "run", return_value=completed) as run:
            dumpcap_manager.probe_capture_access(Path("dumpcap.exe"), "2")
        self.assertEqual(run.call_args.args[0], ["dumpcap.exe", "-i", "2", "-L"])


class tempfile_context:
    def __enter__(self):
        import tempfile
        self.temp = tempfile.TemporaryDirectory()
        return Path(self.temp.name) / "capture" / "capture.pcapng"

    def __exit__(self, *args):
        self.temp.cleanup()


if __name__ == "__main__":
    unittest.main()
