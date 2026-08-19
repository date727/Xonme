import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import dumpcap_manager


class DumpcapManagerTests(unittest.TestCase):
    def test_find_prefers_saved_user_path_after_environment_override(self):
        with tempfile.TemporaryDirectory() as directory:
            saved = Path(directory) / "saved" / "dumpcap.exe"
            saved.parent.mkdir()
            saved.touch()
            with patch.dict(dumpcap_manager.os.environ, {"C2S_DUMPCAP_PATH": ""}), patch.object(
                dumpcap_manager, "load_user_settings", return_value={"dumpcap_path": str(saved)}
            ), patch.object(dumpcap_manager.shutil, "which", return_value=None):
                self.assertEqual(dumpcap_manager.find_dumpcap(), saved.resolve())

    def test_selected_dumpcap_is_validated_before_it_is_saved(self):
        with tempfile.TemporaryDirectory() as directory:
            selected = Path(directory) / "dumpcap.exe"
            selected.touch()
            completed = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="Dumpcap (Wireshark) 4.4.0", stderr=""
            )
            with patch.object(dumpcap_manager.subprocess, "run", return_value=completed):
                self.assertEqual(dumpcap_manager.validate_dumpcap_executable(selected), selected.resolve())

    def test_non_dumpcap_filename_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            selected = Path(directory) / "other.exe"
            selected.touch()
            with self.assertRaises(dumpcap_manager.DumpcapError):
                dumpcap_manager.validate_dumpcap_executable(selected)

    def test_automatic_discovery_does_not_prompt_in_terminal(self):
        located = Path("C:/Program Files/Wireshark/dumpcap.exe")
        with patch.object(dumpcap_manager, "find_dumpcap", return_value=located), patch.object(
            dumpcap_manager, "prompt_for_dumpcap"
        ) as prompt:
            self.assertEqual(dumpcap_manager.ensure_dumpcap_configured(), located)
        prompt.assert_not_called()

    def test_missing_dumpcap_prompts_in_terminal(self):
        selected = Path("D:/Wireshark/dumpcap.exe")
        with patch.object(dumpcap_manager, "find_dumpcap", return_value=None), patch.object(
            dumpcap_manager, "prompt_for_dumpcap", return_value=selected
        ) as prompt:
            self.assertEqual(dumpcap_manager.ensure_dumpcap_configured(), selected)
        prompt.assert_called_once_with()

    def test_terminal_prompt_validates_and_saves_path(self):
        selected = Path("D:/Wireshark/dumpcap.exe")
        with patch.object(dumpcap_manager.os, "name", "nt"), patch(
            "builtins.input", return_value='"D:/Wireshark/dumpcap.exe"'
        ), patch.object(
            dumpcap_manager, "validate_dumpcap_executable", return_value=selected
        ) as validate, patch.object(dumpcap_manager, "save_user_setting") as save:
            result = dumpcap_manager.prompt_for_dumpcap()
        self.assertEqual(result, selected)
        validate.assert_called_once_with(selected)
        save.assert_called_once_with("dumpcap_path", str(selected))

    def test_terminal_prompt_can_be_skipped(self):
        with patch.object(dumpcap_manager.os, "name", "nt"), patch(
            "builtins.input", return_value=""
        ), patch.object(dumpcap_manager, "save_user_setting") as save:
            self.assertIsNone(dumpcap_manager.prompt_for_dumpcap())
        save.assert_not_called()

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
        self.assertEqual(args[0].count("-a"), 1)
        self.assertEqual(args[0].count("-b"), 2)
        self.assertIn("filesize:16384", args[0])

    def test_access_probe_opens_only_the_selected_interface(self):
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="DLT_EN10MB", stderr="")
        with patch.object(dumpcap_manager.subprocess, "run", return_value=completed) as run:
            dumpcap_manager.probe_capture_access(Path("dumpcap.exe"), "2")
        self.assertEqual(run.call_args.args[0], ["dumpcap.exe", "-i", "2", "-L"])


class tempfile_context:
    def __enter__(self):
        self.temp = tempfile.TemporaryDirectory()
        return Path(self.temp.name) / "capture" / "capture.pcapng"

    def __exit__(self, *args):
        self.temp.cleanup()


if __name__ == "__main__":
    unittest.main()
