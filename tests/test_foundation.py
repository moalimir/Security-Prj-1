"""Behavior checks for the scaffold; no downloaded targets are needed."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


from src.core.config_manager import ConfigManager, ExecConfig
from src.core.test_runner import TestRunner
from src.utils.exceptions import ConfigError

ROOT = Path(__file__).resolve().parents[1]


class FoundationTests(unittest.TestCase):
    def test_invalid_execution_limits_rejected(self):
        for kwargs in ({"timeout_sec": 0}, {"memory_limit_mb": -1},
                       {"timeout_sec": True}, {"cmd_template": "{unknown}"}):
            values = {"input_mode": "file", "cmd_template": "{binary} {input_file}", **kwargs}
            with self.subTest(kwargs=kwargs), self.assertRaises(ConfigError):
                ExecConfig(**values)

    def test_missing_config_cli_is_build_config_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.run(
                [sys.executable, str(ROOT / "src/orchestrator.py"),
                 "--config", str(Path(tmp) / "missing.yaml"), "-o", tmp],
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 30, proc.stderr)
            report = json.loads((Path(tmp) / "report.json").read_text())
            self.assertEqual(report["exit_code"], 30)

    def test_cli_argument_errors_use_config_exit_code(self):
        proc = subprocess.run([sys.executable, "-m", "src", "--unknown"],
                              capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(proc.returncode, 30, proc.stderr)

    def test_null_config_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.yaml"
            path.write_text("build: null\n")
            with self.assertRaises(ConfigError):
                ConfigManager.load_config(str(path))

    def test_runner_handles_empty_stdin_and_literal_paths(self):
        with tempfile.TemporaryDirectory(prefix="validator space ") as tmp:
            root = Path(tmp)
            inp = root / "input; literal.txt"
            inp.write_bytes(b"")
            script = root / "echo.py"
            script.write_text("import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())")
            config = type("Config", (), {"execution": ExecConfig(
                "stdin", f'{{binary}} "{script}"', timeout_sec=2)})()
            result = TestRunner(config).run_single_test(Path(sys.executable), inp, "release")
            self.assertEqual(result.exit_code, 0)
            self.assertEqual(result.stdout, "")
            inp.write_bytes(b"literal bytes\n")
            result = TestRunner(config).run_single_test(Path(sys.executable), inp, "release")
            self.assertEqual(result.stdout, "literal bytes\n")

    def test_runner_preserves_signal_and_distinguishes_timeout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inp = root / "input"
            inp.touch()
            script = root / "crash.py"
            script.write_text("import os, signal; os.kill(os.getpid(), signal.SIGABRT)")
            config = type("Config", (), {"execution": ExecConfig(
                "file", f'{{binary}} "{script}"', timeout_sec=2)})()
            result = TestRunner(config).run_single_test(Path(sys.executable), inp, "release")
            self.assertEqual(result.signal, "SIGABRT")
            self.assertTrue(result.crashed)
            script.write_text("import time; time.sleep(5)")
            config.execution = ExecConfig("file", f'{{binary}} "{script}"', timeout_sec=0.1)
            result = TestRunner(config).run_single_test(Path(sys.executable), inp, "release")
            self.assertTrue(result.timed_out)
            self.assertFalse(result.crashed)
            self.assertEqual(result.detection_mechanism, "timeout")

    def test_excessive_output_is_a_resource_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inp = root / "input"
            inp.touch()
            script = root / "output.py"
            script.write_text("import sys; sys.stdout.buffer.write(b'x' * (2 * 1024 * 1024))")
            config = type("Config", (), {"execution": ExecConfig(
                "file", f'{{binary}} "{script}" {{input_file}}', timeout_sec=2)})()
            result = TestRunner(config).run_single_test(Path(sys.executable), inp, "release")
            self.assertTrue(result.resource_limited)
            self.assertFalse(result.crashed)
            self.assertLessEqual(len(result.stdout), 1024 * 1024)

    def test_rosetta_mapping_failure_is_a_runtime_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inp = root / "input"
            inp.touch()
            script = root / "runtime_failure.py"
            script.write_text("import sys; sys.stderr.write('rosetta error: mmap_anonymous_rw mmap failed, size=1000\\n'); sys.exit(1)")
            config = type("Config", (), {"execution": ExecConfig(
                "file", f'{{binary}} "{script}"', timeout_sec=2)})()
            result = TestRunner(config).run_single_test(Path(sys.executable), inp, "sanitized")
            self.assertTrue(result.resource_limited)
            self.assertFalse(result.crashed)
            self.assertEqual(result.error_type, "resource-or-runtime-failure")
            self.assertEqual(result.detection_mechanism, "resource")

    def test_release_address_space_limit_requires_bounded_rosetta_to_skip(self):
        config = type("Config", (), {"execution": ExecConfig()})()
        native = "vendor_id\t: GenuineIntel\nmodel name: VirtualApple\n"
        rosetta = "vendor_id\t: VirtualApple\n"
        for cpuinfo, memory_max, expected_cap in (
            (native, "2147483648", 256 * 1024 * 1024),
            (rosetta, "2147483648", None),
            (rosetta, "max", 256 * 1024 * 1024),
            (rosetta, "0", 256 * 1024 * 1024),
            (rosetta, "-1", 256 * 1024 * 1024),
            (rosetta, "invalid", 256 * 1024 * 1024),
            (rosetta, OSError("missing cgroup"), 256 * 1024 * 1024),
            (OSError("missing cpuinfo"), "2147483648", 256 * 1024 * 1024),
        ):
            with self.subTest(cpuinfo=cpuinfo, memory_max=memory_max), \
                    patch("src.core.test_runner.sys.platform", "linux"), \
                    patch("src.core.test_runner.platform.machine", return_value="x86_64"), \
                    patch.object(Path, "read_text", side_effect=[cpuinfo, memory_max]):
                limits = TestRunner(config).memory_limits("release")
                self.assertEqual(limits["rlimit_as_bytes"], expected_cap)
                self.assertEqual(limits["configured_memory_limit_mb"], 256)
                self.assertIsNone(limits["asan_rss_limit_mb"])
                self.assertEqual(limits["cgroup_memory_max_bytes"],
                                 2147483648 if memory_max == "2147483648" else None)

    def test_sanitizer_rss_limit_is_kept_under_rosetta(self):
        config = type("Config", (), {"execution": ExecConfig()})()
        with patch("src.core.test_runner.sys.platform", "linux"), \
                patch("src.core.test_runner.platform.machine", return_value="x86_64"), \
                patch.object(Path, "read_text", side_effect=["vendor_id: VirtualApple\n", "2147483648"]):
            limits = TestRunner(config).memory_limits("sanitized")
        self.assertIsNone(limits["rlimit_as_bytes"])
        self.assertEqual(limits["asan_rss_limit_mb"], 256)
        self.assertEqual(limits["cgroup_memory_max_bytes"], 2147483648)

    def test_non_linux_keeps_existing_memory_behavior(self):
        config = type("Config", (), {"execution": ExecConfig()})()
        with patch("src.core.test_runner.sys.platform", "darwin"), \
                patch.object(Path, "read_text", side_effect=AssertionError("Must not read Linux procfs")):
            limits = TestRunner(config).memory_limits("release")
        self.assertIsNone(limits["rlimit_as_bytes"])
        self.assertIsNone(limits["cgroup_memory_max_bytes"])
        self.assertFalse(limits["rosetta_detected"])


if __name__ == "__main__":
    unittest.main()
