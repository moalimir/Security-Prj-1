"""Direct target execution, bounded runtime, and separate crash/resource evidence."""
from __future__ import annotations

import hashlib
import os
import re
import resource
import shlex
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from src.core.config_manager import ProjectConfig
from src.utils.constants import ASAN_ERROR_PATTERNS
from src.utils.exceptions import TestExecutionError


@dataclass
class StackFrame:
    frame_id: int
    function_name: str
    file_path: str
    line_number: int
    address: str


@dataclass
class SanitizerReport:
    error_type: str
    stack_frames: list[StackFrame]
    description: str


@dataclass
class TestResult:
    test_name: str
    input_path: Path
    exit_code: int
    signal: str | None
    stdout: str
    stderr: str
    timed_out: bool
    oom_killed: bool
    build_type: str
    error_type: str | None = None
    detection_mechanism: str | None = None
    sanitizer_report: SanitizerReport | None = None
    duration_ms: float = 0
    stdout_hash: str = ""
    resource_limited: bool = False

    @property
    def crashed(self) -> bool:
        return bool(self.error_type) and not (self.timed_out or self.resource_limited)

    @property
    def signature(self) -> tuple:
        """Exclude ASLR addresses and snapshot roots from replay identity."""
        frames = self.sanitizer_report.stack_frames if self.sanitizer_report else []
        frame = next((f for f in frames if f.file_path.endswith((".c", ".cc", ".cpp", ".cxx"))
                      and not f.function_name.startswith("__")), None)
        relative_path = frame.file_path.split("/source/", 1)[-1] if frame else ""
        location = (relative_path, frame.function_name, frame.line_number) if frame else None
        return self.error_type, self.detection_mechanism, location


class TestRunner:
    def __init__(self, config: ProjectConfig):
        self._config = config

    def command(self, binary_path: Path, input_path: Path) -> list[str]:
        value = str(input_path)
        if self._config.execution.input_mode == "args":
            value = input_path.read_text(encoding="utf-8")
        # Tokenize the trusted template before substituting untrusted input.
        return [arg.format(binary=str(binary_path), input=value, input_file=str(input_path))
                for arg in shlex.split(self._config.execution.cmd_template)]

    def environment(self, build_type: str) -> dict[str, str]:
        env = os.environ.copy()
        env["LC_ALL"] = "C"
        if build_type == "sanitized":
            # RLIMIT_AS cannot cap ASan's multi-terabyte shadow mappings.
            env["ASAN_OPTIONS"] = ("detect_leaks=0:abort_on_error=1:symbolize=1:"
                                   f"hard_rss_limit_mb={self._config.execution.memory_limit_mb}")
            env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
        return env

    def run_single_test(self, binary_path: Path, input_path: Path, build_type: str) -> TestResult:
        binary_path, input_path = Path(binary_path).resolve(), Path(input_path).resolve()
        if not binary_path.is_file() or not input_path.is_file():
            raise TestExecutionError(f"Missing binary or input: {binary_path}, {input_path}")
        cfg = self._config.execution
        try:
            cmd = self.command(binary_path, input_path)
            stdin_data = input_path.read_bytes() if cfg.input_mode == "stdin" else None
        except (OSError, UnicodeError, ValueError) as exc:
            raise TestExecutionError(f"Cannot prepare test input: {exc}") from exc

        def limits():
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024 * 1024, 16 * 1024 * 1024))
            if sys.platform.startswith("linux") and build_type == "release":
                cap = cfg.memory_limit_mb * 1024 * 1024
                resource.setrlimit(resource.RLIMIT_AS, (cap, cap))

        start = time.monotonic()
        timed_out = False
        try:
            with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
                with subprocess.Popen(cmd, stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
                                      stdout=output, stderr=errors,
                                      env=self.environment(build_type), start_new_session=True,
                                      preexec_fn=limits) as proc:
                    try:
                        proc.communicate(stdin_data, timeout=cfg.timeout_sec)
                    except subprocess.TimeoutExpired:
                        timed_out = True
                        try:
                            os.killpg(proc.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        proc.communicate()
                    exit_code = proc.returncode
                output_limited = max(output.tell(), errors.tell()) > 1024 * 1024
                output.seek(0)
                stdout_hash = hashlib.file_digest(output, "sha256").hexdigest()
                output.seek(0)
                errors.seek(0)
                stdout_bytes, stderr_bytes = output.read(1024 * 1024), errors.read(1024 * 1024)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            raise TestExecutionError(f"Cannot execute {cmd[0]}: {exc}") from exc
        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")
        sig = self._parse_signal(exit_code) if not timed_out else None
        report = self._parse_asan_output(stderr)
        resource_limited = (not timed_out and (output_limited or sig in ("SIGKILL", "SIGXFSZ") or bool(re.search(
            r"(failed to (?:mmap|allocate)|out of memory|rss limit exhausted|ReserveShadowMemoryRange failed|"
            r"Shadow memory range interleaves|ASan runtime does not come first)", stderr, re.I))))
        error_type = mechanism = None
        if timed_out:
            error_type, mechanism = "timeout", "timeout"
        elif resource_limited:
            error_type, mechanism = "resource-or-runtime-failure", "resource"
        elif report:
            error_type, mechanism = report.error_type, "sanitizer"
        elif "stack smashing detected" in stderr or "buffer overflow detected" in stderr:
            error_type, mechanism = "binary-protection-abort", "binary-protection"
        elif sig:
            error_type, mechanism = f"crash-{sig}", "signal"
        return TestResult(input_path.stem, input_path, exit_code, sig, stdout, stderr,
                          timed_out, False, build_type, error_type, mechanism, report,
                          (time.monotonic() - start) * 1000,
                          stdout_hash, resource_limited)

    def run_test_suite(self, binary_path: Path, test_dir: Path, build_type: str) -> list[TestResult]:
        if not test_dir.is_dir():
            raise TestExecutionError(f"Test directory not found: {test_dir}")
        return [self.run_single_test(binary_path, p, build_type)
                for p in sorted(test_dir.iterdir()) if p.is_file()]

    @staticmethod
    def _parse_signal(returncode: int) -> str | None:
        if returncode >= 0:
            return None
        try:
            return signal.Signals(-returncode).name
        except ValueError:
            return f"SIGNAL_{-returncode}"

    @staticmethod
    def _parse_asan_output(stderr: str) -> SanitizerReport | None:
        error_type = description = None
        for pattern, label in ASAN_ERROR_PATTERNS.items():
            match = re.search(pattern, stderr)
            if match:
                error_type = label
                description = stderr[stderr.rfind("\n", 0, match.start()) + 1:].splitlines()[0]
                break
        if not error_type:
            generic = re.search(r"(?:ERROR|SUMMARY):\s*(?:AddressSanitizer|UndefinedBehaviorSanitizer):\s*(\S+)", stderr)
            ubsan = re.search(r"([^\n]+):\d+:\d+: runtime error: ([^\n]+)", stderr)
            if generic:
                error_type, description = generic.group(1), generic.group(0)
            elif ubsan:
                error_type, description = "undefined-behavior", ubsan.group(0)
            else:
                return None
        frames = []
        pattern = re.compile(r"#(\d+)\s+(0x[0-9a-fA-F]+)\s+(?:in\s+)?(.+?)\s+(\S+\.(?:c|cc|cpp|cxx|h)):(\d+)(?::\d+)?(?:\s|$)")
        for match in pattern.finditer(stderr):
            frames.append(StackFrame(int(match[1]), match[3], match[4], int(match[5]), match[2]))
        if not frames:
            match = re.search(r"([^\s]+\.(?:c|cc|cpp|cxx)):(\d+):\d+: runtime error:", stderr)
            if match:
                frames.append(StackFrame(0, "<unknown>", match[1], int(match[2]), ""))
        return SanitizerReport(error_type, frames, description or "")
