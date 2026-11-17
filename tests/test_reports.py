"""Check mode separation and evidence preservation without executing targets."""
from dataclasses import asdict
import json
from pathlib import Path
import tempfile
import unittest

from src.core.test_runner import SanitizerReport, StackFrame, TestResult
from src.modules.classifier import Finding
from src.modules.report_generator import ReportGenerator, json_default


class ReportTests(unittest.TestCase):
    def fixture(self):
        def result(mode, **changes):
            values = dict(test_name="case", input_path=Path("case.input"), exit_code=0,
                          signal=None, stdout=f"{mode} output", stderr="", timed_out=False,
                          oom_killed=False, build_type=mode)
            return TestResult(**{**values, **changes})

        return {
            "project": "Report fixture", "exit_code": 0,
            "findings": [Finding("case", "Fixed", "combined detail", comparisons={
                "release": {"category": "Inconclusive", "stable": True, "detail": "release reasoning"},
                "sanitized": {"category": "Fixed", "stable": True, "detail": "sanitizer reasoning"}})],
            "hardening": {"base": {"status": "checked", "relro": "full", "nx": True,
                                   "pie": True, "canary": True, "fortify": False},
                          "patched": {"status": "unsupported"}},
            "results": {
                "base_release": {"case": [result("release", stdout="release-only output")]},
                "patched_release": {"case": [result("release", exit_code=1)]},
                "base_sanitized": {"case": [result("sanitized", exit_code=1,
                    error_type="heap-buffer-overflow", detection_mechanism="sanitizer",
                    sanitizer_report=SanitizerReport("heap-buffer-overflow", [
                        StackFrame(0, "parseFixture", "/fixture/parser.c", 42, "0x123")], "fixture"))]},
                "patched_sanitized": {"case": [result("sanitized", stdout="sanitizer-only output")]},
            },
        }

    def test_modes_have_independent_tables_and_combined_verdict(self):
        for serialized in (False, True):
            data = self.fixture()
            expected = json.loads(json.dumps(data, default=json_default))
            if serialized:
                data = expected
            with self.subTest(serialized=serialized), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                ReportGenerator(root).generate(data)
                for suffix in ("md", "html"):
                    text = (root / f"report.{suffix}").read_text()
                    if suffix == "md":
                        self.assertIn("## Release Build Summary", text)
                        self.assertIn("## Instrumented (ASan/UBSan) Build Summary", text)
                        release = text.split("## Release Build Summary", 1)[1].split("\n## ", 1)[0]
                        sanitized = text.split("## Instrumented (ASan/UBSan) Build Summary", 1)[1].split("\n## ", 1)[0]
                    else:
                        self.assertIn("<h2>Release Build Summary</h2>", text)
                        self.assertIn("<h2>Instrumented (ASan/UBSan) Build Summary</h2>", text)
                        release = text.split("<h2>Release Build Summary</h2>", 1)[1].split("<h2>", 1)[0]
                        sanitized = text.split("<h2>Instrumented (ASan/UBSan) Build Summary</h2>", 1)[1].split("<details>", 1)[0]
                        self.assertIn("<table>", release)
                        self.assertIn("<table>", sanitized)
                    self.assertIn("release-only output", release)
                    self.assertNotIn("sanitizer-only output", release)
                    self.assertNotIn("heap-buffer-overflow", release)
                    self.assertIn("sanitizer-only output", sanitized)
                    self.assertNotIn("release-only output", sanitized)
                    for value in ("heap-buffer-overflow", "parseFixture", "/fixture/parser.c:42", "sanitizer"):
                        self.assertIn(value, sanitized)
                    for value in ("Exit code", "Signal", "Execution status", "stdout", "stderr", "Hardening", "RELRO", "full", "unsupported"):
                        self.assertIn(value, release)
                    for value in ("Combined Verdict", "Inconclusive", "Fixed"):
                        self.assertIn(value, text)
                self.assertEqual(json.loads((root / "report.json").read_text()), expected)

    def test_rendering_escapes_target_output_and_retains_all_replays(self):
        data = self.fixture()
        runs = data["results"]["base_release"]["case"]
        runs[0].stdout = '<script>alert(1)</script>\r| [click](https://example.invalid)'
        second = asdict(runs[0])
        second.update(exit_code=-6, signal="SIGABRT", stdout="second replay", stderr="release diagnostic",
                      error_type="crash-SIGABRT", detection_mechanism="signal")
        runs.append(second)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ReportGenerator(root).generate(data)
            for suffix in ("md", "html"):
                text = (root / f"report.{suffix}").read_text()
                self.assertNotIn("<script>", text)
                for value in ("&lt;script&gt;", "second replay", "release diagnostic", "SIGABRT", "Crash"):
                    self.assertIn(value, text)
            markdown = (root / "report.md").read_text()
            self.assertNotIn(b"\r", (root / "report.md").read_bytes())
            self.assertIn(r"\|", markdown)
            self.assertIn(r"\[click\]", markdown)
            self.assertIn("| case | Base | 2 | -6 |", markdown)
            saved = json.loads((root / "report.json").read_text())
            self.assertEqual(saved["results"]["base_release"]["case"][0]["stdout"], runs[0].stdout)

    def test_partial_reports_and_resource_failures_stay_explicit(self):
        data = self.fixture()
        data["exit_code"] = 40
        data["findings"][0].category = "Inconclusive"
        data["results"]["base_release"]["case"][0].timed_out = True
        data["results"]["patched_release"]["case"][0].resource_limited = True
        data["results"]["patched_release"]["case"][0].signal = "SIGKILL"
        data["hardening"] = {"status": "skipped"}
        del data["results"]["patched_sanitized"]
        data.update(errors=["Build <failed>"], warnings=["Check skipped"])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ReportGenerator(root).generate(data)
            for suffix in ("md", "html"):
                text = (root / f"report.{suffix}").read_text()
                for value in ("Timed out", "Resource/runtime failure", "Not recorded", "skipped",
                              "Build &lt;failed&gt;", "Check skipped", "Inconclusive"):
                    self.assertIn(value, text)
            ReportGenerator(root).generate({"project": "failed", "exit_code": 30, "findings": []})
            self.assertIn("No execution data recorded", (root / "report.md").read_text())

    def test_correlation_is_visible_with_frame_role_and_uncertainty(self):
        data = self.fixture()
        data["findings"][0].correlation = {
            "base_sanitized": {"status": "changed_line", "evidence": [
                {"status": "changed_line", "frame_id": 1, "frame_role": "caller",
                 "function": "parse_object", "file": "parser.c", "line": 12}],
                "limitation": "Association is not proof of causation."},
            "patched_sanitized": {"status": "changed_line", "evidence": [
                {"status": "changed_line", "frame_id": 0, "frame_role": "crash",
                 "function": "parse_string", "file": "parser.c", "line": 9}]},
            "base_release": {"status": "unknown", "evidence": [],
                             "limitation": "No symbolized frames."},
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ReportGenerator(root).generate(data)
            for suffix in ("md", "html"):
                text = (root / f"report.{suffix}").read_text().split("<details>", 1)[0]
                for value in ("Diff Correlation", "changed_line (caller frame #1: parse_object)",
                              "changed_line (crash frame #0: parse_string)", "parser.c:12",
                              "unknown", "No symbolized frames.", "Association is not proof of causation."):
                    self.assertIn(value.replace("_", r"\_") if suffix == "md" else value, text)
