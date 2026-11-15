import json
import tempfile
import unittest
from pathlib import Path

from src.core.test_runner import TestResult, TestRunner


class AnalysisTests(unittest.TestCase):
    def result(self, **kwargs):
        values = dict(test_name="case", input_path=Path("input"), exit_code=0,
                      signal=None, stdout="ok\n", stderr="", timed_out=False,
                      oom_killed=False, build_type="sanitized")
        return TestResult(**{**values, **kwargs})

    def test_functional_regression_requires_correct_baseline(self):
        from src.modules.classifier import classify
        oracle = {"category": "invalid", "expected_exit_code": 1}
        self.assertEqual(classify(self.result(exit_code=1), self.result(), oracle)[0], "FunctionalRegression")
        self.assertEqual(classify(self.result(), self.result(), oracle)[0], "Inconclusive")

    def test_exploit_requires_reproduction_and_expected_behavior(self):
        from src.modules.classifier import classify
        oracle = {"category": "exploit", "expected_exit_code": 1,
                  "expected_error_type": "heap-buffer-overflow"}
        crash = self.result(exit_code=-6, signal="SIGABRT", error_type="heap-buffer-overflow",
                            detection_mechanism="sanitizer")
        self.assertEqual(classify(crash, self.result(exit_code=1), oracle)[0], "Fixed")
        self.assertEqual(classify(crash, self.result(exit_code=0), oracle)[0], "Inconclusive")
        self.assertEqual(classify(self.result(), self.result(exit_code=1), oracle)[0], "Inconclusive")
        self.assertEqual(classify(crash, crash, oracle)[0], "IncompleteFix")
        timeout = self.result(exit_code=-9, timed_out=True, error_type="timeout")
        self.assertEqual(classify(crash, timeout, oracle)[0], "Inconclusive")

    def test_new_security_issue_and_changed_error_are_distinct(self):
        from src.modules.classifier import classify
        oracle = {"category": "valid", "expected_exit_code": 0, "expected_stdout": "ok\n"}
        crash = self.result(exit_code=-6, signal="SIGABRT", error_type="heap-buffer-overflow")
        self.assertEqual(classify(self.result(), crash, oracle)[0], "NewIssue")
        self.assertEqual(classify(crash, crash, oracle)[0], "IncompleteFix")

    def test_parser_preserves_frame_and_does_not_infer_null_from_segv(self):
        report = TestRunner._parse_asan_output(
            "ERROR: AddressSanitizer: heap-buffer-overflow\n"
            "    #0 0x123 in parse /tmp/source/parser.c:42:5\n")
        self.assertEqual(report.stack_frames[0].line_number, 42)
        self.assertEqual(report.stack_frames[0].function_name, "parse")
        report = TestRunner._parse_asan_output("ERROR: AddressSanitizer: SEGV on unknown address")
        self.assertEqual(report.error_type, "invalid-memory-access")

    def test_minimizer_retains_predicate_and_original(self):
        from src.modules.testcase_minimizer import minimize
        minimized, attempts = minimize(b"prefix!suffix", lambda data: b"!" in data)
        self.assertEqual(minimized, b"!")
        self.assertGreater(attempts, 0)
        self.assertEqual(minimize(b"", lambda data: True)[0], b"")

    def test_oracle_rejects_placeholder_hashes_and_escaping_inputs(self):
        from src.core.oracle import load_oracle
        from src.utils.exceptions import ConfigError
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "input").touch()
            case = {"name": "valid", "category": "valid", "input_file": "input",
                    "expected_exit_code": 0, "expected_stdout_hash": "TO_BE_COMPUTED"}
            manifest = root / "oracle.json"
            manifest.write_text(json.dumps({"test_cases": [case]}))
            with self.assertRaises(ConfigError):
                load_oracle(manifest)
            case.update(name="..", input_file="input", expected_stdout_hash="0" * 64)
            manifest.write_text(json.dumps({"test_cases": [case]}))
            with self.assertRaises(ConfigError):
                load_oracle(manifest)
            case.update(name="valid", input_file="../outside", expected_stdout_hash="0" * 64)
            manifest.write_text(json.dumps({"test_cases": [case]}))
            with self.assertRaises(ConfigError):
                load_oracle(manifest)

    def test_report_escapes_untrusted_output(self):
        from src.modules.report_generator import ReportGenerator
        with tempfile.TemporaryDirectory() as tmp:
            ReportGenerator(Path(tmp)).generate({"project": "<script>alert(1)</script>",
                                                "exit_code": 40, "findings": []})
            text = (Path(tmp) / "report.html").read_text()
            self.assertNotIn("<script>", text)
            self.assertIn("&lt;script&gt;", text)

    def test_confirmed_security_issue_takes_priority_over_later_analysis_failure(self):
        from src.modules.classifier import Finding
        from src.orchestrator import PatchValidator
        from src.utils.exceptions import AnalysisError

        class FailingAnalysis(PatchValidator):
            def _run_pipeline(self):
                self.findings.append(Finding("remaining", "IncompleteFix", "confirmed error"))
                raise AnalysisError("Later analysis failed")

        with tempfile.TemporaryDirectory() as tmp:
            validator = FailingAnalysis("unused", tmp)
            self.assertEqual(validator.run(), 10)

    def test_unclassified_signal_is_inconclusive(self):
        from src.modules.classifier import classify
        oracle = {"category": "valid", "expected_exit_code": 0, "expected_stdout": "ok\n"}
        result = self.result(exit_code=-6, signal="SIGABRT", error_type="crash-SIGABRT",
                             detection_mechanism="signal")
        self.assertEqual(classify(self.result(), result, oracle)[0], "Inconclusive")

    def test_unexpected_tool_failure_is_30(self):
        from src.orchestrator import PatchValidator

        class BrokenTool(PatchValidator):
            def _run_pipeline(self):
                raise RuntimeError("Unexpected tool failure")

        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(BrokenTool("unused", tmp).run(), 30)

    def test_complete_fixed_findings_have_pass_verdict(self):
        from src.modules.classifier import Finding, determine_exit_code
        self.assertEqual(determine_exit_code([Finding("fixed", "Fixed", "confirmed")]), 0)


if __name__ == "__main__":
    unittest.main()
