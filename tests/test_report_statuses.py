"""Independent JSON conclusions survive verdict priority and partial runs."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ci.check_reports import BUILDS, check_report
from src.core.test_runner import TestResult
from src.modules.classifier import Finding
from src.orchestrator import PatchValidator
from src.utils.exceptions import AnalysisError, ConfigError


class ReportStatusTests(unittest.TestCase):
    def result(self, name, mode, **changes):
        return TestResult(**{
            "test_name": name, "input_path": Path("input"), "exit_code": 0,
            "signal": None, "stdout": "ok\n", "stderr": "", "timed_out": False,
            "oom_killed": False, "build_type": mode, **changes,
        })

    def evidence(self, validator, *, security="Fixed", functionality="Fixed"):
        validator.cases = [
            {"name": "exploit", "category": "exploit", "expected_exit_code": 0,
             "expected_stdout": "ok\n", "expected_error_type": "heap-buffer-overflow"},
            {"name": "valid", "category": "valid", "expected_exit_code": 0,
             "expected_stdout": "ok\n"},
        ]
        validator.runs = {f"{side}_{mode}": {} for side in ("base", "patched")
                          for mode in ("release", "sanitized")}
        for name, category in (("exploit", security), ("valid", functionality)):
            validator.findings.append(Finding(name, category, "fixture", comparisons={
                mode: {"category": category, "stable": True} for mode in ("release", "sanitized")}))
            for mode in ("release", "sanitized"):
                baseline = ({"exit_code": 1, "error_type": "heap-buffer-overflow",
                             "detection_mechanism": "sanitizer"} if name == "exploit" else {})
                validator.runs[f"base_{mode}"][name] = [self.result(name, mode, **baseline)]
                changes = {}
                if category in ("IncompleteFix", "NewIssue"):
                    changes = {"exit_code": 1, "error_type": "heap-buffer-overflow",
                               "detection_mechanism": "sanitizer"}
                elif category in ("FunctionalRegression", "Inconclusive"):
                    changes = {"stdout": "unexpected\n"}
                validator.runs[f"patched_{mode}"][name] = [self.result(name, mode, **changes)]
        validator.report["results"] = validator.runs

    def test_missing_configuration_has_explicit_unknown_statuses_and_incomplete_analysis(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            validator = PatchValidator(str(root / "missing.yaml"), str(root / "report"))
            self.assertEqual(validator.run(), 30)
            report = json.loads((validator.workspace / "report.json").read_text())
            self.assertEqual(report["security_status"], "inconclusive")
            self.assertEqual(report["functionality_status"], "inconclusive")
            self.assertIs(report["analysis_complete"], False)

    def test_exit_zero_requires_both_statuses_to_pass_and_complete_analysis(self):
        for security, functionality, complete, expected in (
                ("pass", "pass", True, 0),
                ("inconclusive", "pass", True, 40),
                ("pass", "inconclusive", True, 40),
                ("pass", "pass", False, 40)):
            with self.subTest(security=security, functionality=functionality, complete=complete), \
                    tempfile.TemporaryDirectory() as temporary:
                validator = PatchValidator("unused", temporary)

                def run_fixture():
                    self.evidence(validator, functionality="Fixed" if functionality == "pass" else "Inconclusive")
                    if security == "inconclusive":
                        result = validator.runs["base_release"]["exploit"][0]
                        result.exit_code, result.signal = -6, "SIGABRT"
                        result.error_type, result.detection_mechanism = "crash-SIGABRT", "signal"
                        validator.findings[0].comparisons["release"]["category"] = "Inconclusive"
                    if functionality == "inconclusive":
                        for mode in ("release", "sanitized"):
                            validator.runs[f"base_{mode}"]["valid"][0].stdout = "unexpected\n"
                    validator.report.update(exit_code=0, analysis_complete=complete)

                with patch.object(validator, "_run_pipeline", side_effect=run_fixture):
                    actual = validator.run()
                report = json.loads((validator.workspace / "report.json").read_text())
                self.assertEqual(actual, expected)
                self.assertEqual(report["exit_code"], expected)
                self.assertEqual(report["security_status"], security)
                self.assertEqual(report["functionality_status"], functionality)
                self.assertIs(report["analysis_complete"], complete)

    def test_ci_checks_pass_consistency_and_correlation_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name in ("report.md", "report.html", "patch.diff"):
                (directory / name).touch()
            path = directory / "report.json"
            report = {
                "exit_code": 0, "security_status": "pass", "functionality_status": "pass",
                "analysis_complete": True, "errors": [], "warnings": [],
                "builds": {label: {"success": True} for label in BUILDS},
                "results": {label: {"fixture": [{"exit_code": 0}]} for label in BUILDS},
                "hardening": {side: {"status": "checked"} for side in ("base", "patched")},
                "findings": [{"correlation": {label: {"status": "unknown", "evidence": []}
                                              for label in BUILDS}}],
            }
            path.write_text(json.dumps(report))
            check_report(directory, 0)
            for field, value in (("security_status", "inconclusive"), ("functionality_status", "fail"),
                                 ("analysis_complete", False), ("analysis_complete", "false")):
                with self.subTest(field=field, value=value):
                    path.write_text(json.dumps({**report, field: value}))
                    with self.assertRaises(AssertionError):
                        check_report(directory, 0)
            correlation = report["findings"][0]["correlation"]
            correlation["base_sanitized"] = {"status": "changed_line", "evidence": [{"status": "changed_line"}]}
            path.write_text(json.dumps(report))
            check_report(directory, 0)
            for value in ({"status": "same_function", "evidence": [{"status": "same_function"}]},
                          {"status": "changed_line", "evidence": []},
                          {"status": "unknown", "evidence": [{"status": "changed_line"}]}):
                with self.subTest(correlation=value):
                    correlation["base_sanitized"] = value
                    path.write_text(json.dumps(report))
                    with self.assertRaises(AssertionError):
                        check_report(directory, 0)

    def test_late_failures_keep_confirmed_independent_findings(self):
        for failure, expected_exit in ((AnalysisError("late analysis failure"), 10),
                                       (ConfigError("late configuration failure"), 30),
                                       (RuntimeError("late tool failure"), 30)):
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as temporary:
                validator = PatchValidator("unused", temporary)

                def fail_late():
                    self.evidence(validator, security="IncompleteFix", functionality="FunctionalRegression")
                    raise failure

                with patch.object(validator, "_run_pipeline", side_effect=fail_late):
                    self.assertEqual(validator.run(), expected_exit)
                report = json.loads((validator.workspace / "report.json").read_text())
                self.assertEqual(report["security_status"], "fail")
                self.assertEqual(report["functionality_status"], "fail")
                self.assertIs(report["analysis_complete"], False)
                self.assertEqual(len(report["findings"]), 2)

    def test_unfinished_cases_prevent_a_partial_pass_but_keep_confirmed_failures(self):
        with tempfile.TemporaryDirectory() as temporary:
            validator = PatchValidator("unused", temporary)

            def fail_late():
                self.evidence(validator, functionality="FunctionalRegression")
                validator.cases.append({"name": "not_run", "category": "boundary", "expected_exit_code": 0})
                raise AnalysisError("not all cases were classified")

            with patch.object(validator, "_run_pipeline", side_effect=fail_late):
                self.assertEqual(validator.run(), 20)
            report = json.loads((validator.workspace / "report.json").read_text())
            self.assertEqual(report["security_status"], "inconclusive")
            self.assertEqual(report["functionality_status"], "fail")
            self.assertIs(report["analysis_complete"], False)

    def test_reusing_a_validator_does_not_reuse_old_conclusions_after_config_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            validator = PatchValidator("missing.yaml", temporary)
            with patch.object(validator, "_run_pipeline", side_effect=lambda: self.evidence(validator)):
                validator.run()
            self.assertEqual(validator.report["security_status"], "pass")
            self.assertEqual(validator.run(), 30)
            self.assertEqual(validator.report["security_status"], "inconclusive")
            self.assertEqual(validator.report["functionality_status"], "inconclusive")
            self.assertIs(validator.report["analysis_complete"], False)

    def test_functional_uncertainty_does_not_erase_a_confirmed_security_fix(self):
        with tempfile.TemporaryDirectory() as temporary:
            validator = PatchValidator("unused", temporary)

            def run_fixture():
                self.evidence(validator, functionality="Inconclusive")
                for mode in ("release", "sanitized"):
                    validator.runs[f"base_{mode}"]["valid"][0].stdout = "unexpected\n"

            with patch.object(validator, "_run_pipeline", side_effect=run_fixture):
                validator.run()
            self.assertEqual(validator.report["security_status"], "pass")
            self.assertEqual(validator.report["functionality_status"], "inconclusive")

    def test_a_security_error_on_a_previously_correct_input_is_also_a_functional_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            validator = PatchValidator("unused", temporary)
            with patch.object(validator, "_run_pipeline", side_effect=lambda: self.evidence(
                    validator, functionality="NewIssue")):
                validator.run()
            self.assertEqual(validator.report["security_status"], "fail")
            self.assertEqual(validator.report["functionality_status"], "fail")

    def test_uncertain_results_do_not_claim_a_pass_or_functional_regression(self):
        for uncertain in ("resource_limited", "timed_out", "unstable", "signal"):
            with self.subTest(uncertain=uncertain), tempfile.TemporaryDirectory() as temporary:
                validator = PatchValidator("unused", temporary)

                def run_fixture():
                    self.evidence(validator, functionality="Inconclusive")
                    finding = validator.findings[-1]
                    for mode in ("release", "sanitized"):
                        if uncertain == "unstable":
                            finding.comparisons[mode]["stable"] = False
                        elif uncertain == "signal":
                            result = validator.runs[f"patched_{mode}"]["valid"][0]
                            result.exit_code, result.signal = -11, "SIGSEGV"
                            result.error_type, result.detection_mechanism = "crash-SIGSEGV", "signal"
                        else:
                            setattr(validator.runs[f"patched_{mode}"]["valid"][0], uncertain, True)

                with patch.object(validator, "_run_pipeline", side_effect=run_fixture):
                    validator.run()
                self.assertEqual(validator.report["security_status"], "inconclusive")
                self.assertEqual(validator.report["functionality_status"], "inconclusive")

    def test_report_render_failure_updates_the_surviving_json_and_return_code(self):
        with tempfile.TemporaryDirectory() as temporary:
            validator = PatchValidator("unused", temporary)
            write_text = Path.write_text

            def write(path, data, **kwargs):
                if path.name == "report.md":
                    raise PermissionError("summary is read-only")
                return write_text(path, data, **kwargs)

            def run_fixture():
                self.evidence(validator)
                validator.report.update(exit_code=0, analysis_complete=True)

            with patch.object(validator, "_run_pipeline", side_effect=run_fixture), \
                    patch.object(Path, "write_text", write):
                self.assertEqual(validator.run(), 30)
            report = json.loads((validator.workspace / "report.json").read_text())
            self.assertEqual(report["exit_code"], 30)
            self.assertEqual(report["security_status"], "pass")
            self.assertEqual(report["functionality_status"], "pass")
            self.assertIs(report["analysis_complete"], False)
            self.assertIn("summary is read-only", report["errors"][-1])


if __name__ == "__main__":
    unittest.main()
