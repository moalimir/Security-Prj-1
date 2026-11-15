"""Regression corpus persistence using harmless programs and synthetic findings."""
import json
from dataclasses import replace
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import yaml

from src.core.oracle import load_oracle
from src.core.test_runner import TestRunner
from src.modules.classifier import Finding
from src.modules.report_generator import json_default
from src.orchestrator import PatchValidator


class RegressionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="regression corpus ")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.repo = self.root / "repository"
        self.repo.mkdir()
        for args in (("init", "-q"), ("config", "user.name", "Fixture"),
                     ("config", "user.email", "fixture@example.invalid")):
            subprocess.run(["git", *args], cwd=self.repo, check=True, capture_output=True)
        (self.repo / "program.py").write_text('print("ok")\n')
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-qm", "harmless fixture"], cwd=self.repo, check=True, capture_output=True)
        (self.root / "input").write_bytes(b"harmless input")
        cases = [{"name": category, "category": category, "input_file": "input",
                  "expected_exit_code": 0, "expected_stdout": "ok\n"}
                 for category in ("valid", "boundary", "invalid", "exploit")]
        cases[-1]["expected_error_type"] = "fixture-not-reproduced"
        self.manifest = self.root / "oracle_manifest.json"
        self.manifest.write_text(json.dumps({"test_cases": cases}))
        self.corpus = self.root / "corpus"
        self.corpus.mkdir()
        command = "cp program.py {output_dir}/program.py && chmod +x {output_dir}/program.py"
        self.raw_config = {
            "project_name": "fixture", "repository_path": self.repo.name,
            "base_commit": "HEAD", "patched_commit": "HEAD",
            "build": {"release_cmd": command, "sanitized_cmd": command,
                      "release_binary": "program.py", "sanitized_binary": "program.py"},
            "execution": {"cmd_template": f"{shlex.quote(sys.executable)} {{binary}} {{input_file}}"},
            "test_suites": {"oracle_manifest": self.manifest.name, "regression_dir": self.corpus.name},
        }
        self.config = self.root / "config.yaml"
        self.config.write_text(yaml.safe_dump(self.raw_config))

    def run_validator(self, name):
        validator = PatchValidator(str(self.config), str(self.root / name), skip_hardening=True)
        self.assertEqual(validator.run(), 40, validator.report["errors"])
        self.assertFalse(validator.report["errors"])
        return validator

    def test_generated_cases_survive_new_output_and_repository_paths(self):
        first = self.run_validator("first report")
        first._save_regression(load_oracle(self.manifest)[-1], b"harmless input")
        persistent = self.corpus / "oracle_manifest.json"
        self.assertTrue(persistent.is_file())
        generated = load_oracle(persistent)[0]
        shutil.rmtree(first.workspace)
        relocated = self.root / "relocated repository"
        subprocess.run(["git", "clone", "-q", str(self.repo), str(relocated)], check=True, capture_output=True)
        self.raw_config["repository_path"] = relocated.name
        self.config.write_text(yaml.safe_dump(self.raw_config))
        second = self.run_validator("fresh report")
        self.assertEqual(len(second.cases), 5)
        for results in second.report["results"].values():
            self.assertIn(generated["name"], results)

    def test_identical_corpus_copies_reload_but_conflicting_inputs_fail(self):
        first = self.run_validator("report")
        first._save_regression(load_oracle(self.manifest)[-1], b"harmless input")
        self.assertEqual(first.run(), 40, first.report["errors"])
        self.assertEqual(len(first.cases), 5)
        generated = load_oracle(first.regression_dir / "oracle_manifest.json")[0]
        Path(generated["input_path"]).write_bytes(b"conflicting copy")
        self.assertEqual(first.run(), 30)
        self.assertIn("Duplicate test name", first.report["errors"][0])

    def test_corpus_write_failures_return_30_and_persist_failure_reports(self):
        from src.modules.report_generator import write_json

        for failure in ("input", "manifest"):
            with self.subTest(failure=failure):
                validator = PatchValidator(str(self.config), str(self.root / f"failed {failure}"),
                                           skip_hardening=True)
                write_bytes = Path.write_bytes

                def save_fixture(case, finding):
                    if case["category"] == "exploit":
                        validator._save_regression(case, Path(case["input_path"]).read_bytes())

                def save_input(path, data):
                    if failure == "input" and path.parent == self.corpus:
                        raise PermissionError("corpus input is read-only")
                    return write_bytes(path, data)

                def save_manifest(path, data):
                    if failure == "manifest" and path.parent == self.corpus:
                        raise OSError("corpus manifest disk is full")
                    return write_json(path, data)

                with patch.object(validator, "_bundle", side_effect=save_fixture), \
                        patch.object(Path, "write_bytes", save_input), \
                        patch("src.orchestrator.write_json", side_effect=save_manifest):
                    self.assertEqual(validator.run(), 30)
                report = json.loads((validator.workspace / "report.json").read_text())
                self.assertEqual(report["exit_code"], 30)
                self.assertIn(str(self.corpus), report["errors"][0])
                self.assertIn("Cannot save regression corpus", report["errors"][0])
                self.assertFalse(report.get("analysis_complete", False))
                self.assertFalse((self.corpus / "oracle_manifest.json").exists())

    def test_new_issues_generate_oracle_preserving_cases_and_replay_checks(self):
        from ci.check_reports import check_replays

        (self.root / "input").write_bytes(b"prefix!suffix")
        generated_names = set()
        for category in ("valid", "boundary", "invalid"):
            validator = self.run_validator(f"new {category}")
            case = next(case for case in validator.cases if case["name"] == category)
            clean = validator.runs["base_sanitized"][category][0]
            diagnostic = TestRunner._parse_asan_output(
                "ERROR: AddressSanitizer: heap-buffer-overflow\n#0 0x123 in parse /fixture/source/parser.c:8:1\n")
            crash = replace(clean, exit_code=1, error_type=diagnostic.error_type,
                            detection_mechanism="sanitizer", sanitizer_report=diagnostic)
            for label in validator.runs:
                validator.runs[label][category] *= 3
            validator.runs["patched_sanitized"][category] = [crash] * 3

            def execute(binary, input_path, mode):
                if binary == validator.builds["patched_sanitized"].binary_path:
                    return crash
                return replace(clean, build_type=mode,
                               stdout="ok\n" if b"!" in input_path.read_bytes() else "different output\n")

            with patch.object(validator.runner, "run_single_test", side_effect=execute):
                validator._bundle(case, Finding(category, "NewIssue", "synthetic diagnostic"))
            manifest = self.corpus / "oracle_manifest.json"
            self.assertTrue(manifest.is_file(), "NewIssue was not added to the project corpus")
            generated = next(entry for entry in load_oracle(manifest) if entry["category"] == category)
            self.assertEqual(Path(generated["input_path"]).read_bytes(), b"!")
            self.assertEqual(generated["expected_stdout"], case["expected_stdout"])
            self.assertEqual(generated["expected_exit_code"], case["expected_exit_code"])
            self.assertNotIn("expected_error_type", generated)
            generated_names.add(generated["name"])

            def replay(command, **options):
                label = command[command.index("--build") + 1]
                result = crash if label == "patched_sanitized" else clean
                return SimpleNamespace(stdout=json.dumps(result, default=json_default),
                                       stderr="", returncode=result.exit_code)

            with patch("ci.check_reports.subprocess.run", side_effect=replay):
                check_replays(validator.workspace)
        self.assertEqual(len(generated_names), 3, "Distinct oracle contracts must not collide")
        fixed = self.run_validator("fixed patch fresh workspace")
        findings = {finding.test_name: finding.category for finding in fixed.findings}
        self.assertTrue(all(findings[name] == "Fixed" for name in generated_names))

    def test_unstable_new_issue_is_bundled_without_publishing_a_regression(self):
        validator = self.run_validator("unstable")
        clean = validator.runs["patched_sanitized"]["valid"][0]
        diagnostic = TestRunner._parse_asan_output(
            "ERROR: AddressSanitizer: heap-buffer-overflow\n#0 0x123 in parse /fixture/source/parser.c:8:1\n")
        crash = replace(clean, exit_code=1, error_type=diagnostic.error_type,
                        detection_mechanism="sanitizer", sanitizer_report=diagnostic)
        validator.runs["patched_sanitized"]["valid"] = [crash, clean, crash]
        case = next(case for case in validator.cases if case["name"] == "valid")
        finding = Finding("valid", "Inconclusive", "unstable diagnostic")
        validator._bundle(case, finding)
        self.assertTrue(Path(finding.reproducer_path).is_dir())
        self.assertFalse((self.corpus / "oracle_manifest.json").exists())


if __name__ == "__main__":
    unittest.main()
