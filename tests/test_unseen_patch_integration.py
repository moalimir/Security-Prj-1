"""Real patch-file CLI runs with compiled, harmless diagnostic fixtures.

These tests exercise orchestration and classification, not sanitizer accuracy.
"""
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("cc"), "A C compiler is required")
class UnseenPatchIntegrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="unseen integration ")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.repo = self.root / "source repository"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.source = (ROOT / "tests/fixtures/unseen_target.c").read_text()
        self.target = self.repo / "target.c"
        self.target.write_text(self.source)
        self.git("add", "target.c")
        self.git("commit", "-qm", "harmless baseline")
        self.base = self.git("rev-parse", "HEAD").strip()
        (self.repo / "untracked.txt").write_text("preserve me")
        self.fixed = self.source.replace('strcmp(value, "exploit") == 0 || ', "")
        self.cases = []
        for category in ("valid", "boundary", "invalid", "exploit"):
            self.add_case(category, category, category)
        command = f"{shlex.quote(shutil.which('cc'))} -std=c99 -O0 -g target.c -o {{output_dir}}/program"
        self.config = {
            "project_name": "unseen integration", "repository_path": str(self.repo),
            "base_commit": self.base, "patched_commit": "unused-unresolvable-ref",
            "build": {"release_cmd": command, "sanitized_cmd": command + " -DFIXTURE_SANITIZED",
                      "release_binary": "program", "sanitized_binary": "program"},
            "execution": {"cmd_template": "{binary} {input_file}"},
            "test_suites": {"oracle_manifest": str(self.root / "oracle.json")},
        }

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.repo, check=True,
                              capture_output=True, text=True).stdout

    def add_case(self, name, category, data, stdout="ok\n"):
        (self.root / f"{name}.input").write_text(data)
        case = {"name": name, "category": category, "input_file": f"{name}.input",
                "expected_exit_code": 0, "expected_stdout": stdout}
        if category == "exploit":
            case["expected_error_type"] = "heap-buffer-overflow"
        self.cases.append(case)

    def evaluate(self, candidate, expected_exit, *, standalone=False):
        self.target.write_text(candidate)
        submitted = self.git("diff", "--binary", "HEAD", "--", "target.c")
        self.git("checkout", "--", "target.c")
        config = self.root / "base config.yaml"
        config.write_text(yaml.safe_dump(self.config))
        (self.root / "oracle.json").write_text(json.dumps({"test_cases": self.cases}))
        patch_file = self.root / "submitted changes.patch"
        patch_file.write_text(submitted)
        self.output = self.root / "output directory"
        entry = ([str(ROOT / "tools/eval_unseen_patch.py"), "--base-config", str(config),
                  "--patch-file", str(patch_file)] if standalone else
                 ["-m", "src", "--config", str(config), "--patch", str(patch_file)])
        proc = subprocess.run([sys.executable, *entry, "--output-dir", str(self.output)],
                              cwd=ROOT, capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, expected_exit, proc.stdout + proc.stderr)
        report = json.loads((self.output / "report.json").read_text())
        self.assertEqual(report["exit_code"], expected_exit)
        metadata = json.loads((self.output / "unseen/metadata.json").read_text())
        self.assertEqual(metadata["validator_exit_code"], expected_exit)
        self.assertEqual(metadata["base_commit"], self.base)
        self.assertNotEqual(metadata["patched_commit"], self.base)
        self.assertEqual((self.output / "unseen/evaluated.patch").read_text(), submitted)
        self.assertEqual(self.target.read_text(), self.source)
        self.assertEqual(self.git("status", "--porcelain"), "?? untracked.txt\n")
        self.assertEqual((self.repo / "untracked.txt").read_text(), "preserve me")
        self.assertEqual(set(report["builds"]), {
            "base_release", "base_sanitized", "patched_release", "patched_sanitized"})
        if expected_exit != 30:
            self.assertEqual(report["errors"], [])
            for label, build in report["builds"].items():
                self.assertTrue(build["success"], build["build_log"])
                self.assertEqual(build["commit_hash"], metadata[f"{label.split('_')[0]}_commit"])
                self.assertEqual(set(report["results"][label]), {case["name"] for case in self.cases})
        return report

    @staticmethod
    def findings(report):
        return {finding["test_name"]: finding for finding in report["findings"]}

    def test_fixed_patch_completes_real_builds_replays_and_minimization(self):
        # A native non-ELF build cannot establish the required Linux hardening evidence.
        expected = 0 if sys.platform.startswith("linux") else 40
        report = self.evaluate(self.fixed, expected)
        self.assertEqual({f["category"] for f in report["findings"]}, {"Fixed"})
        self.assertEqual(report["analysis_complete"], sys.platform.startswith("linux"))
        self.assertEqual(report["hardening"]["patched"]["status"],
                         "checked" if sys.platform.startswith("linux") else "unsupported")
        for label, results in report["results"].items():
            self.assertEqual(len(results["exploit"]), 3)
            error = "heap-buffer-overflow" if label == "base_sanitized" else None
            self.assertEqual([result["error_type"] for result in results["exploit"]], [error] * 3)
        bundle = json.loads((self.output / "reproducers/exploit/metadata.json").read_text())
        self.assertEqual(bundle["minimization_status"], "unchanged")
        self.assertGreater(bundle["attempts"], 0)
        self.assertEqual(len(bundle["minimized_replays"]), 3)

    def test_line_insertions_preserve_the_existing_error_identity(self):
        report = self.evaluate("/* harmless insertion */\n\n" + self.source, 10)
        finding = self.findings(report)["exploit"]
        self.assertEqual(finding["category"], "IncompleteFix")
        self.assertTrue(finding["comparisons"]["sanitized"]["stable"])
        base = report["results"]["base_sanitized"]["exploit"][0]["sanitizer_report"]["stack_frames"][0]
        patched = report["results"]["patched_sanitized"]["exploit"][0]["sanitizer_report"]["stack_frames"][0]
        self.assertEqual(patched["line_number"], base["line_number"] + 2)

    def test_caller_changes_are_correlated_without_changing_the_error_site(self):
        candidate = self.source.replace("emit_diagnostic(__LINE__)", "emit_diagnostic(__LINE__ + 0)")
        report = self.evaluate(candidate, 10)
        finding = self.findings(report)["exploit"]
        self.assertEqual(finding["category"], "IncompleteFix")
        correlation = finding["correlation"]["patched_sanitized"]
        self.assertEqual(correlation["status"], "changed_line")
        changed = [item for item in correlation["evidence"] if item["status"] == "changed_line"]
        self.assertEqual([(item["frame_role"], item["frame_id"], item["function"]) for item in changed],
                         [("caller", 1, "main")])

    def test_functional_regression_outweighs_an_inconclusive_case(self):
        self.add_case("unobserved", "exploit", "unobserved")
        candidate = self.fixed.replace('    puts("ok");',
                                      '    if (strcmp(value, "valid") == 0) { puts("changed"); return 0; }\n'
                                      '    puts("ok");')
        report = self.evaluate(candidate, 20)
        self.assertEqual({name: f["category"] for name, f in self.findings(report).items()}, {
            "valid": "FunctionalRegression", "boundary": "Fixed", "invalid": "Fixed",
            "exploit": "Fixed", "unobserved": "Inconclusive"})

    def test_patch_build_failure_returns_30_with_source_and_failure_evidence(self):
        report = self.evaluate("#error deliberate fixture build failure\n" + self.fixed, 30)
        self.assertIn("Required patched build failed", report["errors"][0])
        self.assertTrue(report["builds"]["base_sanitized"]["success"])
        for mode in ("release", "sanitized"):
            build = report["builds"][f"patched_{mode}"]
            self.assertFalse(build["success"])
            self.assertIn("deliberate fixture build failure", build["build_log"])
        self.assertTrue((self.output / "unseen/source.bundle").is_file())

    def test_disappearing_error_without_oracle_correctness_is_inconclusive(self):
        candidate = self.fixed.replace('    puts("ok");',
                                      '    if (strcmp(value, "exploit") == 0) { puts("unexpected"); return 0; }\n'
                                      '    puts("ok");')
        report = self.evaluate(candidate, 40)
        self.assertEqual(self.findings(report)["exploit"]["category"], "Inconclusive")
        for mode in ("release", "sanitized"):
            result = report["results"][f"patched_{mode}"]["exploit"][0]
            self.assertIsNone(result["error_type"])
            self.assertEqual(result["stdout"], "unexpected\n")

    def test_security_findings_outweigh_mixed_functional_and_inconclusive_findings(self):
        self.add_case("remaining", "exploit", "remaining")
        self.add_case("unobserved", "exploit", "unobserved")
        candidate = self.fixed.replace('    puts("ok");',
                                      '#ifdef FIXTURE_SANITIZED\n'
                                      '    if (strcmp(value, "boundary") == 0) return emit_diagnostic(__LINE__);\n'
                                      '#endif\n'
                                      '    if (strcmp(value, "valid") == 0) { puts("changed"); return 0; }\n'
                                      '    puts("ok");')
        report = self.evaluate(candidate, 10)
        self.assertEqual({name: f["category"] for name, f in self.findings(report).items()}, {
            "valid": "FunctionalRegression", "boundary": "NewIssue", "invalid": "Fixed",
            "exploit": "Fixed", "remaining": "IncompleteFix", "unobserved": "Inconclusive"})

    def test_argument_inputs_preserve_empty_values_spaces_and_shell_characters(self):
        marker = self.root / "must not exist"
        literal = f'two words "quoted"; $(touch {shlex.quote(str(marker))}) `touch {shlex.quote(str(marker))}`\n--flag'
        self.add_case("args_literal", "valid", "echo:" + literal, stdout=literal)
        self.add_case("args_empty", "boundary", "")
        self.config["execution"] = {"input_mode": "args", "cmd_template": "{binary} {input}"}
        for mode in ("release", "sanitized"):
            self.config["build"][f"{mode}_cmd"] += " -DINPUT_ARGS"
        report = self.evaluate(self.fixed, 0 if sys.platform.startswith("linux") else 40, standalone=True)
        for results in report["results"].values():
            self.assertEqual(results["args_literal"][0]["stdout"], literal)
            self.assertEqual(results["args_literal"][0]["exit_code"], 0)
            self.assertEqual(results["args_empty"][0]["stdout"], "ok\n")
            self.assertEqual(results["args_empty"][0]["exit_code"], 0)
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
