"""Exercise unseen-patch isolation with real Git repositories."""
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

from src import unseen_patch as eval_unseen_patch
from src.orchestrator import main as validator_main


class UnseenPatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="unseen patch test ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.repo = self.root / "source repository"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        (self.repo / "target.c").write_text("original\n")
        self.git("add", "target.c")
        self.git("commit", "-qm", "base")
        self.git("tag", "base")
        (self.repo / "target.c").write_text("corrected\n")
        self.git("commit", "-qam", "candidate")
        self.git("tag", "candidate")
        self.patch_path = self.root / "unseen changes.patch"
        self.patch_path.write_text(self.git("diff", "base", "candidate"))
        self.git("checkout", "-q", "base")
        (self.repo / "untracked.txt").write_text("preserve me")
        self.manifest = self.root / "oracle manifest.json"
        self.manifest.write_text('{"test_cases": []}')
        self.config = self.root / "base config.yaml"
        self.config.write_text(yaml.safe_dump({
            "project_name": "fixture", "repository_path": self.repo.name,
            "base_commit": "base", "patched_commit": "candidate",
            "build": {"release_cmd": "cc target.c", "sanitized_cmd": "cc target.c",
                      "release_binary": "a.out", "sanitized_binary": "a.out"},
            "test_suites": {"oracle_manifest": self.manifest.name},
        }))
        self.output = self.root / "output directory"

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.repo, check=True,
                              text=True, capture_output=True).stdout

    def args(self, *candidate):
        return ["--base-config", str(self.config), *candidate, "--output-dir", str(self.output)]

    def test_patch_paths_with_spaces_are_isolated_and_archived(self):
        seen = {}

        def validate(config, output, **options):
            cfg = yaml.safe_load(config.read_text())
            clone = Path(cfg["repository_path"])
            self.assertNotEqual(clone, self.repo)
            self.assertEqual((clone / "target.c").read_text(), "corrected\n")
            self.assertEqual(cfg["test_suites"]["oracle_manifest"], str(self.manifest))
            self.assertTrue(Path(cfg["test_suites"]["oracle_manifest"]).is_file())
            self.assertEqual(len(cfg["patched_commit"]), 40)
            self.assertEqual(output, self.output)
            seen.update(cfg)
            return 20

        with patch.object(eval_unseen_patch, "_run_validator", side_effect=validate):
            self.assertEqual(eval_unseen_patch.main(self.args("--patch-file", str(self.patch_path))), 20)
        self.assertEqual((self.repo / "target.c").read_text(), "original\n")
        self.assertEqual((self.repo / "untracked.txt").read_text(), "preserve me")
        self.assertEqual(self.git("status", "--porcelain"), "?? untracked.txt\n")
        evidence = self.output / "unseen"
        self.assertEqual((evidence / "submitted.patch").read_bytes(), self.patch_path.read_bytes())
        self.assertEqual(json.loads((evidence / "metadata.json").read_text())["validator_exit_code"], 20)
        restored = self.root / "restored repository"
        subprocess.run(["git", "clone", "-q", str(evidence / "source.bundle"), str(restored)], check=True)
        actual = subprocess.run(["git", "show", f"{seen['patched_commit']}:target.c"], cwd=restored,
                                text=True, capture_output=True, check=True).stdout
        self.assertEqual(actual, "corrected\n")
        self.assertFalse(Path(seen["repository_path"]).exists())

    def test_bad_patch_fails_without_running_validator_or_changing_source(self):
        self.patch_path.write_text("not a patch\n")
        with patch.object(eval_unseen_patch, "_run_validator") as validate:
            self.assertEqual(eval_unseen_patch.main(self.args("--patch-file", str(self.patch_path))), 30)
            validate.assert_not_called()
        self.assertEqual((self.repo / "target.c").read_text(), "original\n")

    def test_patched_commit_uses_verified_commit_without_rewriting_it(self):
        expected = self.git("rev-parse", "candidate").strip()
        with patch.object(eval_unseen_patch, "_run_validator", return_value=10):
            self.assertEqual(eval_unseen_patch.main(self.args("--patched-commit", "candidate")), 10)
        config = yaml.safe_load((self.output / "unseen" / "config.evaluated.yaml").read_text())
        self.assertEqual(config["patched_commit"], expected)
        self.assertIn("+corrected", (self.output / "unseen" / "evaluated.patch").read_text())

    def test_invalid_ref_and_existing_evidence_are_not_overwritten(self):
        with patch.object(eval_unseen_patch, "_run_validator") as validate:
            self.assertEqual(eval_unseen_patch.main(self.args("--patched-commit=--help")), 30)
            validate.assert_not_called()
        self.output.mkdir(exist_ok=True)
        (self.output / "unseen").mkdir(exist_ok=True)
        marker = self.output / "unseen" / "metadata.json"
        marker.write_text("preserve me")
        self.assertEqual(eval_unseen_patch.main(self.args("--patched-commit", "candidate")), 30)
        self.assertEqual(marker.read_text(), "preserve me")

    def test_patch_commit_is_deterministic(self):
        commits = []
        with patch.object(eval_unseen_patch, "_run_validator", return_value=0):
            for name in ("first", "second"):
                self.output = self.root / name
                candidate = self.root / f"{name}.patch"
                candidate.write_bytes(self.patch_path.read_bytes())
                self.assertEqual(eval_unseen_patch.main(self.args("--patch-file", str(candidate))), 0)
                metadata = json.loads((self.output / "unseen" / "metadata.json").read_text())
                commits.append(metadata["patched_commit"])
        self.assertEqual(commits[0], commits[1])

    def test_candidate_flags_are_required_and_mutually_exclusive(self):
        for candidate in ([], ["--patch-file", str(self.patch_path), "--patched-commit", "candidate"]):
            with self.assertRaises(SystemExit) as result:
                eval_unseen_patch.main(self.args(*candidate))
            self.assertEqual(result.exception.code, 30)

    def test_main_cli_forwards_validator_verdicts_and_skip_options(self):
        def validate(config, output, **options):
            cfg = yaml.safe_load(config.read_text())
            clone = Path(cfg["repository_path"])
            self.assertEqual((clone / "target.c").read_text(), "corrected\n")
            self.assertNotEqual(clone, self.repo)
            self.assertEqual(options, {"skip_minimize": True, "skip_hardening": True})
            return code

        for code in (0, 10, 20, 30, 40):
            with self.subTest(code=code):
                self.output = self.root / f"verdict {code}"
                with patch.object(eval_unseen_patch, "_run_validator", side_effect=validate):
                    actual = validator_main(["--config", str(self.config), "--patch", str(self.patch_path),
                                             "-o", str(self.output), "--skip-minimize", "--skip-hardening"])
                self.assertEqual(actual, code)
                self.assertEqual((self.repo / "target.c").read_text(), "original\n")
                metadata = json.loads((self.output / "unseen" / "metadata.json").read_text())
                self.assertEqual(metadata["rerun_command"][-2:], ["--skip-minimize", "--skip-hardening"])

    def test_main_cli_without_patch_keeps_normal_pipeline(self):
        with patch("src.orchestrator.PatchValidator") as validator:
            validator.return_value.run.return_value = 40
            self.assertEqual(validator_main(["-c", str(self.config), "-o", str(self.output)]), 40)
            validator.assert_called_once_with(str(self.config), str(self.output),
                                              skip_minimize=False, skip_hardening=False)

    def test_unseen_path_uses_the_standard_validator(self):
        with patch("src.orchestrator.PatchValidator") as validator:
            validator.return_value.run.return_value = 20
            self.assertEqual(eval_unseen_patch._run_validator(self.config, self.output,
                            skip_minimize=True, skip_hardening=False), 20)
            validator.assert_called_once_with(str(self.config), str(self.output),
                                              skip_minimize=True, skip_hardening=False)

    def test_cli_runs_a_harmless_patch_through_all_four_builds(self):
        (self.repo / "target.c").write_text('print("ok")\n')
        self.git("commit", "-qam", "harmless base")
        base = self.git("rev-parse", "HEAD").strip()
        (self.repo / "target.c").write_text('print("ok")\n# harmless patch\n')
        self.git("commit", "-qam", "harmless candidate")
        self.patch_path.write_text(self.git("diff", base, "HEAD"))
        self.git("checkout", "-q", base)
        cfg = yaml.safe_load(self.config.read_text())
        cfg.update(base_commit=base, patched_commit="unused-unresolvable-ref")
        cfg["build"] = {"release_cmd": "cp target.c {output_dir}/program.py && chmod +x {output_dir}/program.py",
                        "sanitized_cmd": "cp target.c {output_dir}/program.py && chmod +x {output_dir}/program.py",
                        "release_binary": "program.py", "sanitized_binary": "program.py"}
        cfg["execution"] = {"cmd_template": f"{shlex.quote(sys.executable)} {{binary}} {{input_file}}"}
        self.config.write_text(yaml.safe_dump(cfg))
        (self.root / "harmless.input").write_text("harmless input\n")
        cases = [{"name": category, "category": category, "input_file": "harmless.input",
                  "expected_exit_code": 0, "expected_stdout": "ok\n"}
                 for category in ("valid", "boundary", "invalid", "exploit")]
        cases[-1]["expected_error_type"] = "fixture-not-reproduced"
        self.manifest.write_text(json.dumps({"test_cases": cases}))
        proc = subprocess.run([sys.executable, "-m", "src", "-c", str(self.config),
                               "--patch", str(self.patch_path), "-o", str(self.output)],
                              cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 40, proc.stderr)
        report = json.loads((self.output / "report.json").read_text())
        self.assertEqual(report["exit_code"], 40)
        self.assertEqual(len(report["builds"]), 4)
        self.assertTrue(all(build["success"] for build in report["builds"].values()))
        for mode in report["results"].values():
            self.assertEqual(set(mode), {case["name"] for case in cases})
            self.assertTrue(all(runs[0]["exit_code"] == 0 for runs in mode.values()))
        self.assertEqual(report["findings"][-1]["category"], "Inconclusive")
        self.assertEqual((self.repo / "untracked.txt").read_text(), "preserve me")


if __name__ == "__main__":
    unittest.main()
