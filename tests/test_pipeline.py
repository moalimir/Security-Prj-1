import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from src.orchestrator import PatchValidator

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("clang") or shutil.which("gcc"), "C compiler required")
class PipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="pipeline space ")
        cls.demo = Path(cls.temp.name) / "demo"
        subprocess.run([sys.executable, str(ROOT / "tools/prepare_demo.py"),
                        "--output-dir", str(cls.demo)], check=True, capture_output=True, text=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_real_c_patch_variants_and_replay_bundles(self):
        for variant, expected in (("correct", 40), ("incomplete", 10), ("regression", 20)):
            with self.subTest(variant=variant):
                output = self.demo / f"reports-{variant}"
                validator = PatchValidator(str(self.demo / f"{variant}.yaml"), str(output), skip_hardening=True)
                self.assertEqual(validator.run(), expected, validator.report.get("errors"))
                report = json.loads((output / "report.json").read_text())
                self.assertEqual(report["exit_code"], expected)
                self.assertEqual(len(report["builds"]), 4)
                self.assertEqual(len(report["results"]), 4)
                self.assertTrue(all(b["binary_hash"] for b in report["builds"].values()))
                self.assertTrue((output / "report.html").exists())
                self.assertTrue((output / "report.md").exists())
                metadata = list((output / "reproducers").glob("*/metadata.json"))
                self.assertTrue(metadata)
                bundle = json.loads(metadata[0].read_text())
                self.assertEqual(len(bundle["original_executions"]["base_sanitized"]), 3)
                for run in bundle["original_executions"]["base_sanitized"]:
                    self.assertGreater(run["exit_code"], 0)
                    self.assertIsNone(run["signal"])
                self.assertTrue(bundle["minimized_replays"])
                self.assertEqual(len(bundle["minimized_executions"]), 4)
                self.assertTrue(list((output / "regression").glob("*/oracle_manifest.json")))
                if variant == "correct":
                    replay = subprocess.run([sys.executable, "-m", "src.replay", str(metadata[0].parent),
                                             "--build", "patched_sanitized", "--minimized"],
                                            capture_output=True, text=True)
                    self.assertEqual(replay.returncode, 1, replay.stderr)
                    self.assertEqual(json.loads(replay.stdout)["exit_code"], 1)
                    original_count = len(report["findings"])
                    self.assertEqual(validator.run(), 40, validator.report.get("errors"))
                    self.assertGreater(len(validator.findings), original_count)

    def test_missing_commit_returns_30_and_persists_failure_report(self):
        import yaml
        config = yaml.safe_load((self.demo / "correct.yaml").read_text())
        config["base_commit"] = "missing-commit"
        path = self.demo / "missing.yaml"
        path.write_text(yaml.safe_dump(config))
        validator = PatchValidator(str(path), str(self.demo / "missing-report"), skip_hardening=True)
        self.assertEqual(validator.run(), 30)
        self.assertTrue(validator.report["errors"])

    def test_empty_oracle_and_partial_build_cannot_pass(self):
        import yaml
        config = yaml.safe_load((self.demo / "correct.yaml").read_text())
        config["build"]["sanitized_cmd"] = "false"
        path = self.demo / "build-failure.yaml"
        path.write_text(yaml.safe_dump(config))
        validator = PatchValidator(str(path), str(self.demo / "build-failure"), skip_hardening=True)
        self.assertEqual(validator.run(), 30)
        (self.demo / "empty-oracle.json").write_text('{"test_cases": []}')
        config["test_suites"]["oracle_manifest"] = "empty-oracle.json"
        path.write_text(yaml.safe_dump(config))
        self.assertEqual(validator.run(), 30)

    def test_unreproduced_oracle_returns_40(self):
        import yaml
        config = yaml.safe_load((self.demo / "correct.yaml").read_text())
        oracle = json.loads((self.demo / "inputs/oracle_manifest.json").read_text())
        for case in oracle["test_cases"]:
            if case["category"] == "exploit":
                case["expected_error_type"] = "division-by-zero"
        (self.demo / "inputs/unreproduced.json").write_text(json.dumps(oracle))
        config["test_suites"]["oracle_manifest"] = "inputs/unreproduced.json"
        path = self.demo / "unreproduced.yaml"
        path.write_text(yaml.safe_dump(config))
        validator = PatchValidator(str(path), str(self.demo / "unreproduced"),
                                   skip_hardening=True, skip_minimize=True)
        self.assertEqual(validator.run(), 40)

    def test_timeout_cannot_be_reported_as_fixed(self):
        import yaml
        config = yaml.safe_load((self.demo / "correct.yaml").read_text())
        config["execution"]["timeout_sec"] = 0.1
        config["execution"]["cmd_template"] = f'"{sys.executable}" -c "import time; time.sleep(5)" {{binary}}'
        path = self.demo / "timeout.yaml"
        path.write_text(yaml.safe_dump(config))
        validator = PatchValidator(str(path), str(self.demo / "timeout-report"),
                                   skip_hardening=True, skip_minimize=True)
        self.assertEqual(validator.run(), 40)
        self.assertTrue(any(r[0].timed_out for cases in validator.report["results"].values() for r in cases.values()))


if __name__ == "__main__":
    unittest.main()
