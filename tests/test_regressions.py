"""Regression corpus persistence using harmless programs and synthetic findings."""
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml

from src.core.oracle import load_oracle
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


if __name__ == "__main__":
    unittest.main()
