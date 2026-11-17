"""Check submission archives and scenario orchestration with inert fixtures."""
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from ci.check_reports import BUILDS
from tools import package_submission, verify_all_scenarios


class SubmissionToolsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        (self.root / "پروژه ۱.pdf").write_bytes(b"inert PDF fixture")
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)
        for variant, expected, _, _ in verify_all_scenarios.SCENARIOS:
            directory = self.root / "reports/container_verified" / variant
            directory.mkdir(parents=True)
            report = {
                "exit_code": expected, "errors": [], "warnings": [], "analysis_complete": True,
                "security_status": "pass", "functionality_status": "pass",
                "builds": {label: {"success": True} for label in BUILDS},
                "results": {label: {"fixture": []} for label in BUILDS},
                "hardening": {side: {"status": "checked", "relro": "full", "nx": True,
                                      "pie": True, "canary": True} for side in ("base", "patched")},
                "findings": [{"correlation": {label: {"status": "unknown", "evidence": []}
                                               for label in BUILDS}}],
            }
            if variant == "tlv_hardening_warn":
                report["hardening"]["patched"].update(canary=False, relro="partial")
                report["warnings"] = ["Hardening decreased: canary", "Hardening decreased: RELRO"]
            (directory / "report.json").write_text(json.dumps(report))
            for name in ("report.md", "report.html", "patch.diff"):
                (directory / name).touch()
        self.addCleanup(patch.stopall)
        patch.object(package_submission, "ROOT", self.root).start()
        patch.object(package_submission, "OUTPUT_DIR", self.root / "dist").start()

    def test_archive_keeps_unicode_paths_and_previous_archive_on_write_failure(self):
        with redirect_stdout(StringIO()):
            archive = package_submission.package()
        with zipfile.ZipFile(archive) as package:
            self.assertEqual(package.read("پروژه ۱.pdf"), b"inert PDF fixture")
        previous = archive.read_bytes()
        with patch.object(zipfile.ZipFile, "write", side_effect=OSError("archive disk is full")), \
                redirect_stdout(StringIO()), self.assertRaises(OSError):
            package_submission.package()
        self.assertEqual(archive.read_bytes(), previous)

    def test_missing_scenario_report_prevents_packaging(self):
        (self.root / "reports/container_verified/cjson_correct/report.json").unlink()
        with redirect_stdout(StringIO()), self.assertRaises((OSError, AssertionError)):
            package_submission.package()

    def test_verifier_builds_current_image_and_persists_target_regressions(self):
        commands = []

        def execute(command, **options):
            commands.append(command)
            code = 0
            if command[:2] == ["docker", "run"] and "--config" in command:
                variant = Path(command[command.index("--config") + 1]).stem
                code = next(expected for name, expected, _, _ in verify_all_scenarios.SCENARIOS
                            if name == variant)
            return subprocess.CompletedProcess(command, code, "", "")

        with patch.object(verify_all_scenarios, "ROOT", self.root), \
                patch.object(verify_all_scenarios.subprocess, "run", side_effect=execute), \
                redirect_stdout(StringIO()):
            verify_all_scenarios.main()
        self.assertEqual(commands[0][:2], ["docker", "build"])
        containers = [command for command in commands if command[:2] == ["docker", "run"]]
        self.assertEqual(len(containers), 11)
        for command in containers:
            self.assertIn(f"{self.root}/tests/cjson/regression:/workspace/tests/cjson/regression:rw", command)
            self.assertIn(f"{self.root}/tests/tlv_parser/regression:/workspace/tests/tlv_parser/regression:rw", command)


if __name__ == "__main__":
    unittest.main()
