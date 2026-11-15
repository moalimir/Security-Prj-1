"""Build archived study revisions and check their independent oracle contracts."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from src.core.oracle import load_oracle

ROOT = Path(__file__).resolve().parents[1]
PREPARER = ROOT / "tools/prepare_targets.py"


class PreparedTargetTests(unittest.TestCase):
    def prepare(self, destination):
        self.assertTrue(PREPARER.is_file(), "missing offline target preparer")
        return subprocess.run([sys.executable, str(PREPARER), "--output-dir", str(destination)],
                              capture_output=True, text=True, timeout=60)

    def git(self, repo, *args):
        return subprocess.run(["git", "-C", str(repo), *args], check=True,
                              capture_output=True, text=True).stdout.strip()

    def test_revisions_are_reproducible_siblings_and_never_overwrite_work(self):
        with tempfile.TemporaryDirectory(prefix="prepared targets ") as temporary:
            root = Path(temporary)
            first, second = root / "first", root / "second"
            for target in ("cjson", "tlv_parser"):
                for revision in ("base", "correct_patch", "incomplete_patch", "regression_patch"):
                    (first / target / revision).mkdir(parents=True)
            for destination in (first, second):
                result = self.prepare(destination)
                self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads((first / "revisions.json").read_text())
            self.assertEqual(manifest, json.loads((second / "revisions.json").read_text()))
            for target in ("cjson", "tlv_parser"):
                repo = first / target
                base = self.git(repo, "rev-parse", "base")
                for revision in ("base", "correct", "incomplete", "regression"):
                    self.assertEqual(manifest[target][revision], self.git(repo, "rev-parse", revision))
                    self.assertIn("main(", self.git(repo, "show", f"{revision}:driver.c"))
                    if revision != "base":
                        self.assertEqual(self.git(repo, "rev-parse", f"{revision}^"), base)
                        self.assertTrue(self.git(repo, "diff", "base", revision))
                self.assertEqual(self.git(repo, "status", "--porcelain"), "")
            marker = first / "tlv_parser/driver.c"
            marker.write_text("preserve local work\n")
            before = (first / "revisions.json").read_bytes()
            result = self.prepare(first)
            self.assertEqual(result.returncode, 30)
            self.assertEqual(marker.read_text(), "preserve local work\n")
            self.assertEqual((first / "revisions.json").read_bytes(), before)
            # Preflight the whole destination before installing either target.
            third = root / "third"
            (third / "tlv_parser").mkdir(parents=True)
            (third / "tlv_parser/notes.txt").write_text("keep\n")
            self.assertEqual(self.prepare(third).returncode, 30)
            self.assertFalse((third / "cjson").exists())

    @unittest.skipUnless(shutil.which("clang"), "Clang required for target builds")
    def test_archived_revisions_expose_the_intended_security_and_regression_behavior(self):
        with tempfile.TemporaryDirectory(prefix="target builds ") as temporary:
            root = Path(temporary)
            result = self.prepare(root / "targets")
            self.assertEqual(result.returncode, 0, result.stderr)
            env = {**os.environ, "ASAN_OPTIONS": "detect_leaks=0:abort_on_error=1:symbolize=1"}
            for target in ("cjson", "tlv_parser"):
                cases = load_oracle(ROOT / "tests" / target / "oracle_manifest.json")
                exploits = [case for case in cases if case["category"] == "exploit"]
                self.assertEqual({case["name"] for case in exploits}, {"exploit_original_poc", "exploit_bypass_poc"})
                for revision in ("base", "correct", "incomplete", "regression"):
                    source = root / f"{target}_{revision}"
                    source.mkdir()
                    archive = subprocess.run(["git", "-C", str(root / "targets" / target),
                                              "archive", revision], capture_output=True, check=True)
                    subprocess.run(["tar", "-xf", "-", "-C", str(source)], input=archive.stdout, check=True)
                    for mode in ("release", "sanitized"):
                        binary = source / f"target_{mode}"
                        build = subprocess.run(["make", mode, f"OUT={binary}"], cwd=source,
                                               capture_output=True, text=True, timeout=60)
                        self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
                        if target == "cjson" and revision == "correct":
                            oversized = root / "oversized.json"
                            oversized.write_bytes(b" " * (1024 * 1024 + 1))
                            for args in ([], [str(root / "missing.json")], [str(oversized)], [str(oversized), "extra"]):
                                rejected = subprocess.run([str(binary), *args], env=env, capture_output=True, timeout=10)
                                self.assertEqual((rejected.returncode, rejected.stdout), (1, b""))
                        regressions = []
                        for case in cases:
                            with self.subTest(target=target, revision=revision, mode=mode, case=case["name"]):
                                run = subprocess.run([str(binary), case["input_path"]], env=env,
                                                     capture_output=True, timeout=10)
                                if case["category"] == "exploit":
                                    vulnerable = revision == "base" or (revision == "incomplete" and case["name"] == "exploit_bypass_poc")
                                    if vulnerable:
                                        if mode == "sanitized":
                                            self.assertNotEqual(run.returncode, 0)
                                            self.assertIn(b"AddressSanitizer: heap-buffer-overflow", run.stderr)
                                        continue
                                expected = (case["expected_exit_code"], case["expected_stdout"].encode())
                                actual = (run.returncode, run.stdout)
                                if revision == "regression" and case["category"] == "boundary" and actual != expected:
                                    regressions.append(case["name"])
                                    self.assertEqual(actual, (1, b""))
                                else:
                                    self.assertEqual(actual, expected, run.stderr)
                                    self.assertNotIn(b"Sanitizer", run.stderr)
                        if revision == "regression":
                            expected_regressions = {"boundary_empty_object"} if target == "cjson" else {"boundary_empty_label", "boundary_max_label_16"}
                            self.assertEqual(set(regressions), expected_regressions)

    def test_cjson_source_matches_pinned_upstream_hashes(self):
        provenance = ROOT / "examples/targets/cjson/provenance.json"
        self.assertTrue(provenance.is_file(), "missing cJSON source provenance")
        data = json.loads(provenance.read_text())
        self.assertRegex(data["upstream_commit"], r"^[0-9a-f]{40}$")
        self.assertRegex(data["fix_commit"], r"^[0-9a-f]{40}$")
        for name, expected in data["sha256"].items():
            self.assertEqual(hashlib.sha256((provenance.parent / "base" / name).read_bytes()).hexdigest(), expected)

    def test_cjson_functional_expectations_match_an_independent_json_parser(self):
        for case in load_oracle(ROOT / "tests/cjson/oracle_manifest.json"):
            with self.subTest(case=case["name"]):
                data = Path(case["input_path"]).read_text()
                if case["expected_exit_code"] == 0:
                    expected = json.dumps(json.loads(data), ensure_ascii=False, separators=(",", ":")) + "\n"
                    self.assertEqual(case["expected_stdout"], expected)
                else:
                    with self.assertRaises(json.JSONDecodeError):
                        json.loads(data)


if __name__ == "__main__":
    unittest.main()
