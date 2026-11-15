"""Exercise the protocol contract against separately built target revisions."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from src.core.oracle import load_oracle

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "examples/targets/tlv_parser"
SUITE = ROOT / "tests/tlv_parser"


class TLVTargetTests(unittest.TestCase):
    def test_target_sources_available(self):
        for name in ("driver.c", "tlv_parser.c", "tlv_parser.h", "Makefile"):
            self.assertTrue((TEMPLATE / "base" / name).is_file(), name)

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.work = Path(cls.temp.name)
        cls.binaries = {}

    @classmethod
    def build(cls, revision, sanitized=False):
        key = (revision, sanitized)
        if key in cls.binaries:
            return cls.binaries[key]
        if not shutil.which("clang"):
            raise unittest.SkipTest("Clang is required for target integration checks")
        source = cls.work / f"{revision}_{sanitized}"
        shutil.copytree(TEMPLATE / "base", source)
        if revision != "base":
            subprocess.run(["git", "apply", str(TEMPLATE / "patches" / f"{revision}.patch")],
                           cwd=source, check=True, capture_output=True)
        binary = source / "target_bin"
        subprocess.run(["make", "sanitized" if sanitized else "release", f"OUT={binary}"],
                       cwd=source, check=True, capture_output=True)
        cls.binaries[key] = binary
        return binary

    def run_packet(self, revision, packet, sanitized=False):
        path = self.work / "packet.bin"
        path.write_bytes(packet)
        env = {**os.environ, "ASAN_OPTIONS": "detect_leaks=0:abort_on_error=1:symbolize=1"}
        return subprocess.run([str(self.build(revision, sanitized)), str(path)],
                              capture_output=True, env=env, timeout=10)

    def test_correct_matches_independent_manifest(self):
        cases = load_oracle(SUITE / "oracle_manifest.json")
        self.assertGreaterEqual(len(cases), 16)
        for case in cases:
            with self.subTest(case=case["name"]):
                result = self.run_packet("correct", Path(case["input_path"]).read_bytes())
                self.assertEqual(result.returncode, case["expected_exit_code"], result.stderr)
                self.assertEqual(result.stdout, case["expected_stdout"].encode("ascii"))

    def test_invalid_later_record_never_leaks_partial_output(self):
        for revision in ("base", "correct", "incomplete", "regression"):
            for tail in (b"\xff\x00", b"\x02\x04\x00", b"\x01\x01\x80"):
                with self.subTest(revision=revision, tail=tail):
                    result = self.run_packet(revision, b"T\x01\x02\x00\x01\x01A" + tail)
                    self.assertEqual((result.returncode, result.stdout), (1, b""))

    def test_count_trailing_and_nesting_bounds(self):
        inner = b"\x01\x01A"
        for _ in range(16):
            inner = bytes((3, len(inner))) + inner
        accepted = self.run_packet("correct", b"T\x01\x01\x00" + inner)
        self.assertEqual((accepted.returncode, accepted.stdout), (0, b"NESTED->" * 16 + b"LABEL:A\n"))
        inner = bytes((3, len(inner))) + inner
        for packet in (b"", b"T\x01\x01", b"T\x01\x00\x00x", b"T\x01\x02\x00\x01\x01A",
                       b"T\x01\x01\x00" + inner):
            result = self.run_packet("correct", packet)
            self.assertEqual((result.returncode, result.stdout), (1, b""))

    def test_security_patches_and_nested_bypass(self):
        for name in ("original_poc", "bypass_poc"):
            packet = (SUITE / "exploit" / f"{name}.bin").read_bytes()
            for revision in ("base", "correct", "incomplete", "regression"):
                with self.subTest(revision=revision, exploit=name):
                    result = self.run_packet(revision, packet, sanitized=True)
                    vulnerable = revision == "base" or (revision == "incomplete" and name == "bypass_poc")
                    if vulnerable:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn(b"AddressSanitizer: heap-buffer-overflow", result.stderr)
                        self.assertIn(b"parse_label_record", result.stderr)
                    else:
                        self.assertEqual(result.returncode, 1, result.stderr)
                        self.assertNotIn(b"Sanitizer", result.stderr)
                    self.assertEqual(result.stdout, b"")

    def test_regression_rejects_only_declared_label_boundaries(self):
        for length in (0, 16):
            packet = b"T\x01\x01\x00" + bytes((1, length)) + b"A" * length
            self.assertEqual(self.run_packet("correct", packet).returncode, 0)
            self.assertEqual(self.run_packet("regression", packet).returncode, 1)
        self.assertEqual(self.run_packet("regression", b"T\x01\x01\x00\x01\x01A").stdout, b"LABEL:A\n")

    @unittest.skipUnless(os.name == "posix" and __import__("sys").platform.startswith("linux"), "ELF-only hardening")
    def test_hardening_variant_loses_canary_and_full_relro(self):
        from src.modules.hardening_checker import HardeningChecker
        # Both variants carry the complete security guard; only release flags differ.
        strong = HardeningChecker().check(self.build("correct"))
        weak = HardeningChecker().check(self.build("hardening_weak"))
        self.assertTrue(strong["canary"])
        self.assertFalse(weak["canary"])
        self.assertEqual(strong["relro"], "full")
        self.assertEqual(weak["relro"], "partial")
