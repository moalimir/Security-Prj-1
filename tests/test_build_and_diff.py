import subprocess
import tempfile
import unittest
from pathlib import Path

from src.core.build_engine import BuildEngine
from src.core.config_manager import BuildConfig, ExecConfig, ProjectConfig, TestConfig
from src.core.test_runner import StackFrame, TestRunner


def git(repo, *args):
    return subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, check=True).stdout.strip()


class BuildTests(unittest.TestCase):
    def test_snapshots_preserve_dirty_checkout_and_independent_binaries(self):
        with tempfile.TemporaryDirectory(prefix="build space ") as tmp:
            root = Path(tmp)
            repo, workspace = root / "repo", root / "build"
            repo.mkdir()
            workspace.mkdir()
            git(repo, "init", "-q")
            git(repo, "config", "user.name", "Fixture")
            git(repo, "config", "user.email", "fixture@example.invalid")
            (repo / "answer").write_text("base")
            git(repo, "add", "answer")
            git(repo, "commit", "-qm", "base")
            base = git(repo, "rev-parse", "HEAD")
            (repo / "answer").write_text("patched")
            git(repo, "commit", "-qam", "patched")
            patched = git(repo, "rev-parse", "HEAD")
            (repo / "answer").write_text("user edit")
            (repo / "keep-untracked").write_text("precious")
            cfg = ProjectConfig("fixture", str(repo), base, patched,
                                BuildConfig("cp answer {output_dir}/binary && chmod +x {output_dir}/binary",
                                            "cp answer {output_dir}/binary && chmod +x {output_dir}/binary",
                                            "binary", "binary"), ExecConfig(), TestConfig("unused"))
            engine = BuildEngine(cfg, workspace)
            first = engine.build_version(base, "base")
            second = engine.build_version(patched, "patched")
            self.assertEqual(first["release"].binary_path.read_text(), "base")
            self.assertEqual(second["sanitized"].binary_path.read_text(), "patched")
            self.assertEqual((repo / "answer").read_text(), "user edit")
            self.assertEqual((repo / "keep-untracked").read_text(), "precious")
            self.assertEqual(git(repo, "rev-parse", "HEAD"), patched)
            self.assertNotEqual(first["release"].binary_path, second["release"].binary_path)

    def test_diff_correlates_source_lines_and_retains_unknown(self):
        from src.modules.diff_analyzer import DiffAnalyzer
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            git(root, "init", "-q")
            git(root, "config", "user.name", "Fixture")
            git(root, "config", "user.email", "fixture@example.invalid")
            source = root / "parser.c"
            source.write_text("int parse(int n) {\n  return n;\n}\n")
            git(root, "add", ".")
            git(root, "commit", "-qm", "base")
            base = git(root, "rev-parse", "HEAD")
            source.write_text("int parse(int n) {\n  return n + 1;\n}\n")
            git(root, "commit", "-qam", "patch")
            analyzer = DiffAnalyzer(root)
            report = analyzer.analyze(base, "HEAD")
            frames = TestRunner._parse_asan_output(
                f"ERROR: AddressSanitizer: heap-buffer-overflow\n#0 0x123 in parse {source}:2:1\n").stack_frames
            correlation = analyzer.correlate(frames, report, "patched", root)
            self.assertEqual(correlation["status"], "changed_line")
            self.assertEqual(analyzer.correlate([], report, "base", root)["status"], "unknown")

    def test_non_elf_hardening_is_unknown(self):
        from src.modules.hardening_checker import HardeningChecker
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "not-elf"
            path.write_text("not an ELF")
            result = HardeningChecker().check(path)
            self.assertEqual(result["status"], "unsupported")
            self.assertIsNone(result["nx"])

    def test_correlation_preserves_crash_and_caller_frame_roles(self):
        from src.modules.diff_analyzer import DiffAnalyzer
        root = Path("/fixture")
        diff = {"files": [{"base_path": "parser.c", "patched_path": "parser.c", "hunks": [
            {"context": "int parse_object(int n)", "base_lines": [8], "patched_lines": [9]}]}]}
        frames = [StackFrame(0, "parse_string", str(root / "parser.c"), 3, "0x123"),
                  StackFrame(1, "parse_object", str(root / "parser.c"), 12, "0x456")]
        for side in ("base", "patched"):
            with self.subTest(side=side):
                correlation = DiffAnalyzer.correlate(frames, diff, side, root)
                self.assertEqual(correlation["status"], "same_function")
                evidence, = correlation["evidence"]
                self.assertEqual((evidence["frame_id"], evidence["frame_role"]), (1, "caller"))
                self.assertEqual(evidence["function"], "parse_object")
        frames[0] = StackFrame(0, "parse_string", str(root / "parser.c"), 9, "0x123")
        evidence = DiffAnalyzer.correlate(frames, diff, "patched", root)["evidence"][0]
        self.assertEqual(evidence["status"], "changed_line")
        self.assertEqual((evidence["frame_id"], evidence["frame_role"]), (0, "crash"))
        # An unsymbolized/missing #0 must not turn a caller into the crash frame.
        evidence = DiffAnalyzer.correlate(frames[1:], diff, "base", root)["evidence"][0]
        self.assertEqual(evidence["frame_role"], "caller")
        frames[1] = StackFrame(1, "unrelated", str(root / "parser.c"), 12, "0x456")
        self.assertEqual(DiffAnalyzer.correlate(frames[1:], diff, "base", root)["status"], "unknown")
        # ASan can append allocation/free stacks with frame numbers starting over.
        frames = [StackFrame(0, "parse_string", "parser.c", 3, "0x123"),
                  StackFrame(1, "parse_object", "parser.c", 12, "0x456"),
                  StackFrame(0, "parse_object", "parser.c", 12, "0x789")]
        evidence = DiffAnalyzer.correlate(frames, diff, "base", root)["evidence"]
        self.assertEqual([e["frame_role"] for e in evidence], ["caller", "auxiliary"])

    def test_elf_headers_provide_hardening_evidence(self):
        import struct
        from src.modules.hardening_checker import HardeningChecker
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fixture.elf"
            ident = b"\x7fELF\x02\x01\x01" + b"\0" * 9
            header = struct.pack("<HHIQQQIHHHHHH", 3, 62, 1, 0, 64, 0, 0, 64, 56, 3, 64, 0, 0)
            program = lambda kind, flags: struct.pack("<IIQQQQQQ", kind, flags, 0, 0, 0, 0, 0, 8)
            path.write_bytes(ident + header + program(0x6474e552, 4) + program(0x6474e551, 6) + program(3, 4))
            checked = HardeningChecker().check(path)
            self.assertEqual(checked["status"], "checked")
            self.assertEqual(checked["relro"], "partial")
            self.assertTrue(checked["nx"])
            self.assertTrue(checked["pie"])
            weakened = {**checked, "nx": False, "pie": False, "relro": "none"}
            warnings = HardeningChecker.compare(checked, weakened)
            self.assertEqual(len(warnings), 3)


if __name__ == "__main__":
    unittest.main()
