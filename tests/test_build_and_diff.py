import subprocess
import tempfile
import unittest
from pathlib import Path

from src.core.build_engine import BuildEngine
from src.core.config_manager import BuildConfig, ExecConfig, ProjectConfig, TestConfig
from src.core.test_runner import SanitizerReport, StackFrame, TestResult


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
            original = "int alpha(void) {\n    return 0;\n}\n\nint beta(void) {\n    return 1;\n}\n"
            source.write_text(original)
            git(root, "add", ".")
            git(root, "commit", "-qm", "base")
            base = git(root, "rev-parse", "HEAD")
            source.write_text(original.replace("return 1;", "return 2;"))
            git(root, "commit", "-qam", "patch")
            analyzer = DiffAnalyzer(root)
            report = analyzer.analyze(base, "HEAD")
            self.assertIn("alpha", report["files"][0]["hunks"][0]["context"])
            for side in ("base", "patched"):
                with self.subTest(side=side):
                    unchanged = StackFrame(0, "alpha", str(source), 2, "0x123")
                    changed = StackFrame(0, "beta", str(source), 6, "0x456")
                    correlation = analyzer.correlate([unchanged], report, side, root)
                    self.assertEqual(correlation["status"], "unknown")
                    self.assertEqual(correlation["evidence"], [])
                    self.assertEqual(analyzer.correlate([changed], report, side, root)["status"], "changed_line")
            self.assertEqual(analyzer.correlate([], report, "base", root)["status"], "unknown")

    def test_non_elf_hardening_is_unknown(self):
        from src.modules.hardening_checker import HardeningChecker
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "not-elf"
            path.write_text("not an ELF")
            result = HardeningChecker().check(path)
            self.assertEqual(result["status"], "unsupported")
            self.assertIsNone(result["nx"])

    def test_cross_revision_matching_maps_unchanged_sites_and_keeps_replays_strict(self):
        from types import SimpleNamespace
        from src.modules.diff_analyzer import DiffAnalyzer
        from src.orchestrator import PatchValidator

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            git(root, "init", "-q")
            git(root, "config", "user.name", "Fixture")
            git(root, "config", "user.email", "fixture@example.invalid")
            original = [f"/* line {n} */\n" for n in range(1, 41)]
            (root / "parser.c").write_text("".join(original))
            git(root, "add", ".")
            git(root, "commit", "-qm", "base")
            base = git(root, "rev-parse", "HEAD")
            modified = (original[:4] + ["/* inserted */\n"] + original[4:10]
                        + original[12:25] + ["/* another insertion */\n"] + original[25:])
            analyzer = DiffAnalyzer(root)

            def compare(base_line, patched_line, patched_file, error_type="heap-buffer-overflow"):
                validator = PatchValidator("unused")
                validator.builds, validator.runs = {}, {}
                for side, filename, line in (("base", "parser.c", base_line),
                                             ("patched", patched_file, patched_line)):
                    source = root / side / "source"
                    kind = "heap-buffer-overflow" if side == "base" else error_type
                    for mode in ("release", "sanitized"):
                        label = f"{side}_{mode}"
                        validator.builds[label] = SimpleNamespace(source_dir=source)
                        report = SanitizerReport(kind, [StackFrame(0, "parse", str(source / filename), line, "0x123")], "")
                        validator.runs[label] = {"case": [TestResult(
                            "case", root / "input", 1, None, "", "", False, False, mode,
                            error_type=kind, detection_mechanism="sanitizer", sanitizer_report=report)]}
                finding = validator._classify({"name": "case", "category": "exploit"}, analyzer, diff)
                return finding, validator.runs["base_sanitized"]["case"][0], validator.runs["patched_sanitized"]["case"][0]

            for filename in ("parser.c", "renamed.c"):
                git(root, "checkout", "-q", base)
                if filename != "parser.c":
                    (root / "parser.c").rename(root / filename)
                (root / filename).write_text("".join(modified))
                git(root, "add", "--all")
                git(root, "commit", "-qm", "move unchanged lines")
                diff = analyzer.analyze(base, "HEAD")
                for line in (1, 4, 5, 10, 13, 19, 25, 26, 32, 40):
                    with self.subTest(filename=filename, line=line):
                        mapped = modified.index(original[line - 1]) + 1
                        finding, before, after = compare(line, mapped, filename)
                        self.assertEqual(finding.category, "IncompleteFix")
                        self.assertEqual({c["category"] for c in finding.comparisons.values()}, {"IncompleteFix"})
                        if line != mapped:
                            self.assertNotEqual(before.signature, after.signature)
                            self.assertFalse(PatchValidator._stable([before, after]))
                for line, patched_line, kind in ((5, 9, "heap-buffer-overflow"),
                                                 (11, 11, "heap-buffer-overflow"),
                                                 (5, 6, "heap-use-after-free")):
                    with self.subTest(filename=filename, distinct_site=(line, patched_line, kind)):
                        finding, _, _ = compare(line, patched_line, filename, kind)
                        self.assertEqual(finding.category, "NewIssue")

    def test_correlation_preserves_crash_and_caller_frame_roles(self):
        from src.modules.diff_analyzer import DiffAnalyzer
        root = Path("/fixture")
        diff = {"files": [{"base_path": "parser.c", "patched_path": "parser.c", "hunks": [
            {"context": "int parse_object(int n)", "base_lines": [8], "patched_lines": [9]}]}]}
        frames = [StackFrame(0, "parse_string", str(root / "parser.c"), 3, "0x123"),
                  StackFrame(1, "parse_object", str(root / "parser.c"), 8, "0x456")]
        correlation = DiffAnalyzer.correlate(frames, diff, "base", root)
        self.assertEqual(correlation["status"], "changed_line")
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
                  StackFrame(1, "parse_object", "parser.c", 8, "0x456"),
                  StackFrame(0, "parse_object", "parser.c", 8, "0x789")]
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
