"""CLI and orchestration for the university security patch validator."""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import shutil
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

# Support the documented direct-script invocation as well as python -m src.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.core.build_engine import BuildEngine
from src.core.config_manager import ConfigManager
from src.core.oracle import load_oracle
from src.core.test_runner import TestResult, TestRunner
from src.modules.classifier import Finding, FindingCategory, aggregate_statuses, classify, determine_exit_code, matches_oracle
from src.modules.diff_analyzer import DiffAnalyzer
from src.modules.hardening_checker import HardeningChecker
from src.modules.report_generator import ReportGenerator, write_json
from src.modules.testcase_minimizer import minimize
from src.utils.constants import MAX_REPLAY_COUNT
from src.utils.exceptions import BuildError, ConfigError, PatchValidatorError

logger = logging.getLogger("patch_validator")


class ArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(30, f"{self.prog}: error: {message}\n")


class PatchValidator:
    def __init__(self, config_path: str, output_dir: str = "./reports", *,
                 skip_minimize: bool = False, skip_hardening: bool = False):
        self.config_path = config_path
        self.workspace = Path(output_dir).resolve()
        self.skip_minimize = skip_minimize
        self.skip_hardening = skip_hardening
        self.findings: list[Finding] = []
        self.report = {}

    def run(self) -> int:
        self.findings = []
        self.cases = []
        self.runs = {}
        self.analysis_incomplete = False
        self.report = {"schema_version": 1, "project": "unresolved", "exit_code": 40,
                       "security_status": "inconclusive", "functionality_status": "inconclusive",
                       "analysis_complete": False,
                       "started_at": datetime.now(timezone.utc).isoformat(),
                       "warnings": [], "errors": [], "findings": self.findings,
                       "builds": {}, "results": {}, "hardening": {}, "diff": {}}
        try:
            self._run_pipeline()
        except PatchValidatorError as exc:
            logger.error("%s", exc)
            self.report["errors"].append(str(exc))
            observed = determine_exit_code(self.findings)
            self.report["exit_code"] = 30 if exc.exit_code == 30 else observed if observed in (10, 20) else 40
        except Exception as exc:
            logger.exception("Pipeline could not complete")
            self.report["errors"].append(f"{type(exc).__name__}: {exc}")
            self.report["exit_code"] = 30
        self.report.update(aggregate_statuses(self.cases, self.findings, self.runs))
        if self.report["errors"]:
            self.report["analysis_complete"] = False
        self.report["finished_at"] = datetime.now(timezone.utc).isoformat()
        try:
            ReportGenerator(self.workspace).generate(self.report)
        except OSError as exc:
            self.report.update(exit_code=30, analysis_complete=False)
            self.report["errors"].append(f"Cannot write reports: {exc}")
            logger.exception("Cannot write reports to %s", self.workspace)
            try:
                write_json(self.workspace / "report.json", self.report)
            except OSError:
                pass
            return 30
        logger.info("Verdict: %s; reports: %s", self.report["exit_code"], self.workspace)
        return self.report["exit_code"]

    def _run_pipeline(self):
        logger.info("Loading configuration and independent oracle")
        config = ConfigManager.load_config(self.config_path)
        self.config = ConfigManager.validate_workspace(config)
        self.report["project"] = self.config.project_name
        self.report["config"] = asdict(self.config)
        self.workspace = ConfigManager.setup_workspace(self.config, str(self.workspace))
        self.cases = load_oracle(Path(self.config.test_suites.oracle_manifest))
        categories = {case["category"] for case in self.cases}
        if not {"valid", "boundary", "invalid", "exploit"} <= categories:
            raise ConfigError("A complete target oracle must cover valid, boundary, invalid, and exploit inputs.")
        repo_key = hashlib.sha256(self.config.repository_path.encode()).hexdigest()[:12]
        self.regression_dir = self.workspace / "regression" / repo_key
        manifests = {self.regression_dir / "oracle_manifest.json"}
        configured_regression = self.config.test_suites.regression_dir
        self.persistent_regression_dir = Path(configured_regression) if configured_regression else self.regression_dir
        if configured_regression:
            directory = Path(configured_regression)
            if not directory.is_dir():
                raise ConfigError(f"Regression directory does not exist: {directory}")
            manifests.add(directory / "oracle_manifest.json")
        names = {case["name"]: case for case in self.cases}
        for manifest in sorted(manifests):
            if manifest.is_file():
                for case in load_oracle(manifest):
                    if case["name"] in names:
                        previous = names[case["name"]]
                        if ({k: v for k, v in case.items() if k != "input_path"}
                                != {k: v for k, v in previous.items() if k != "input_path"}
                                or Path(case["input_path"]).read_bytes() != Path(previous["input_path"]).read_bytes()):
                            raise ConfigError(f"Duplicate test name across oracle/regression manifests: {case['name']}")
                        continue
                    self.cases.append(case)
                    names[case["name"]] = case
        self.runner = TestRunner(self.config)
        self.builds = {}
        engine = BuildEngine(self.config, self.workspace / "build")
        logger.info("Building isolated base and patched snapshots in both modes")
        for side in ("base", "patched"):
            variants = engine.build_version(getattr(self.config, f"{side}_commit"), side)
            for mode, build in variants.items():
                self.builds[f"{side}_{mode}"] = build
            self.report["builds"] = self.builds
            if not all(build.success for build in variants.values()):
                raise BuildError(f"Required {side} build failed; inspect build.log in {self.workspace / 'build'}.")
        hardening_inconclusive = False
        if self.skip_hardening:
            hardening_inconclusive = True
            self.report["hardening"] = {"status": "skipped"}
            self.report["warnings"].append("ELF hardening was explicitly skipped.")
        else:
            checker = HardeningChecker()
            hardening = {side: checker.check(self.builds[f"{side}_release"].binary_path)
                         for side in ("base", "patched")}
            self.report["hardening"] = hardening
            self.report["warnings"].extend(checker.compare(hardening["base"], hardening["patched"]))
            hardening_inconclusive = any(h["status"] != "checked" for h in hardening.values())

        logger.info("Running test cases; replaying errors on both versions in matching modes")
        self.runs = {label: {} for label in self.builds}
        self.report["results"] = self.runs
        for case in self.cases:
            name, inp = case["name"], Path(case["input_path"])
            for label, build in self.builds.items():
                result = self.runner.run_single_test(build.binary_path, inp, build.build_type)
                result.test_name = name
                self.runs[label][name] = [result]
            if any(self.runs[label][name][0].crashed for label in self.builds):
                for label, build in self.builds.items():
                    for _ in range(MAX_REPLAY_COUNT - 1):
                        result = self.runner.run_single_test(build.binary_path, inp, build.build_type)
                        result.test_name = name
                        self.runs[label][name].append(result)
        for label, results in self.runs.items():
            write_json(self.workspace / "results" / f"{label}.json", results)

        analyzer = DiffAnalyzer(Path(self.config.repository_path))
        diff = analyzer.analyze(self.config.base_commit, self.config.patched_commit)
        (self.workspace / "patch.diff").write_text(diff["patch"], encoding="utf-8")
        self.report["diff"] = diff
        for case in self.cases:
            finding = self._classify(case, analyzer, diff)
            self.findings.append(finding)
            logger.info("[%s] %s", finding.category, finding.test_name)
        if self.skip_minimize:
            self.analysis_incomplete = True
            self.report["warnings"].append("Input minimization was explicitly skipped; original reproducers are still saved.")
        for case, finding in zip(self.cases, self.findings):
            self._bundle(case, finding)
        code = determine_exit_code(self.findings)
        self.report["analysis_complete"] = not (hardening_inconclusive or self.analysis_incomplete)
        self.report["exit_code"] = 40 if code == 0 and not self.report["analysis_complete"] else code

    @staticmethod
    def _stable(results: list[TestResult]) -> bool:
        first = results[0]
        return all((r.signature, r.exit_code, r.stdout_hash, r.timed_out, r.resource_limited)
                   == (first.signature, first.exit_code, first.stdout_hash, first.timed_out, first.resource_limited)
                   for r in results)

    def _classify(self, case, analyzer, diff):
        comparisons, correlation = {}, {}
        name = case["name"]
        for mode in ("release", "sanitized"):
            base = self.runs[f"base_{mode}"][name]
            patched = self.runs[f"patched_{mode}"][name]
            stable = self._stable(base) and self._stable(patched)
            category, detail = classify(base[0], patched[0], case, diff=diff) if stable else (
                "Inconclusive", "Replay results are unstable; no fix conclusion.")
            comparisons[mode] = {"category": category, "detail": detail, "stable": stable}
            for side in ("base", "patched"):
                label = f"{side}_{mode}"
                report = self.runs[label][name][0].sanitizer_report
                correlation[label] = analyzer.correlate(report.stack_frames if report else [], diff,
                                                       side, self.builds[label].source_dir)
        categories = {c["category"] for c in comparisons.values()}
        category = next(c for c in ("IncompleteFix", "NewIssue", "FunctionalRegression", "Inconclusive", "Fixed") if c in categories)
        # A sanitizer can prove a fix when the release baseline does not expose the error.
        if case["category"] == "exploit" and "Fixed" in categories and categories <= {"Fixed", "Inconclusive"}:
            if all(c["stable"] for c in comparisons.values()) and all(
                matches_oracle(self.runs[f"patched_{mode}"][name][0], case)
                and not self.runs[f"base_{mode}"][name][0].timed_out
                and not self.runs[f"base_{mode}"][name][0].resource_limited for mode in comparisons):
                category = "Fixed"
        detail = "; ".join(f"{mode}: {c['detail']}" for mode, c in comparisons.items())
        return Finding(name, category, detail, comparisons, correlation)

    def _bundle(self, case, finding):
        name = case["name"]
        crashing = [label for label in ("base_sanitized", "patched_sanitized", "base_release", "patched_release")
                    if self.runs[label][name][0].crashed]
        if not crashing:
            return
        new_issue = finding.category == "NewIssue" and case["category"] != "exploit"
        if new_issue:
            crashing.sort(key=lambda label: not label.startswith("patched_"))
        bundle = self.workspace / "reproducers" / name
        bundle.mkdir(parents=True, exist_ok=True)
        original = Path(case["input_path"]).read_bytes()
        (bundle / "original.input").write_bytes(original)
        chosen = crashing[0]
        reference = self.runs[chosen][name][0]
        candidate_path = bundle / "candidate.input"
        stable = all(self._stable(self.runs[label][name]) for label in self.builds)
        data, attempts, status = original, 0, "skipped"
        frames = reference.sanitizer_report.stack_frames if reference.sanitizer_report else []
        if not self.skip_minimize and stable and frames:
            def predicate(candidate):
                candidate_path.write_bytes(candidate)
                result = self.runner.run_single_test(self.builds[chosen].binary_path, candidate_path, reference.build_type)
                if not result.crashed or result.signature != reference.signature:
                    return False
                if finding.category == "Fixed":
                    patched = self.builds[f"patched_{reference.build_type}"]
                    result = self.runner.run_single_test(patched.binary_path, candidate_path, reference.build_type)
                    return matches_oracle(result, case)
                if new_issue:
                    return all(matches_oracle(self.runner.run_single_test(
                        self.builds[f"base_{mode}"].binary_path, candidate_path, mode), case)
                        for mode in ("release", "sanitized"))
                return True
            data, attempts = minimize(original, predicate)
            status = "minimized" if len(data) < len(original) else "unchanged"
        elif not stable:
            status = "unstable-original"
        elif not frames:
            status = "no-symbolized-site"
        minimized_path = bundle / "minimized.input"
        minimized_path.write_bytes(data)
        candidate_path.unlink(missing_ok=True)
        minimized_runs = {label: [self.runner.run_single_test(build.binary_path, minimized_path, build.build_type)
                                  for _ in range(MAX_REPLAY_COUNT)] for label, build in self.builds.items()} if stable else {}
        checks = minimized_runs.get(chosen, [])
        if checks and not all(r.crashed and r.signature == reference.signature for r in checks):
            status = "unstable-minimized"
        if minimized_runs and not all(self._stable(runs) for runs in minimized_runs.values()):
            status = "unstable-minimized"
        oracle_side = "patched" if finding.category == "Fixed" else None
        if new_issue and data != original:
            oracle_side = "base"
        if oracle_side and minimized_runs and not all(
            matches_oracle(result, case) for label, runs in minimized_runs.items()
            if label.startswith(f"{oracle_side}_") for result in runs):
            status = "minimized-oracle-mismatch"
        if status in ("unstable-minimized", "minimized-oracle-mismatch", "no-symbolized-site", "unstable-original"):
            self.analysis_incomplete = True
            self.report["warnings"].append(f"{name}: input minimization is incomplete ({status}).")
        metadata = {"test": name, "classification": finding.category, "chosen_build": chosen,
                    "oracle": case, "original_size": len(original), "minimized_size": len(data),
                    "execution": asdict(self.config.execution),
                    "attempts": attempts, "minimization_status": status,
                    "original_executions": {label: results[name] for label, results in self.runs.items()},
                    "minimized_replays": checks, "builds": self.builds, "commands": {}, "environment": {}}
        metadata["minimized_executions"] = minimized_runs
        for label, build in self.builds.items():
            binary = bundle / f"binary-{label}"
            shutil.copy2(build.binary_path, binary)
            command = self.runner.command(binary, bundle / "original.input")
            env = self.runner.environment(build.build_type)
            relevant_env = {key: env[key] for key in ("LC_ALL", "ASAN_OPTIONS", "UBSAN_OPTIONS") if key in env}
            metadata["environment"][label] = relevant_env
            metadata["commands"][label] = command
            script = ('#!/bin/sh\n'
                      'bundle_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 1\n'
                      f'exec python3 -m src.replay "$bundle_dir" --build {label} "$@"\n')
            path = bundle / f"run-{label}.sh"
            path.write_text(script, encoding="utf-8")
            path.chmod(0o755)
        write_json(bundle / "metadata.json", metadata)
        finding.reproducer_path = str(bundle)
        if (stable and checks and status in ("minimized", "unchanged")
                and ((case["category"] == "exploit" and chosen.startswith("base_")
                      and reference.error_type == case["expected_error_type"])
                     or (new_issue and chosen.startswith("patched_")))):
            self._save_regression(case, data, error_type=reference.error_type)

    def _save_regression(self, case, data, *, error_type=None):
        if case["category"] == "exploit":
            identity = data + case["expected_error_type"].encode()
        else:
            identity = json.dumps({"input_hash": hashlib.sha256(data).hexdigest(), "error_type": error_type,
                                   "oracle": {k: v for k, v in case.items()
                                              if k == "category" or k.startswith("expected_")}}, sort_keys=True).encode()
        digest = hashlib.sha256(identity).hexdigest()
        name = f"regression_{digest[:20]}"
        for directory in {self.regression_dir, self.persistent_regression_dir}:
            try:
                directory.mkdir(parents=True, exist_ok=True)
                path = directory / "oracle_manifest.json"
                entries = load_oracle(path) if path.exists() else []
                if name in {c["name"] for c in entries}:
                    continue
                (directory / f"{name}.input").write_bytes(data)
                entry = {k: v for k, v in case.items() if k != "input_path"}
                entry.update(name=name, input_file=f"{name}.input", generated_from=case.get("generated_from", case["name"]))
                if case["category"] != "exploit":
                    entry["observed_error_type"] = error_type
                entries.append(entry)
                write_json(path, {"test_cases": [{k: v for k, v in e.items() if k != "input_path"} for e in entries]})
            except OSError as exc:
                raise ConfigError(f"Cannot save regression corpus {directory}: {exc}") from exc


def main(argv=None) -> int:
    parser = ArgumentParser(prog="patch-validator", description=__doc__)
    parser.add_argument("--config", "-c", required=True, help="Target YAML configuration.")
    parser.add_argument("--patch", help="Evaluate this patch against the configured base in an isolated clone.")
    parser.add_argument("--output-dir", "-o", default="./reports", help="Reports, builds, and regression workspace.")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--skip-minimize", action="store_true")
    parser.add_argument("--skip-hardening", action="store_true")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s %(message)s")
    if args.patch is not None:
        from src.unseen_patch import evaluate

        return evaluate(args.config, args.output_dir, patch_file=args.patch,
                        skip_minimize=args.skip_minimize, skip_hardening=args.skip_hardening)
    return PatchValidator(args.config, args.output_dir, skip_minimize=args.skip_minimize,
                          skip_hardening=args.skip_hardening).run()


if __name__ == "__main__":
    raise SystemExit(main())
