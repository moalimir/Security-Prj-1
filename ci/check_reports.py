"""Assert saved evidence and replay bundles without guessing verdicts from names."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


BUILDS = ("base_release", "base_sanitized", "patched_release", "patched_sanitized")


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def check_report(directory, expected, regression_loaded=False, hardening_warning=False):
    report = read_json(directory / "report.json")
    assert report["exit_code"] == expected, (directory, report["exit_code"], expected)
    assert not report["errors"], report["errors"]
    assert report["analysis_complete"] is True, report["warnings"]
    if expected == 0:
        for status in ("security_status", "functionality_status"):
            assert report.get(status) == "pass", (status, report.get(status))
    for name in ("report.md", "report.html", "patch.diff"):
        assert (directory / name).is_file(), directory / name
    for label in BUILDS:
        assert report["builds"][label]["success"], label
        assert report["results"][label], label
    for side in ("base", "patched"):
        assert report["hardening"][side]["status"] == "checked", report["hardening"]
    assert report["findings"], "No findings recorded"
    for finding in report["findings"]:
        for label in BUILDS:
            correlation = finding["correlation"][label]
            evidence = correlation["evidence"]
            assert all(match["status"] == "changed_line" for match in evidence), (label, correlation)
            assert correlation["status"] == ("changed_line" if evidence else "unknown"), (label, correlation)
    if hardening_warning:
        base, patched = report["hardening"]["base"], report["hardening"]["patched"]
        assert base["canary"] is True and patched["canary"] is False, report["hardening"]
        assert base["relro"] == "full" and patched["relro"] != "full", report["hardening"]
        assert any("canary" in warning for warning in report["warnings"]), report["warnings"]
        assert any("RELRO" in warning for warning in report["warnings"]), report["warnings"]
    if regression_loaded:
        manifests = list((directory / "regression").glob("*/oracle_manifest.json"))
        assert manifests, "No generated regression manifest"
        cases = [case for manifest in manifests for case in read_json(manifest)["test_cases"]]
        assert cases, "Empty generated regression manifest"
        findings = {finding["test_name"] for finding in report["findings"]}
        for case in cases:
            assert case["name"] in findings, f"Regression case was not classified: {case['name']}"
            for label in BUILDS:
                runs = report["results"][label].get(case["name"])
                assert runs and all(run["test_name"] == case["name"] for run in runs), (label, case["name"])
    print(f"Verified report: {directory} (exit {expected})")


def check_replays(directory):
    bundles = sorted((directory / "reproducers").glob("*/metadata.json"))
    assert bundles, f"No reproducer bundles in {directory}"
    for metadata_path in bundles:
        bundle = metadata_path.parent
        metadata = read_json(metadata_path)
        for label, minimized in (("base_sanitized", False), ("patched_sanitized", True)):
            command = [sys.executable, "-m", "src.replay", str(bundle), "--build", label]
            if minimized:
                command.append("--minimized")
            process = subprocess.run(command, text=True, capture_output=True)
            assert process.stdout, (command, process.returncode, process.stderr)
            result = json.loads(process.stdout)
            assert not result["timed_out"] and not result["resource_limited"], result
            oracle = metadata["oracle"]
            reference = metadata["original_executions"][label][0]
            expected_error = (oracle["expected_error_type"]
                              if label == "base_sanitized" and oracle["category"] == "exploit"
                              else reference["error_type"])
            if expected_error:
                assert process.returncode != 0, result
                assert result["error_type"] == expected_error, result
                assert result["detection_mechanism"] == reference["detection_mechanism"], result
            else:
                assert process.returncode == oracle["expected_exit_code"], result
                assert not result["error_type"] and result["signal"] is None, result
                if "expected_stdout" in oracle:
                    assert result["stdout"] == oracle["expected_stdout"], result
                if "expected_stdout_hash" in oracle:
                    assert hashlib.sha256(result["stdout"].encode()).hexdigest() == oracle["expected_stdout_hash"], result
            print(f"Verified replay: {bundle.name} {label} (exit {process.returncode})")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    report = commands.add_parser("report")
    report.add_argument("directory", type=Path)
    report.add_argument("--expected-exit", type=int, required=True)
    report.add_argument("--regression-loaded", action="store_true")
    report.add_argument("--expect-hardening-warning", action="store_true")
    replay = commands.add_parser("replay")
    replay.add_argument("directory", type=Path)
    args = parser.parse_args()
    if args.command == "report":
        check_report(args.directory, args.expected_exit, args.regression_loaded, args.expect_hardening_warning)
    else:
        check_replays(args.directory)


if __name__ == "__main__":
    main()
