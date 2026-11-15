"""Evidence-based comparisons of matching release or sanitized executions."""
from dataclasses import dataclass, field
from enum import Enum

from src.core.test_runner import TestResult
from src.modules.diff_analyzer import DiffAnalyzer


class FindingCategory(str, Enum):
    FIXED = "Fixed"
    INCOMPLETE_FIX = "IncompleteFix"
    NEW_ISSUE = "NewIssue"
    FUNCTIONAL_REGRESSION = "FunctionalRegression"
    INCONCLUSIVE = "Inconclusive"


@dataclass
class Finding:
    test_name: str
    category: str
    detail: str
    comparisons: dict = field(default_factory=dict)
    correlation: dict = field(default_factory=dict)
    reproducer_path: str | None = None


def matches_oracle(result: TestResult, oracle: dict) -> bool:
    return (not result.crashed and not result.timed_out and not result.resource_limited
            and result.exit_code == oracle["expected_exit_code"]
            and ("expected_stdout" not in oracle or result.stdout == oracle["expected_stdout"])
            and ("expected_stdout_hash" not in oracle or result.stdout_hash == oracle["expected_stdout_hash"]))


def classify(base: TestResult, patched: TestResult, oracle: dict, *, diff: dict | None = None) -> tuple[str, str]:
    if any(r.timed_out or r.resource_limited for r in (base, patched)):
        return "Inconclusive", "Timeout or resource/runtime failure; no vulnerability conclusion."
    if any(r.crashed and r.detection_mechanism == "signal" for r in (base, patched)):
        return "Inconclusive", "Unclassified signal termination; a confirmed memory/security error needs additional evidence."
    if patched.crashed:
        base_signature = DiffAnalyzer.map_signature(base.signature, diff) if diff is not None else base.signature
        if base.crashed and base_signature == patched.signature:
            return "IncompleteFix", "The same error signature persists in the matching build mode."
        return "NewIssue", "A newly observed error signature; this alone does not establish patch causation."
    if oracle["category"] == "exploit":
        if not base.crashed or base.error_type != oracle["expected_error_type"]:
            return "Inconclusive", "The expected baseline error was not reproduced in this build mode."
        if matches_oracle(patched, oracle):
            return "Fixed", "Baseline error reproduced; patched result meets the independent oracle."
        return "Inconclusive", "Error disappeared but the patched result does not meet the independent oracle."
    if matches_oracle(patched, oracle):
        return "Fixed", "Patched result meets the independent oracle within the tested scope."
    if matches_oracle(base, oracle):
        return "FunctionalRegression", "Base meets the independent oracle; patched result violates it."
    return "Inconclusive", "Neither version meets the independent oracle; regression is unproven."


def determine_exit_code(findings: list[Finding]) -> int:
    categories = {f.category for f in findings}
    if categories & {"IncompleteFix", "NewIssue"}:
        return 10
    if "FunctionalRegression" in categories:
        return 20
    if not findings or "Inconclusive" in categories:
        return 40
    return 0


def aggregate_statuses(cases: list[dict], findings: list[Finding], runs: dict) -> dict:
    """Keep confirmed failures and require complete evidence for each pass."""
    categories = {f.category for f in findings} | {
        comparison["category"] for f in findings for comparison in f.comparisons.values()}
    security_failed = bool(categories & {"IncompleteFix", "NewIssue"})
    functionality_failed = "FunctionalRegression" in categories
    security_known = any(case["category"] == "exploit" for case in cases)
    functionality_known = any(case["category"] != "exploit" for case in cases)
    by_name = {f.test_name: f for f in findings}
    for case in cases:
        name = case["name"]
        functional = case["category"] != "exploit"
        finding = by_name.get(name)
        if not functional and (finding is None or finding.category != "Fixed"):
            security_known = False
        for mode in ("release", "sanitized"):
            base = runs.get(f"base_{mode}", {}).get(name, [])
            patched = runs.get(f"patched_{mode}", {}).get(name, [])
            comparison = finding.comparisons.get(mode, {}) if finding else {}
            if (not base or not patched or not comparison.get("stable", False)
                    or any(r.timed_out or r.resource_limited
                           or (r.crashed and r.detection_mechanism == "signal") for r in (*base, *patched))):
                security_known = False
                if functional:
                    functionality_known = False
                continue
            if patched[0].crashed:
                security_known = False
            if functional:
                patched_correct = matches_oracle(patched[0], case)
                functionality_failed |= matches_oracle(base[0], case) and not patched_correct
                functionality_known &= patched_correct
    return {
        "security_status": "fail" if security_failed else "pass" if security_known else "inconclusive",
        "functionality_status": "fail" if functionality_failed else "pass" if functionality_known else "inconclusive",
    }
