"""Load independent expected outcomes; reject missing or placeholder evidence."""
import json
import re
from pathlib import Path

from src.utils.exceptions import ConfigError


def load_oracle(path: Path) -> list[dict]:
    path = Path(path).resolve()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ConfigError(f"Cannot read oracle {path}: {exc}") from exc
    cases = data.get("test_cases") if isinstance(data, dict) else None
    if not isinstance(cases, list) or not cases:
        raise ConfigError(f"Oracle {path} must contain a nonempty test_cases list.")
    names = set()
    for case in cases:
        if not isinstance(case, dict):
            raise ConfigError("Every oracle case must be a mapping.")
        name = case.get("name")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name) or name in names:
            raise ConfigError(f"Invalid or duplicate oracle case name: {name}")
        names.add(name)
        if case.get("category") not in ("valid", "boundary", "invalid", "exploit"):
            raise ConfigError(f"Unknown category for {name}.")
        code = case.get("expected_exit_code")
        if isinstance(code, bool) or not isinstance(code, int) or not 0 <= code <= 255:
            raise ConfigError(f"{name} requires expected_exit_code (0..255) for the patched program.")
        digest = case.get("expected_stdout_hash")
        if digest is not None and (not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)):
            raise ConfigError(f"{name} requires a real SHA-256 output hash; placeholders are not oracles.")
        if "expected_stdout" in case and not isinstance(case["expected_stdout"], str):
            raise ConfigError(f"expected_stdout must be a string for {name}.")
        if case["category"] in ("valid", "boundary") and digest is None and "expected_stdout" not in case:
            raise ConfigError(f"{name} requires independent expected_stdout or expected_stdout_hash.")
        if case["category"] == "exploit" and not isinstance(case.get("expected_error_type"), str):
            raise ConfigError(f"{name} requires the baseline expected_error_type.")
        if case.get("base_expected_crash", True) is not True or case.get("patched_expected_crash", False) is not False:
            raise ConfigError(f"{name}: exploit expectations must require a base crash and a safe patched outcome.")
        if case.get("expected_signal") is not None or case.get("expected_no_crash", True) is not True:
            raise ConfigError(f"{name}: patched oracle outcomes must terminate without a crash.")
        inp = case.get("input_file")
        if not isinstance(inp, str) or not inp or Path(inp).is_absolute():
            raise ConfigError(f"{name} requires an input_file relative to its manifest.")
        resolved = (path.parent / inp).resolve()
        if not resolved.is_relative_to(path.parent) or not resolved.is_file():
            raise ConfigError(f"Missing or escaping input_file for {name}: {inp}")
        case["input_path"] = str(resolved)
    return cases
