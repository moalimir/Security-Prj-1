"""Global constants for the security patch validation tool.

Exit codes follow a strict priority so the CI gate always surfaces the
most important issue first.  Priority order: 30 > 10 > 20 > 40 > 0.
"""

from __future__ import annotations

# ── Exit codes ───────────────────────────────────────────────────────────────
EXIT_PASS: int = 0
"""All oracle tests fixed, no functional regressions, no new issues."""

EXIT_VULN_REMAINS: int = 10
"""At least one vulnerability from the oracle set is not fixed."""

EXIT_FUNC_REGRESSION: int = 20
"""Functional regression detected in the patched binary."""

EXIT_BUILD_CONFIG_ERROR: int = 30
"""Build or configuration error — cannot proceed."""

EXIT_INCONCLUSIVE: int = 40
"""Analysis was inconclusive (e.g., flaky test, missing data)."""

EXIT_PRIORITY: list[int] = [30, 10, 20, 40, 0]
"""Exit codes ordered by descending severity for ``determine_exit_code``."""

# ── Signal mapping ───────────────────────────────────────────────────────────
SUPPORTED_SIGNALS: dict[str, int] = {
    "SIGSEGV": 11,
    "SIGABRT": 6,
    "SIGFPE": 8,
    "SIGBUS": 7,
    "SIGILL": 4,
}
"""Mapping of POSIX signal names to their numeric values (Linux x86_64)."""

# ── ASan / UBSan patterns ───────────────────────────────────────────────────
ASAN_ERROR_PATTERNS: dict[str, str] = {
    r"ERROR:\s*AddressSanitizer:\s*heap-buffer-overflow":        "heap-buffer-overflow",
    r"ERROR:\s*AddressSanitizer:\s*stack-buffer-overflow":       "stack-buffer-overflow",
    r"ERROR:\s*AddressSanitizer:\s*global-buffer-overflow":      "global-buffer-overflow",
    r"ERROR:\s*AddressSanitizer:\s*heap-use-after-free":         "heap-use-after-free",
    r"ERROR:\s*AddressSanitizer:\s*stack-use-after-return":      "stack-use-after-return",
    r"ERROR:\s*AddressSanitizer:\s*use-after-poison":            "use-after-poison",
    r"ERROR:\s*AddressSanitizer:\s*(?:attempting )?double-free":  "double-free",
    r"ERROR:\s*AddressSanitizer:\s*alloc-dealloc-mismatch":      "alloc-dealloc-mismatch",
    r"ERROR:\s*AddressSanitizer:\s*SEGV":                        "invalid-memory-access",
    r"ERROR:\s*AddressSanitizer:\s*requested allocation size":   "allocation-size-too-big",
    r"runtime error:\s*signed integer overflow":                 "signed-integer-overflow",
    r"runtime error:\s*unsigned integer overflow":               "unsigned-integer-overflow",
    r"runtime error:\s*shift exponent":                          "invalid-shift-exponent",
    r"runtime error:\s*division by zero":                        "division-by-zero",
    r"runtime error:\s*null pointer":                            "null-pointer-dereference",
    r"runtime error:\s*load of misaligned address":              "misaligned-address",
    r"ERROR:\s*LeakSanitizer:\s*detected memory leaks":          "memory-leak",
}
"""Regex pattern → canonical error-type label used by the triage engine."""

# ── Replay / minimiser ──────────────────────────────────────────────────────
MAX_REPLAY_COUNT: int = 3
"""Default number of replay iterations for stability checks."""
