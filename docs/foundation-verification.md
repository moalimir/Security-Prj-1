# Foundation verification — 2026-11-10

> Historical record or implementation plan. For current verification limits,
> remaining work, and instructor approval, see [Project status](project-status.md).

Verified locally on macOS ARM64 with Python 3.12.12 and the installed Clang.

- `python -m unittest discover -s tests -v`: **27 tests passed**.
- Editable package installation and the `patch-validator` console entry point work.
- Real C fixture CLI runs, invoked from `/tmp` with absolute config paths:
  correct **40** (mandatory ELF check skipped), incomplete **10**, functional
  regression **20**. At this assessment, the Linux PASS path had not been verified. Later measurements
  are recorded in [Linux verification](linux-verification.md).
- Missing configuration/commit, invalid oracle, and partial build checks return
  **30**. Unreproduced baseline and timeout checks return **40**.
- Unclassified signal-only stops remain **40**; unexpected internal tool errors
  return **30**. A unit check verifies **0** for complete fixed findings.
- Each successful fixture run retains four separate binaries, hashes, snapshots,
  build logs, result sets, and JSON/Markdown/HTML reports.
- Original 16/17-byte PoCs reduce to **9 bytes** for the correct fixture while
  preserving the sanitizer error/site. The incomplete fixture's original PoC
  stays at 16 bytes; its distinct bypass reduces to 9 bytes.
- Original errors replay three times per binary; minimized inputs are also
  replayed three times on each binary. Generated regressions reload on a second run.
- Bundle replay of the patched sanitized binary safely rejects the minimized
  exploit with the independent expected exit **1**.
- Demo sanitizer frames correlate to the changed function. Reports label that
  evidence `same_function`; they do not assert changed-line overlap or causation.
- Dirty checkout preservation, ELF header/symbol inspection contracts, stdin,
  signals/timeouts, bounded output, oracle path validation, and HTML escaping pass.
- `python -m compileall -q src tools tests` passes. Configuration examples and
  workflow YAML parse; `docker compose -f docker/docker-compose.yml config --quiet`
  passes. The demo target Git checkout remains clean after validation.

Inspectable native artifacts are in `reports/correct/`, `reports/incomplete/`,
and `reports/regression/`. Their hardening check is explicitly skipped because
native macOS executables are not ELF.

**Not run:** Docker image build, container execution, GitHub-hosted CI, or real
cJSON/TLV studies. At that assessment, the Docker CLI could not connect to its
daemon and the remote CI result was pending. Current evidence is linked above.
The final course work is tracked in
`docs/course-checklist.md`.
