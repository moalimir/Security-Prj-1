# Target verification — 2026-11-15

> Historical record or implementation plan. For current verification limits,
> remaining work, and instructor approval, see [Project status](project-status.md).

Verified on native macOS ARM64 with Python 3.12.12 and Apple Clang. This records
source/revision completion and native behavior; it does not claim Linux ELF or
instructor approval.

## Prepared source

- `targets/cjson/` contains the actual cJSON 1.7.17 library, a file driver and
  Makefile. Its `base`, `correct`, `incomplete`, and `regression` tags contain
  substantive source changes. Vendored library/header/license/README bytes
  match upstream commit `87d8f0961a01bf09bef98ff89bae9fdec42181ee`; preparation
  checks their SHA-256 values. The correct patch is upstream commit
  `c39043866aaef2e599045b2c04936b247f84d82d` from issue #800 / PR #852.
- `targets/tlv_parser/` contains the independent original C protocol program,
  driver and Makefile at all four tags, plus `hardening_weak` for the existing
  ELF degradation scenario.
- Each patched tag is a direct child of its own target's base. Independent
  preparations reproduce the same commit IDs across directories. The preparer
  replaces only the old empty skeletons and refuses to overwrite source or
  local modifications. Exact local revision IDs are in
  [target-revisions.json](target-revisions.json).
- All eight target configs resolve their Git revisions successfully, including
  the `cjson_config.yaml` compatibility entry point. Both generated target
  checkouts remain clean after builds and validation.

## Executed checks

Historical `python -m unittest discover -s tests -v` result before subsequent
implementation changes: **44 tests run, 43 passed, 1 skipped**
(the Linux ELF-only hardening check). The new target checks build all four core
revisions of both programs in release and ASan/UBSan modes: **16 successful
archived builds**. They verify complete-fix behavior, original exploits,
incomplete-fix bypasses, declared boundary regressions, driver error handling,
source checksums and non-destructive/reproducible preparation. cJSON's 20
literal expectations are cross-checked with the independent Python JSON parser;
TLV's existing 24 cases follow its written protocol.

Two pre-existing timing assumptions failed during initial full-suite runs:
the signal fixture allowed only 100 ms for interpreter startup, and the
pipeline timeout fixture used a one-microsecond deadline, which encountered a
macOS process-start error. Test-only changes allow startup before checking the
signal and use an explicitly sleeping subprocess for the timeout comparison.
Both focused checks and the final full suite pass. Validator code was unchanged.

Six full validator comparisons ran with `--skip-hardening`, with minimization
and three-run crash replay enabled:

| Scenario | Native exit | Corpus findings |
| --- | ---: | --- |
| `cjson_correct` | 40 | 20 Fixed |
| `cjson_incomplete` | 10 | 19 Fixed, 1 IncompleteFix |
| `cjson_regression` | 20 | 19 Fixed, 1 FunctionalRegression |
| `tlv_correct` | 40 | 24 Fixed |
| `tlv_incomplete` | 10 | 23 Fixed, 1 IncompleteFix |
| `tlv_regression` | 20 | 22 Fixed, 2 FunctionalRegression |

For both targets the original and nested exploits produce a baseline ASan
heap-buffer-overflow. Correct versions reject both with exit 1 and no stdout;
partial versions still fail the nested input at the same error site. cJSON's
regression rejects the valid empty object; TLV's rejects the valid empty and
16-byte labels. Baseline sanitizer stacks correlate to the patched function
(`same_function`); this is weaker than changed-line overlap or proof of causation.

Both correct comparisons were then rerun in the same output directory. Each
loaded two generated regression cases into findings and all four execution
sets, reaching 22 cJSON and 26 TLV Fixed findings. The saved original and
minimized reproducers passed `ci/check_reports.py replay` for both targets:
baseline sanitizer runs crash as expected, and patched runs safely reject the
inputs with exit 1. The unit log, replay logs, summary JSON, source snapshots,
binary hashes, diffs and human-readable reports are in `reports/targets_native/`.

`docker compose -f docker/docker-compose.yml config --quiet` also passes.

## Container verification and exit-0 evidence

The native correct verdicts are **40**, because mandatory ELF hardening was
explicitly skipped on macOS Mach-O binaries. In Linux container execution,
complete validator verdicts (**0**, **10**, **20**) and ELF hardening have been
verified across all seven target scenarios under `reports/container_verified/`.
A guarded memory policy resolves the initial Rosetta release mapping failures.
See [Linux verification](linux-verification.md). The tracked
`.github/workflows/validate.yml` defines all seven scenarios and replay/reload
checks for both correct targets; final-revision CI verification remains pending.

Instructor approval of targets, harnesses and oracles remains a course deliverable.
The old pinned cJSON baseline deliberately retains the studied vulnerability;
this study is not a claim of overall library security.
