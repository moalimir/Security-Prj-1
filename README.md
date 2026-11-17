# Security Patch Validator

Reusable foundation for the university project **Automated Security Patch
Validation and Regression Testing in CI/CD**. The specification is
[`project1.txt`](project1.txt), extracted from the supplied six-page PDF.

The pipeline is runnable: it builds four binaries, executes independent oracle
tests, keeps release and sanitizer evidence separate, checks ELF hardening,
correlates stack frames with a Git diff, replays errors, minimizes inputs, saves
reproducers/regression cases, and writes JSON, Markdown, and HTML reports.

**Target status:** both C studies now have real source and buildable `base`,
`correct`, `incomplete`, and `regression` Git revisions. cJSON uses the actual
upstream 1.7.17 library and issue #800 fix; TLV is an independent original C
program. Run `python tools/prepare_targets.py` once to prepare both offline.
Native tests exercise the security and regression behavior. Complete Linux
x86_64 validator evidence across all seven target scenarios (verdicts 0, 10, 20),
including ELF hardening inspection, recorded 3-run replays, and regression
reloads, is saved under `reports/container_verified/`. Instructor approval and
CI verification of the final source revision remain outstanding. The authoritative
[project status](docs/project-status.md) distinguishes implementation, current
checks, historical evidence, and approval that is not recorded.
The guarded Rosetta compatibility fix and full container measurements are recorded
in [`docs/linux-verification.md`](docs/linux-verification.md). See
[`docs/course-checklist.md`](docs/course-checklist.md).
The measured native target results are in
[`docs/target-verification.md`](docs/target-verification.md).

## Install and run the local fixture

Requires Python **3.12+**, Git, and Clang or GCC with ASan/UBSan. The full course
runtime is **Linux x86_64 / ELF**. macOS can run the C smoke tests, but cannot
validate ELF hardening for its native Mach-O binaries.

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
python tools/prepare_demo.py
python -m src --config .demo/correct.yaml --output-dir reports/demo --skip-hardening
```

The final command exits **40** because ELF hardening was explicitly skipped;
its test findings are all `Fixed`. The expected verdict for a complete Linux
container run is **0**, verified in container execution with complete ELF hardening
and preserved under `reports/container_verified/` (see [`docs/linux-verification.md`](docs/linux-verification.md)).
The local fixture
repository is created under `.demo/`; the preparer refuses to overwrite a
nonempty destination. For a new fixture use `--output-dir PATH`.

Other entry points are `patch-validator` and `python src/orchestrator.py`, with
the same arguments. `--verbose`, `--skip-minimize`, and `--skip-hardening` are
supported. Explicit skips prevent an overall PASS and are recorded in the report. Skipping minimization still
saves original crash reproducers.

```sh
python -m src -c .demo/incomplete.yaml -o reports/incomplete --skip-hardening
# Expected exit: 10 (the alternate input bypasses the partial guard).
python -m src -c .demo/regression.yaml -o reports/regression --skip-hardening
# Expected exit: 20 (the memory error is blocked, but a valid input is rejected).
python -m unittest discover -s tests -v
```

Tests use temporary Git repositories and real C builds, including the vendored
cJSON and TLV study sources. No test-time target downloads are needed.
They also exercise failure verdicts, dirty checkout preservation, shell-sensitive
paths, stdin, signals/timeouts, source correlation, minimization, and report escaping.

## Defense day: evaluate an unseen patch

After installation and `python tools/prepare_targets.py`, run from the project
checkout with a fresh output directory for each submission:

```sh
patch-validator --config configs/cjson_correct.yaml \
  --patch /absolute/path/unseen.patch -o reports/unseen
# Equivalent entry point:
python -m src --config configs/cjson_correct.yaml \
  --patch /absolute/path/unseen.patch -o reports/unseen
```

`--patch` applies the submitted diff to the configured `base_commit` in a
temporary clone, replacing the configured `patched_commit` for this evaluation.
The original repository and working-tree edits are preserved. The normal
pipeline evaluates both build modes against the unchanged independent oracle,
including remaining/new security errors and functional regressions. Verdicts
come from execution evidence, never the patch filename or known revision names.
Standard exits are `0` (pass), `10` (remaining/new security error), `20`
(functional regression), `30` (build/config/tool error, including patch-application
failure), and `40` (inconclusive). A complete Linux/ELF run is required for pass.

After patch preparation, pipeline reports are written to the output directory.
Patch-preparation failures return `30`, print a diagnostic, and write
`report.json` in a fresh output directory when writable. If an earlier run
already owns the evidence directory or has a report, the failure is recorded
in a separate `patch-failure-*/report.json`. The diagnostic prints the report path.
Its `unseen/` folder retains the
submitted patch, evaluated diff, exact commits, configs, source bundle, and
restore/rerun commands. An existing `unseen/` folder is never overwritten.
The legacy `python tools/eval_unseen_patch.py --base-config CONFIG --patch-file
PATCH --output-dir OUTPUT` command remains supported; it also accepts
`--patched-commit REF` instead of `--patch-file PATCH`.

## Linux container

Docker must be running. The image contains an already prepared offline demo.
The course requires x86_64; use the explicit platform on ARM hosts.

```sh
docker build --platform linux/amd64 -t patch-validator -f docker/Dockerfile .
mkdir -p reports/container
docker run --rm --platform linux/amd64 --network none --memory 2g --cpus 2 \
  --pids-limit 128 --cap-drop ALL --security-opt no-new-privileges \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/reports/container:/workspace/reports:rw" \
  patch-validator --config .demo/correct.yaml --output-dir /workspace/reports
```

Compose uses the same demo, limits, default seccomp policy, and no network:

```sh
mkdir -p reports
LOCAL_UID=$(id -u) LOCAL_GID=$(id -g) \
  docker compose -f docker/docker-compose.yml up --build --abort-on-container-exit --exit-code-from patch-validator
```

To run a real target, mount `targets`, `tests`, and `configs` read-only, with
the configured regression directories and reports directory mounted writable.
Compose already supplies these mounts; override
its command with `docker compose ... run --rm patch-validator --config
configs/cjson_correct.yaml --output-dir /workspace/reports`. Prepare host targets
first when using Compose's bind mounts. Configurations and build commands are trusted
project inputs: building a target executes its code and build scripts.

Release tests on native Linux use `RLIMIT_AS` for the configured memory cap.
On Linux x86_64 with `vendor_id: VirtualApple` in `/proc/cpuinfo`, the runner
recognizes Rosetta and omits that cap only when `/sys/fs/cgroup/memory.max`
contains a finite positive limit. The supplied Docker commands provide a 2 GiB
container-wide memory bound for this compatibility path. Missing, unreadable,
unlimited, or invalid cgroup limits retain `RLIMIT_AS`; other emulators receive
no automatic exemption.

Sanitized tests retain ASan's configured RSS limit because ASan reserves a very
large virtual address range. Native macOS runs do not enforce the release
address-space cap. Each execution's `memory_limits` records the configured cap,
selected `RLIMIT_AS`, ASan RSS limit, observed cgroup bound, and Rosetta detection
in JSON reports and bundle/replay results. Replay checks its current environment.
The Rosetta release fallback uses the container's physical-memory allowance;
the configured 256 MiB process cap is inactive. Swap is controlled separately by
[Docker's resource settings](https://docs.docker.com/engine/containers/resource_constraints/).
A resource/runtime failure or timeout remains inconclusive. See the
[ASan limitation](https://clang.llvm.org/docs/AddressSanitizer.html#limitations).

Target stdout/stderr are spooled to disk, with a 16 MiB file-size cap and a
1 MiB per-stream report limit. Exceeding the report limit is a resource failure;
it cannot be classified as fixed. These limits also apply to bundle replay.

## Configuration contract

All configured paths are relative to the **YAML file's directory**, independent
of the invoking working directory. Oracle input paths are relative to their
manifest and must remain inside that directory. Git branches/tags are resolved
to exact commits before any builds.

```yaml
project_name: my_target
repository_path: ../targets/my_target
base_commit: exact-base-commit-or-tag
patched_commit: exact-patched-commit-or-tag
build:
  release_cmd: >-
    clang -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2
    -fPIE -pie -Wl,-z,relro,-z,now driver.c parser.c -o {output_dir}/target_bin
  sanitized_cmd: >-
    clang -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all
    -fno-omit-frame-pointer driver.c parser.c -o {output_dir}/target_bin
  release_binary: target_bin
  sanitized_binary: target_bin
execution:
  input_mode: file
  cmd_template: "{binary} {input_file}"
  timeout_sec: 5
  memory_limit_mb: 256
test_suites:
  oracle_manifest: ../tests/my_target/oracle_manifest.json
  regression_dir: ../tests/my_target/regression
```

Build commands run in **separate Git archive snapshots** for each revision and
mode. `{output_dir}` is shell-quoted automatically; leave that placeholder
unquoted in the command. Binary paths are relative to that output directory.
Commands that produce a binary relative to the source snapshot are also supported;
the executable is copied into the isolated output directory. Every required
build must succeed. Builds have a 600-second timeout and retain `build.log`.
Git submodules/LFS payloads are not fetched by archive export; vendor necessary
build sources into the selected revision or prepare a self-contained target.

Execution templates are tokenized before substitution and run without a shell:

| Input mode | Template | Meaning |
| --- | --- | --- |
| `file` | `{binary} {input_file}` | Pass the input filename as one argument. |
| `stdin` | `{binary}` | Send the exact input bytes, including empty input. |
| `args` | `{binary} {input}` | Pass UTF-8 file contents as one argument. |

`{input}` also aliases the filename in file/stdin mode. Shell pipes, redirects,
and shell expansion in execution templates are unsupported; put such work in a
target-specific driver. Keep drivers inside the target's selected Git revisions
so both builds use recorded sources.

## Oracle and classification

A complete suite must cover `valid`, `boundary`, `invalid`, and `exploit` inputs.
Each case needs a unique filename-safe `name`, `category`, `input_file`, and
`expected_exit_code` for the patched outcome. Valid, boundary, and invalid cases
also need independent `expected_stdout` or a real SHA-256 `expected_stdout_hash`.
Use `expected_stdout: ""` when no output is expected.
`expected_error_type` is required for exploits, for example
`heap-buffer-overflow`. Signal-only stops remain inconclusive until corroborated
by classified error evidence. Expected patched outcomes must not crash.
Placeholder hashes, missing files, duplicate names, malformed sections, and
escaping input paths are rejected before execution.

The expected outcomes must come from the target specification or independent
reference tests and be approved as the course requires. Neither patched output
nor model-generated expectations alone establish correctness. The demo oracle
comes from its explicitly defined toy contract: lengths 1–7 echo the bytes and
LF, empty/long inputs return 1 with empty stdout.

Every input runs on all four binaries. When any run crashes, all four executions
are replayed for **three total runs each**. Changes in error signature,
termination, or stdout mark the comparison unstable. A matching release pair and
a matching sanitized pair are classified separately, and both appear in reports.
A sanitizer may establish a fix when the release baseline does not expose the
error, provided both patched modes meet the independent oracle and are stable.

For symbolized error sites, cross-version comparisons map unchanged baseline
lines through the Git diff, including line shifts and detected file renames.
The error type, detection mechanism, function, and mapped location must match.
Changed or deleted sites do not establish the same error identity. Replays and
minimization retain exact source-site signatures within each binary.

| Category | Required evidence |
| --- | --- |
| `Fixed` | Exploit error reproduced on base and absent with expected patched behavior; functional cases meet their oracle. |
| `IncompleteFix` | Same observed error signature persists in a matching mode. |
| `NewIssue` | A new error signature appears in the patched run; causation is not presumed. |
| `FunctionalRegression` | Base meets the independent oracle and patched violates it. |
| `Inconclusive` | Missing baseline reproduction, unstable results, timeout/resource failure, or inadequate evidence. |

Error signatures compare error type, detection method, and symbolized source
location without ASLR addresses. A changed source line may yield a new signature;
inspect the reported frames/diff before claiming a common root cause. Signal-only
errors retain their observed signal and do not claim an inferred memory subtype.

Diff correlation reports `changed_line` when a symbolized frame overlaps a
changed line in the corresponding source version. An association based only on
a Git hunk header is `unknown`. Each match retains the stack frame number and
role, for example `changed_line (caller frame #1: parse_object)`. Markdown and
HTML show this evidence separately for each mode and binary, including source
locations and the limitation that association does not prove causation.
Later stack sequences whose frame numbers restart are labeled `auxiliary`
(for example allocation/free traces); roles describe the first recorded trace.
Caller effects and unsymbolized paths may remain unknown. ELF
hardening records RELRO level, NX, PIE, canary and Fortify symbol evidence, and
warns on reductions. PIE does not prove runtime ASLR; symbols do not prove that
every function is protected. Missing `PT_GNU_STACK` leaves NX unknown and marks
hardening `inconclusive`, so `analysis_complete` is false and a complete PASS
cannot be returned. Known protection reductions still produce warnings.

## Reports, replay, and regression inputs

Markdown and HTML reports start with a combined verdict table that also shows
each mode's classification. Separate release and ASan/UBSan sections then show
base/patched execution records and every replay: exit codes, signals, execution
status, stdout, and stderr. The release section includes ELF hardening; the
instrumented section includes error type, detection mechanism, and symbolized
stack frames. Missing evidence, timeouts, and resource failures remain explicit.
HTML uses scrollable tables and escaped output; complete JSON evidence is retained.

Every validator JSON report includes three independent aggregate fields, including
reports saved after configuration, build, or analysis failures:

| Field | Values and meaning |
| --- | --- |
| `security_status` | `fail` if a remaining or new security error is confirmed; `pass` if all configured exploit cases are fixed and stable comparisons leave no unresolved security evidence; otherwise `inconclusive`. |
| `functionality_status` | `fail` if a stable valid, boundary, or invalid case meets its baseline oracle but violates it after patching; `pass` if all those cases meet their patched oracle in both modes; otherwise `inconclusive`. |
| `analysis_complete` | Boolean indicating that required pipeline stages and checks completed. It starts as `false` and remains false after failures or skipped/unsupported required checks. |

These fields are computed from findings and execution evidence, independently of
exit-code priority. A security error on a previously correct functional input can
fail both statuses. An incomplete analysis preserves confirmed failures but cannot
claim a pass for unexamined cases. Timeouts, resource failures, unclassified
signals, and unstable comparisons leave affected conclusions inconclusive unless
other evidence already confirms a failure. Completed execution can still yield an
`inconclusive` judgment, such as when the expected baseline error is not reproduced.
All conclusions apply within the configured tests and build settings.

`--output-dir` contains:

```text
report.json / report.md / report.html   verdict, warnings, errors, and evidence
patch.diff                             exact source diff
build/<variant>_<unique-id>/            preserved snapshot, binary, build.log
results/<variant>.json                  separate raw executions and replays
reproducers/<test>/                     original/minimized inputs, four binaries,
                                       metadata.json, run-<variant>.sh
regression/<repository-key>/           generated inputs and oracle_manifest.json
```

Failure runs also write reports when the output directory is writable. Old build
artifacts are retained to avoid invalidating earlier reproducers. A fresh run
replaces the top-level report and per-test reproducer directory contents; use
separate output directories to retain separate experiment reports.

Minimization uses byte deletion and preserves the observed error type and source
site. When a fixed test is shrunk, its patched oracle behavior must also hold.
For a newly observed error on a valid, boundary, or invalid case, reduction must
preserve the independent baseline oracle in both build modes. The generated
case retains its original category, exit code, and output expectations; its
`observed_error_type` records the diagnostic without requiring a baseline crash.
The original input is always retained; the minimized input is replayed three
times against all four binaries. Unstable or unsymbolized crashes are bundled without claiming a minimized
same-site reproducer. The search is bounded at 200 attempts and reports its
attempt count and status. This is a practical bounded reducer, not a guarantee
of a globally smallest input.

Generated regression manifests are copied into both the report directory
and optional `test_suites.regression_dir`. The configured directory must exist
and be writable; it is loaded on subsequent runs even with a fresh report or
repository path. Identical copies are deduplicated; conflicting names or inputs
are configuration errors. Without a configured directory, reuse the report
directory to retain cases. Arbitrary files without an oracle are not assigned
invented expected behavior.

CI restores these target corpora from its latest available branch-scoped cache,
saves updates even after validation fails, and includes them in uploaded artifacts.
Commit reviewed regression files for permanent retention: caches may be evicted.

Replay with the project installed (same OS/architecture and compatible runtime):

```sh
python -m src.replay reports/demo/reproducers/exploit --build base_sanitized
python -m src.replay reports/demo/reproducers/exploit --build patched_sanitized --minimized
```

Replay uses the saved execution limits and copied binaries. The bundle may be
moved; its binaries and inputs resolve relative to the bundle. Metadata records
exact source commits, binary hashes, build commands, environment overrides,
execution settings, and all original replays. Source snapshot paths in traces
refer to the saved build workspace; retain that workspace for source inspection.

## Exit codes and CI

| Exit | Meaning |
| --- | --- |
| `0` | Tested patch outcomes meet their oracles; no observed issue. |
| `10` | Remaining or newly observed security error. |
| `20` | Functional regression, with no confirmed security error. |
| `30` | Configuration/oracle/workspace error, required build failure, or environment/tool error. |
| `40` | Inconclusive analysis, unsupported/skipped mandatory checks, or unclassified termination. |

Priority is **30 > 10 > 20 > 40 > 0**. An empty suite or inconclusive test never
passes. No finite passing suite proves the absence of every vulnerability.

The active workflow is [`.github/workflows/validate.yml`](.github/workflows/validate.yml),
in the [GitHub workflow discovery location](https://docs.github.com/en/actions/concepts/workflows-and-actions/workflows).
It runs the full test suite, all three demo verdicts, and all seven target
scenarios in resource-limited Linux containers, uploading evidence even on
failure. Test discovery uses the image's non-root user and has network access
disabled.

## Code layout

- `src/core/`: configuration, oracle validation, snapshot builds, execution/triage.
- `src/modules/`: classification, diff correlation, hardening, reduction, reports.
- `src/orchestrator.py`: pipeline and CLI; `src/replay.py`: bundle replay.
- `examples/demo/`, `tools/prepare_demo.py`: offline C fixture and setup.
- `tests/test_*.py`: foundation unit and integration checks.
- `examples/targets/`, `tools/prepare_targets.py`: vendored source, patches,
  provenance, and deterministic offline preparation of both target studies.
- `tests/cjson/`, `tests/tlv_parser/`, `configs/`: independent target corpora and
  runnable correct/incomplete/regression comparisons.
- `docker/`, `.github/workflows/`: repeatable runtime and CI.
