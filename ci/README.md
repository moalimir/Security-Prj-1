The workflow in `.github/workflows/validate.yml` runs unit discovery, builds a
Linux `amd64` image, and validates the three demo variants plus these target
scenarios:

| Configuration | Expected validator exit |
| --- | ---: |
| `cjson_correct` | 0 |
| `cjson_incomplete` | 10 |
| `cjson_regression` | 20 |
| `tlv_correct` | 0 |
| `tlv_incomplete` | 10 |
| `tlv_regression` | 20 |
| `tlv_hardening_warn` | 0, with canary and RELRO degradation warnings |

Every target container uses `--platform linux/amd64 --network none --memory 2g
--cpus 2 --pids-limit 128 --cap-drop ALL --security-opt no-new-privileges`, with
its report directory and the two target regression corpora bind mounted writable.
Runtime needs no downloads:
the image prepares both target Git repositories during the build. Hardening and
minimization are enabled. Report directories are uploaded even after a failed
workflow step, together with generated target corpora. A branch-scoped Actions
cache restores corpora into fresh checkouts and saves updates even when
validation fails. Reviewed cases should also be committed for permanent retention; cache
availability is not guaranteed.

`python ci/check_reports.py report reports/tlv_correct --expected-exit 0` checks
all four builds, all four result sets, report files, completed analysis, native
ELF inspection, and a symbolized baseline stack associated with the patch.
Add `--expect-hardening-warning` for the warning scenario.

For each correct scenario, CI runs the saved original input against the bundled
`base_sanitized` binary and the minimized input against `patched_sanitized`.
`python ci/check_reports.py replay /workspace/reports` performs these checks
inside the image. A baseline sanitizer crash must return nonzero and match the
oracle's error type. The patched program must satisfy the independent oracle:
malformed exploit input is safely **rejected with exit 1**, so replay success
does not mean every replay CLI exits 0.

For bundles from newly observed errors on functional or invalid inputs, replay
checks the recorded error type and detection mechanism on the affected build.
Clean executions must satisfy the independent oracle. Generated cases retain
their original input category and oracle, so a subsequent correct patch can pass
them without reproducing an error in the baseline.

CI then validates each correct scenario a second time using the same mounted
output directory. `ci/check_reports.py report ... --expected-exit 0
--regression-loaded` requires every generated regression entry to appear in
findings and in execution results for **all four binaries**. The configured
project corpus is also populated and loaded independently of the report path;
identical project/report copies do not execute twice.

The unseen-patch defense command is:

```sh
patch-validator --config configs/tlv_correct.yaml \
  --patch /absolute/path/candidate.patch --output-dir reports/unseen_trial
```

The legacy `python tools/eval_unseen_patch.py --base-config CONFIG --patch-file
PATCH --output-dir OUTPUT` command also supports `--patched-commit <ref>` in
place of `--patch-file` for an existing commit.
The wrapper resolves exact commits, clones locally into a temporary directory,
checks and applies the patch through argument-based Git calls, and invokes
the normal `PatchValidator` pipeline in the same interpreter. It returns the
validator verdict;
configuration, Git, and filesystem failures return 30. Existing source files,
working-tree changes, and refs remain untouched. Use a fresh output directory
for every submission: an existing `unseen/` evidence folder is never replaced.

`unseen/` contains the original submitted patch (when supplied), the evaluated
binary-capable diff, `config.evaluated.yaml`, `config.replay.yaml`, exact hashes,
and `source.bundle`. `metadata.json` records argument arrays to restore the
source bundle and rerun the validator. Run those commands from the project
checkout with the original oracle files available. The evaluated config records
the temporary repository used during execution; the replay config points at the
persistent repository location created by the recorded restore command.
Saved reproducer binaries work independently of that temporary source tree.

Current verification results and their limits are recorded in
[Project status](../docs/project-status.md). Unit discovery includes the eight
unmocked CLI integration tests in `tests/test_unseen_patch_integration.py` and
the independent JSON-status/failure-path checks in `tests/test_report_statuses.py`.
The CLI fixtures compile harmless C programs that print synthetic diagnostics.
Every current validator report contains `security_status`, `functionality_status`,
and boolean `analysis_complete`; see the [JSON contract](../README.md#reports-replay-and-regression-inputs).
