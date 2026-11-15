# Remaining university deliverables

The target source/revision work is implemented. The supplied brief still requires
approval and measured Linux evidence before final assessment:

- [x] Two independent C/C++ target programs running as Linux x86_64 ELF binaries,
  including at least one real non-toy project/library. Source preparation is
  complete: real cJSON 1.7.17 and the independent original TLV program. ELF
  builds and patched release/sanitizer functional executions are measured using
  the guarded Rosetta memory policy. See [Linux evidence](linux-verification.md).
- [ ] Instructor-approved targets, source provenance, patch provenance, harness
  interfaces, independent reference tests, and expected outcomes.
- [x] For **each target**, exact vulnerable, correct, incomplete, and functional
  regression revisions, with drivers present in the selected revisions.
- [x] A documented original memory-error PoC and a distinct input demonstrating
  the incomplete-fix bypass, plus valid, boundary, and invalid test suites.
- [ ] Real target runs establishing verdicts 0, 10, and 20 using matching release
  and sanitized builds; failures/inconclusive conditions must remain explicit.
- [ ] Reviewed error-to-diff evidence, reproducible bundles with at least three
  replays, minimized same-error/site inputs, and automatically rerun regressions.
- [x] Linux container ELF hardening evidence and detection of unintended reductions
  (static inspection; complete validator verdicts remain pending).
- [ ] CI runs for the pinned real targets and retained JSON/human-readable reports.
- [ ] An independently reproducible submission containing source, configs,
  revisions, patches, tests, evidence, pipeline, and run instructions.
- [ ] Actual contribution records for all four members and preparation for
  individual explanation, result analysis, and a small live code/config change.
- [ ] Evaluation on unseen patches without hardcoding patch names or identifiers.

The demo tags `base`, `correct`, `incomplete`, and `regression` only create
repeatable integration fixtures. The validator decides from their builds and
runtime outcomes; it does not classify from tag names.

## Foundation verification on this workspace

Native macOS verification can check the Python/C pipeline and file contracts.
Both target studies now have native reports and saved replays under
`reports/targets_native/`. Their correct patches meet all corpus expectations;
incomplete and regression comparisons return 10 and 20. Correct comparisons
return 40 because ELF hardening is explicitly skipped on macOS. Source and
revision details are in `examples/targets/` and `docs/target-revisions.json`.
The course's Linux ELF/container verification requires a running Docker daemon.
The CI workflow includes that verification for Linux x86_64. Report its actual
result when run; do not replace it with an assertion based on the native smoke test.

Latest partial Linux measurements are in `reports/linux/rosetta-compatibility/`:
12 x86_64 ELF builds, full hardening inspection, detected canary/RELRO reductions,
and 124 passing patched release/sanitizer functional checks. Rosetta now uses a
verified finite container memory bound for release execution; native Linux keeps
the process address-space cap. Original mapping failures remain recorded under
`reports/linux/defensive/`. This does not establish a full validator exit 0.
See [the measured results](linux-verification.md).
