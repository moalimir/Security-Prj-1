# Remaining university deliverables

See [Project status](project-status.md) for current evidence and the approval record.
Checked items below describe implemented capabilities or dated evidence, not full-grade certification.

The target source/revision work and saved Linux scenarios are implemented.
Instructor approval and the contribution statement are confirmed by the team.
Final-revision verification and submission packaging remain:

- [x] Team-confirmed contribution statement for all four members, with equal 25%
  shares and subsystem responsibilities, recorded in
  [Team contributions](team-contributions.md). Include it in the submission;
  individual participation and understanding are assessed during defense.
- [x] Two independent C/C++ target programs running as Linux x86_64 ELF binaries,
  including at least one real non-toy project/library. Source preparation is
  complete: real cJSON 1.7.17 and the independent original TLV program. ELF
  builds and patched release/sanitizer functional executions are measured using
  the guarded Rosetta memory policy. See [Linux evidence](linux-verification.md).
- [x] Instructor approval complete, as confirmed by the team on 2026-11-17;
  see the [approval record](project-status.md#instructor-approval-confirmed-by-the-team).
- [x] For **each target**, exact vulnerable, correct, incomplete, and functional
  regression revisions, with drivers present in the selected revisions.
- [x] A documented original memory-error PoC and a distinct input demonstrating
  the incomplete-fix bypass, plus valid, boundary, and invalid test suites.
- [x] Real target runs establishing verdicts 0, 10, and 20 using matching release
  and sanitized builds; failures/inconclusive conditions must remain explicit.
  Established across all seven target scenarios in container execution (see
  `reports/container_verified/`).
- [x] Reviewed error-to-diff evidence, reproducible bundles with at least three
  replays, minimized same-error/site inputs, and automatically rerun regressions.
  Verified with `ci/check_reports.py replay` and automated reload checks.
- [x] Linux container ELF hardening evidence and detection of unintended reductions
  (static inspection and complete validator verdicts 0, 10, 20 established).
- [x] CI runs for the pinned real targets and retained JSON/human-readable reports.
  [Run 44108086819](https://github.com/moalimir/Security-Prj-1/actions/runs/44108086819)
  passed at implementation revision `4bd8974`, including full test discovery,
  all seven target scenarios, hardening warnings, and replay/reload checks.
  Subsequent commits receive their own CI runs.
- [x] An independently reproducible submission containing source, configs,
  revisions, patches, tests, evidence, pipeline, and run instructions.
  Offline target reconstruction exists; `tools/package_submission.py` packages
  source, configs, tests, container-verified reports, and reproducers into
  `dist/security_patch_validator_submission.zip`. Source-byte comparisons,
  ZIP integrity, executable permissions after unzip, and offline target revision
  reconstruction were checked on 2026-11-17. Regenerate after final updates.
- [x] Evaluation on unseen patches without hardcoding patch names or identifiers.
  Both CLI entry points have unmocked integration coverage for all five exits,
  line insertions, caller changes, mixed findings, and argument inputs. Harmless
  compiled fixtures emit synthetic diagnostics; they do not validate ASan itself.
  Full real-target patch-file integration on the final revision remains to verify.

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

Complete Linux measurements across all seven target scenarios are in
`reports/container_verified/`: verdicts 0, 10, and 20 are established with full
ELF hardening inspection, detected canary/RELRO reductions, 3-run replays, and
verified regression reloads. Rosetta uses a verified finite container memory
bound for release execution; native Linux keeps the process address-space cap.
The tracked `.github/workflows/validate.yml` defines all seven scenarios and
replay/reload checks for both correct targets.
Earlier partial measurements and failure logs remain recorded under
`reports/linux/rosetta-compatibility/` and `reports/linux/defensive/`.
See [the measured results](linux-verification.md).
