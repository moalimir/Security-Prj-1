# Team responsibilities and contribution statement

Project: Automated Security Patch Validation and Regression Testing in CI/CD.
This statement follows sections 5 and 6 of the [Persian assignment](../project1.txt).

## Responsibility allocation

The team declares an equal 25% share of the work for each member, confirmed by
the team representative on 2026-11-17. The sections below describe the contribution
scope declared for each member, including design, implementation, tests, result
analysis, and technical documentation. These shares do not determine individual
defense grades.

| Contributor | Member | Assigned section | Share |
| --- | --- | --- | --- |
| 1 | Mahan Rezai | Secure build environment and dynamic execution | 25% |
| 2 | Alireza Asgarian | Patch analysis and security verdicts | 25% |
| 3 | Alireza Mosallanezhad | Reproducibility, minimization, and regression testing | 25% |
| 4 | Mohammad Ali Mirzayi | Binary security assessment, security reporting, and CI verification | 25% |

### 1. Mahan Rezai — Secure build environment and dynamic execution

- Validate configuration and build isolated base/patched revisions in release
  and ASan/UBSan modes.
- Execute matching inputs and collect diagnostics, signals, exit codes, stdout,
  and stderr; distinguish timeouts and resource failures from security findings.
- Maintain container isolation, execution limits, and build/input integration
  for both cJSON and TLV.
- Test and document build, configuration, and execution behavior.

Primary scope: `src/core/config_manager.py`, `src/core/build_engine.py`,
`src/core/test_runner.py`, `docker/`, and target build/input configurations.
Relevant checks include execution/configuration cases in `tests/test_foundation.py`,
`tests/test_build_and_diff.py`, and `tests/test_pipeline.py`.

### 2. Alireza Asgarian — Patch analysis and security verdicts

- Analyze Git diffs and correlate runtime stack frames with changed code,
  including changes in callers and shifted source lines.
- Compare error identities and classify fixed errors, incomplete fixes, new
  issues, functional regressions, and inconclusive findings.
- Maintain verdict aggregation and exit-code decisions, including priority
  `30 > 10 > 20 > 40 > 0`.
- Maintain unseen-patch evaluation without classifying by patch names or IDs;
  review existing target patch scenarios and their provenance.
- Test and document classification decisions and the limits of correlation
  evidence; association alone does not establish causation.

Primary scope: `src/modules/diff_analyzer.py`, `src/modules/classifier.py`,
`src/unseen_patch.py`, `src/utils/constants.py`, and classification sections of
`src/orchestrator.py`. Relevant checks include `tests/test_analysis.py`, diff
cases in `tests/test_build_and_diff.py`, `tests/test_unseen_patch.py`, and
`tests/test_unseen_patch_integration.py`.

### 3. Alireza Mosallanezhad — Reproducibility and regression testing

- Maintain valid, boundary, and invalid corpora and independent expected
  outcomes for both targets; document the reference basis for the oracles.
- Preserve reproducer inputs, exact revisions, binary hashes, build settings,
  relevant environment, and complete execution commands.
- Record at least three replays and identify unstable findings.
- Minimize inputs while preserving the same error and relevant location;
  retain original/minimized inputs and required oracle behavior.
- Persist regression cases and verify automatic reload on subsequent runs.
- Test and document reproduction, minimization, and regression behavior.

Primary scope: `src/core/oracle.py`, `src/modules/testcase_minimizer.py`,
`src/replay.py`, target corpora/oracle manifests, and reproduction, stability,
and regression-persistence sections of `src/orchestrator.py`. Relevant checks
include `tests/test_regressions.py`, `tests/test_tlv_target.py`, and replay/reload
checks shared with contributor 4.

### 4. Mohammad Ali Mirzayi — Binary security assessment and CI verification

- Inspect release ELF binaries for NX, PIE, stack canary, and RELRO
  (none/partial/full), preserving supporting evidence.
- Compare protections across revisions and report unintended reductions.
  Explain that PIE does not prove runtime ASLR and canary evidence does not
  establish protection of every function.
- Produce JSON and readable security reports that separate error type,
  detection mechanism, termination details, and release/sanitizer results.
- Preserve independent security, functionality, and analysis-completeness
  statuses, including simultaneous failures and inconclusive results.
- Maintain CI hardening/report/replay checks, exit-code handling, and retention
  of reports and reproducer artifacts.
- Verify the final scenario matrix, assemble submission evidence, and check
  clean-environment run instructions. Each member supplies their own technical
  documentation; Mohammad assembles the final submission documentation.
- Test and document hardening and report behavior.

Primary scope: `src/modules/hardening_checker.py`,
`src/modules/report_generator.py`, `.github/workflows/validate.yml`,
`ci/check_reports.py`, `tools/verify_all_scenarios.py`, and submission documentation.
Relevant checks include `tests/test_reports.py`, `tests/test_report_statuses.py`,
hardening checks in `tests/test_build_and_diff.py` and `tests/test_tlv_target.py`,
and scenario/report verification.

Shared files are coordinated by the responsibilities above. Subsystem owners
remain responsible for their integration points; report presentation does not
transfer verdict logic from contributor 2 to contributor 4.

## Team-confirmed contribution record

The team representative confirmed this contribution statement on 2026-11-17.
The scope and primary source/test paths for each member are detailed above.
This is the team's declaration, not an independent authorship audit; it does
not invent commit attribution or individual test-run records. Participation is
assessed using attributable output, development evidence, and individual defense,
not commit counts or lines of code alone.

| Member | Declared contribution scope |
| --- | --- |
| Mahan Rezai | Secure builds, configuration, execution, isolation, and target build/input integration; associated tests, analysis, and documentation (section 1). |
| Alireza Asgarian | Diff correlation, error classification, verdicts, unseen-patch evaluation, and patch-scenario review; associated tests, analysis, and documentation (section 2). |
| Alireza Mosallanezhad | Oracles/corpora, replay stability, reproducer bundles, minimization, and regression persistence; associated tests, analysis, and documentation (section 3). |
| Mohammad Ali Mirzayi | ELF protections, security reports, CI checks/artifacts, and submission verification; associated tests, analysis, and documentation (section 4). |

## Individual defense requirements

Every member must understand the overall architecture and their assigned code.
Defense is individual, without help from teammates or answer-generating tools.

| Assessment | Points |
| --- | --- |
| Explain architecture, design choices, and assigned code logic | 3 |
| Analyze a finding/test result and connect evidence to the tool's decision | 3 |
| Make a limited code/configuration change and test its effect within the defense time | 4 |

Eligibility requires effective participation, at least 5/10 overall, and at
least 1 point in each category. Failure to meet these conditions gives that
member a zero project grade, regardless of the team's technical result.
For eligible members, the assignment defines:

`Individual grade = 2.5 × (team technical score / 100) × (individual defense score / 10)`

Language-model assistance is allowed during project work, but each member
remains responsible for understanding, checking, and defending their output.

Include this statement with the final submission.
Use the [course checklist](course-checklist.md) for required
technical artifacts and the [project status](project-status.md) for verification
and instructor-approval status. The contribution statement does not certify
completion of outstanding technical verification or submission packaging.
