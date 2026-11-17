# Project status — 2026-11-17

This is the current status record. Dated verification documents describe their
recorded runs; they do not certify later commits or instructor approval.
Instructor approval and the contribution statement are confirmed by the team
as recorded below. Individual defense remains separately assessed.

## Implementation and current verification

| Area | Implemented and checked | Limit |
| --- | --- | --- |
| Error matching | Unchanged sites map through line shifts and renames (`d647390`) | Changed/deleted sites do not prove error identity. |
| Regression persistence | Report and configured corpora are populated; identical copies deduplicate; write failures return 30 (`11ce564`, `92b497c`) | Commit reviewed cases for durable retention; Actions caches can expire. |
| New errors | Valid/boundary/invalid discoveries retain their original oracle during reduction and reload (`5cc7a15`) | Unstable discoveries retain bundles without publishing a regression. |
| Unseen patches | Eight real CLI integration tests cover exits 0/10/20/30/40, insertions, callers, mixed findings, and literal/empty arguments (`c95d581`) | Harmless compiled fixtures print synthetic diagnostics; these checks do not validate ASan itself or every unseen patch. |
| JSON contract | Independent security/functionality statuses and an always-present completion boolean (`05a8e9f`) | Conclusions apply to configured tests; incomplete checks cannot establish a full pass. |
| Current framework checks | 76 focused native and restricted Linux x86_64 tests pass, including submission-tool regressions; hosted full test discovery and all seven target scenarios pass at `4bd8974` | Synthetic CLI diagnostics verify infrastructure behavior; defense-day unseen patches remain separately assessed. |
| Submission archive | All tracked files match the ZIP, including the Persian brief; standard unzip preserves binary permissions and offline preparation restores the pinned revisions | Retain the final revision's hosted reports and regenerate the archive after source or evidence updates. |

The local verification commands are:

```sh
python -m unittest tests.test_analysis tests.test_build_and_diff tests.test_foundation tests.test_regressions tests.test_reports tests.test_report_statuses tests.test_unseen_patch tests.test_unseen_patch_integration tests.test_submission_tools -q
# Inside the Linux image, with the current checkout mounted at /workspace:
python -m unittest tests.test_report_statuses tests.test_unseen_patch_integration -q
```

Linux reports cover seven real-target scenarios and the correct-target
replays/reloads. See [Linux evidence](linux-verification.md). Those files live in
Git-ignored `reports/container_verified/`; include them in the submission ZIP.
The current hosted workflow retains equivalent reports and regression corpora
in its `validation-reports` artifact.
Locally generated, Git-ignored tutorial HTML/PDF exports also describe an older
snapshot: their statements that `analysis_complete` can be absent or that the
README still lacks Linux results are superseded by the current JSON contract and
this status record. They are not included in the pushed source documentation.

The implementation revision `4bd89743e3bdea1da268730ffe6e9bcc0e2023bf` passed
[hosted run 44108086819](https://github.com/moalimir/Security-Prj-1/actions/runs/44108086819)
on 2026-11-17. Full test discovery, all three demo verdicts, all seven target
scenarios, hardening warnings, saved replays, and generated regression reloads
completed successfully. The containers use Docker init to reap orphaned
subprocesses within the existing 128-process limit. This documentation update
records that measured result; subsequent commits receive their own CI runs.

## Instructor approval: confirmed by the team

On 2026-11-17, the team representative confirmed in the project chat that
instructor approval of targets, provenance, and independent oracles is complete.
This records the team's confirmation; the confirmation date is not asserted to
be the date of the instructor's decision.

The associated project material is:

- cJSON: [source and patch provenance](../examples/targets/cjson/provenance.json),
  [study contract](../examples/targets/cjson/README.md),
  [oracle](../tests/cjson/oracle_manifest.json).
- TLV: [original source, protocol, and revision contract](../examples/targets/tlv_parser/README.md),
  [oracle](../tests/tlv_parser/oracle_manifest.json).
- Both: [exact generated revisions](target-revisions.json),
  [build/input configurations](../configs/), and [assignment](../project1.txt).

## Team contribution statement

On 2026-11-17, the team representative confirmed the added
[contribution statement](team-contributions.md) as the team's contribution record.
It records four equal 25% shares and each member's technical scope. This is a
team declaration; it does not assert independently audited authorship or a
completed individual defense.

## Remaining technical/submission work

- Retain the submitted commit's successful CI run and its reports and reproducer artifacts.
- Verify real-target patch-file evaluation on the final revision; the compiled
  synthetic fixtures establish infrastructure behavior within their stated scope.
- Regenerate the verified submission archive after final source or evidence
  updates using `python tools/package_submission.py`.

No full-grade percentage is asserted: implemented capability, measured evidence,
formal approval, and submission packaging are separate requirements.

## Assignment translation erratum

The priority sentence in `project1_english_translation.pdf` reverses the order.
Use the original assignment, `src/utils/constants.py`, and the implemented order
**30 > 10 > 20 > 40 > 0**. The supplied assignment artifacts are retained;
this note records the translation discrepancy without changing the source brief.
