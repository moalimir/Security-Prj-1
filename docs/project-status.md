# Project status — 2026-11-15

This is the current status record. Dated verification documents describe their
recorded runs; they do not certify later commits or instructor approval.
Team contribution and individual defense are outside this technical assessment.

## Implementation and current verification

| Area | Implemented and checked | Limit |
| --- | --- | --- |
| Error matching | Unchanged sites map through line shifts and renames (`d647390`) | Changed/deleted sites do not prove error identity. |
| Regression persistence | Report and configured corpora are populated; identical copies deduplicate; write failures return 30 (`11ce564`, `92b497c`) | Commit reviewed cases for durable retention; Actions caches can expire. |
| New errors | Valid/boundary/invalid discoveries retain their original oracle during reduction and reload (`5cc7a15`) | Unstable discoveries retain bundles without publishing a regression. |
| Unseen patches | Eight real CLI integration tests cover exits 0/10/20/30/40, insertions, callers, mixed findings, and literal/empty arguments (`c95d581`) | Harmless compiled fixtures print synthetic diagnostics; these checks do not validate ASan itself or every unseen patch. |
| JSON contract | Independent security/functionality statuses and an always-present completion boolean (`05a8e9f`) | Conclusions apply to configured tests; incomplete checks cannot establish a full pass. |
| Current framework checks | 64 native framework tests and 16 Linux status/integration tests pass | Full real-target sanitizer scenarios have not been rerun for these revisions. |

The local verification commands are:

```sh
python -m unittest tests.test_analysis tests.test_build_and_diff tests.test_foundation tests.test_regressions tests.test_reports tests.test_report_statuses tests.test_unseen_patch tests.test_unseen_patch_integration -q
# Inside the Linux image, with the current checkout mounted at /workspace:
python -m unittest tests.test_report_statuses tests.test_unseen_patch_integration -q
```

Historical Linux reports cover seven real-target scenarios and the correct-target
replays/reloads. See [Linux evidence](linux-verification.md). Those files live in
Git-ignored `reports/container_verified/`; a fresh clone does not contain them.
They predate the recent correctness changes and JSON status contract.
Locally generated, Git-ignored tutorial HTML/PDF exports also describe an older
snapshot: their statements that `analysis_complete` can be absent or that the
README still lacks Linux results are superseded by the current JSON contract and
this status record. They are not included in the pushed source documentation.

The latest hosted success verified before this documentation update was
[run 43708073445](https://github.com/moalimir/Security-Prj-1/actions/runs/43708073445)
at `82e90a2e696bbadfc83dfcdee80e63d746dd005e`. A successful run on an earlier
commit does not establish the result of the revision now being pushed. Check the
new run in GitHub Actions and retain its exact commit and artifacts.

## Instructor approval: not recorded

No instructor decision or approval evidence is recorded in the tracked repository.
Source preparation, provenance checks, passing tests, and this status update do
not grant course approval. This applies to **both** targets, their source/patch
provenance, harness interfaces, independent oracles, and expected outcomes.

The approval material is available for review:

- cJSON: [source and patch provenance](../examples/targets/cjson/provenance.json),
  [study contract](../examples/targets/cjson/README.md),
  [oracle](../tests/cjson/oracle_manifest.json).
- TLV: [original source, protocol, and revision contract](../examples/targets/tlv_parser/README.md),
  [oracle](../tests/tlv_parser/oracle_manifest.json).
- Both: [exact generated revisions](target-revisions.json),
  [build/input configurations](../configs/), and [assignment](../project1.txt).

To record approval, retain the actual decision, date, reviewer, approved scope,
and a durable evidence reference. Identify any requested changes and pin the
approved target revisions and oracle versions. Until that evidence exists, keep
this status as **not recorded**. No approval request has been sent by this update.

## Remaining technical/submission work

- Verify the final commit in hosted CI and retain reports and reproducer artifacts.
- Verify real-target patch-file evaluation on the final revision; the compiled
  synthetic fixtures establish infrastructure behavior within their stated scope.
- Record the instructor's actual decision for the materials above.
- Assemble and independently check a submission archive containing the tracked
  sources plus the otherwise ignored reports, bundles, and reviewed regressions.

No full-grade percentage is asserted: implemented capability, measured evidence,
formal approval, and submission packaging are separate requirements.

## Assignment translation erratum

The priority sentence in `project1_english_translation.pdf` reverses the order.
Use the original assignment, `src/utils/constants.py`, and the implemented order
**30 > 10 > 20 > 40 > 0**. The supplied assignment artifacts are retained;
this note records the translation discrepancy without changing the source brief.
