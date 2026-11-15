# Independent cJSON study corpus

The 20 manifest cases cover valid documents, empty/boundary values, invalid
syntax, trailing data, and two unpadded malformed-object exploits. Successful
cases have explicit compact JSON + LF expectations; rejected documents have
exit 1 and empty stdout. Expectations were written independently of target
execution and are cross-checked with Python's standard-library `json` parser
in `tests/test_prepared_targets.py`.

The original exploit comes from upstream issue #800. The nested bypass follows
the same object grammar and tests the incomplete guard's depth restriction.
See [exploit/README.md](exploit/README.md) and the
[target contract](../../examples/targets/cjson/README.md).

The complete fix must meet all cases in release and ASan/UBSan modes. The
incomplete version must still fail the nested exploit under ASan. The
regression version must reject the valid empty-object boundary. These are
observed behavior checks; the validator has no patch-name shortcuts.
Instructor approval of these reference expectations remains pending.

Instructor approval of this study and its reference expectations is **not recorded**.
See the [shared approval status](../../docs/project-status.md#instructor-approval-not-recorded) for scope and required evidence.
