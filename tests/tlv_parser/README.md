# Independent TLV protocol oracle

The 24 manifest cases specify expected bytes from the [protocol contract](../../examples/targets/tlv_parser/README.md).
They cover six valid packets, five boundaries, eleven invalid packets, and two
heap-overflow exploits. All paths are relative to `oracle_manifest.json`.

Every valid/boundary output is a literal expectation. Every invalid/exploit
packet must exit `1` with empty stdout on the correct revision. The baseline
must produce ASan `heap-buffer-overflow` on both exploit cases. The incomplete
revision must still crash on the nested bypass. The regression revision must
reject empty and 16-byte labels that the independent protocol permits.

Instructor approval of this study and its reference expectations is confirmed by the team.
See the [shared approval record](../../docs/project-status.md#instructor-approval-confirmed-by-the-team).
