# Prepared C target repositories

Run `python tools/prepare_targets.py` from the project root. It prepares both
targets offline from the versioned material under `examples/targets/`:

- **cJSON:** the real upstream 1.7.17 C library, issue #800 and its upstream fix.
- **TLV parser:** an independent original C program with a documented binary
  protocol and a shared label-parser overflow.

Each directory becomes a standalone Git repository containing source, driver,
and Makefile in the `base`, `correct`, `incomplete`, and `regression` revisions.
Patched revisions are independent children of `base`. TLV also has the existing
`hardening_weak` scenario. `correct` is checked out so source is immediately
visible; the former empty `*_patch/` directories are replaced by actual Git
history. For example, `git -C targets/cjson diff base correct` shows the fix,
and `git -C targets/tlv_parser show incomplete:tlv_parser.c` shows a revision.

Exact generated commit IDs are in `revisions.json` and the versioned copy
`docs/target-revisions.json`. Source provenance, licenses, patches, harness
contracts, and oracle sources live with the templates and tests. Preparation
uses fixed Git metadata and refuses to overwrite populated repositories,
including local changes. For another copy use `--output-dir PATH`.

The validator reads these repositories without changing their checkouts.
Generated targets remain ignored by the outer project; distribute the tracked
templates, patches and preparer to reproduce them. Instructor approval and
Linux x86_64 ELF evidence are separate from source preparation.
