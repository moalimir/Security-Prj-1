# Target study implementation

The requested deliverable is two independent C targets with genuine source
revisions: vulnerable base, complete fix, incomplete fix, and functional
regression. Keep the validator unchanged; it must infer outcomes from execution.

Use the real cJSON 1.7.17 library and upstream issue #800 / fix c390438 for
the first study. Vendor the required library sources and MIT license so builds
and preparation need no network. The incomplete and regression versions are
explicit course mutations, not upstream releases. Reuse the existing original
TLV protocol implementation and patches for the second study. Full upstream
history and four duplicated source directories add no build capability; use
standalone Git repositories with four tags and independent children of base.

Implementation reaches the vendored cJSON sources, common file driver,
Makefile, three patches, independent oracle inputs, offline target preparer,
cJSON configs, integration tests, and onboarding documentation. Existing TLV
configs, Docker and CI already reference this preparation/config interface.
The preparer may replace only the known empty skeletons, must preserve existing
source/work, and must reproduce the same commit IDs across destinations.

1. Add checks for preparation, source provenance, archived builds, incomplete
   bypasses, boundary regressions, and independently specified outputs. Confirm
   the missing preparer fails before implementation.
2. Vendor pinned cJSON sources; add the length-aware driver, portable builds,
   upstream complete fix and two labeled mutations. Register original and nested
   exploit inputs, plus valid, boundary, and invalid cases.
3. Implement deterministic offline preparation and connect all three cJSON
   configs. Materialize both target repositories in this workspace and record
   exact revisions.
4. Run focused integration checks, the full unit suite, all six validator
   comparisons, and saved exploit replays. Document observed evidence and
   unresolved Linux/container and instructor-approval requirements.

Review focus: truncated unpadded input must reach the real library; nested
objects must bypass the partial fix; trailing bytes must be rejected; empty
objects must survive the correct patch; preparation must not overwrite work.
