# Foundation completion

The university brief in `project1.txt` (matching the six-page PDF) is the
specification. This work completes the reusable pipeline and development setup;
it does not supply the team's two approved final target studies.

1. Unify configuration, build, execution, and finding interfaces. Validate paths,
   manifests, commands, and independent expected outcomes before running builds.
2. Build four separate binaries from Git snapshots without changing or cleaning
   the target checkout. Retain hashes, exact commits, commands, and logs.
3. Execute matching build modes separately, distinguish crashes from time/resource
   failures, replay crashes three times, and classify from observed evidence.
4. Connect diff correlation, ELF hardening, signature-preserving minimization,
   reproducer bundles, generated regression cases, and JSON/Markdown/HTML reports.
5. Provide an offline C demo with correct, incomplete, and regression patches,
   tests, discoverable GitHub Actions, and a constrained Docker environment.
6. Verify real builds and CLI outcomes 0/10/20/30/40. Document limits and the
   remaining course deliverables honestly.

Scope reaches `src/core`, `src/modules`, `src/utils`, the CLI, configs, fixtures,
tests, Docker, CI, and README. Existing example target configs remain templates.
No target repository or user data may be reset, cleaned, or overwritten.

Checks cover malformed config/oracles, missing files and commits, shell-sensitive
paths, stdin (including empty input), signals and timeouts, sanitizer parsing,
classification without a valid baseline, incomplete builds, source preservation,
escaping report content, minimization identity, and the actual C pipeline.
