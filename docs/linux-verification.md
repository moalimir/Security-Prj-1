# Linux evidence — 2026-11-15

**The Rosetta release startup conflict is resolved, and full validator verdicts (0, 10, 20)
are established across all seven target scenarios.** Complete measured evidence is preserved
in `reports/container_verified/`. Earlier intermediate measurements remain in
`reports/linux/rosetta-compatibility/` and failure logs in `reports/linux/defensive/`.

## Guarded Rosetta compatibility

`TestRunner.memory_limits()` detects Linux x86_64 with the exact
`vendor_id: VirtualApple` marker measured in this container. Release runs omit
`RLIMIT_AS` only when `/sys/fs/cgroup/memory.max` also provides a finite positive
bound. In this environment the observed cgroup bound is 2,147,483,648 bytes.
Native Linux retains the configured address-space cap. Missing/unreadable CPU
information, unknown emulators, and missing/unlimited/invalid cgroup bounds keep
the original release behavior. The finite-limit check currently supports the
standard cgroup v2 mount used by this Docker runtime; other layouts keep the cap.

Each execution now records `memory_limits`, including the configured memory
limit, selected address-space cap, ASan RSS limit, cgroup memory bound, and
Rosetta detection. These records flow through report serialization and saved
bundle/replay results without changing the configuration schema. Replay evaluates
the current environment. Base/patched executions use the same selection logic.

The release compatibility path uses the container-wide physical-memory limit,
with the 256 MiB process virtual-address cap inactive. ASan retains its 256 MiB
RSS setting. Timeouts, core/output caps, ELF checks, and verdict rules are
preserved. The kernel documents `memory.max` as a cgroup hard memory limit;
swap has its own controls. See [cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)
and [Docker resource constraints](https://docs.docker.com/engine/containers/resource_constraints/).

The same collector was rerun with the current source mounted read-only in the
cached amd64 runtime and a fresh writable evidence directory:

| Comparison | Patched release checks | Patched sanitizer checks | ELF builds |
| --- | ---: | ---: | ---: |
| `cjson_correct` | 18/18 passed | 18/18 passed | 4 passed |
| `tlv_correct` | 22/22 passed | 22/22 passed | 4 passed |
| `tlv_hardening_warn` | 22/22 passed | 22/22 passed | 4 passed |

All **124 patched functional executions** passed. Full RELRO, NX, PIE, canary,
and Fortify symbols remain verified for the correct comparisons. Both expected
canary/RELRO reductions remain detected for the weak variant. The collector
exited 0; its evidence explicitly records `validator_exit_code: null` and
`full_validation_performed: false`.

The focused native suite passes **26 tests**. The Linux foundation, analysis,
build/diff, and real ELF hardening selection passes **27 tests**, including the
three release-mode foundation tests that previously failed. Unit cases cover
native Linux, bounded Rosetta, missing/unlimited/zero/negative/invalid cgroup
limits, unreadable CPU information, preserved ASan RSS limits, and macOS behavior.
The new logs are in `reports/linux/rosetta-compatibility/`.

## Environment and source

Docker Desktop is running on the macOS ARM64 host. Containers report Linux
x86_64 and execute through Rosetta. The runtime has Python 3.12.3 and Ubuntu
Clang 18.1.3. A fresh image build failed while obtaining Docker Hub's anonymous
token (TLS handshake timeout); its output is retained in
`reports/linux/defensive/docker-build.log`.

The checks used the cached amd64 image
`sha256:6c9faf91ca727111156c5f102b95d27d351cfbee3b9ef32befaf9404b6c97690`.
The cached runtime contains older source, so the current project was
mounted read-only at `/project` and used for imports, configs, sources, and tests.
Only the evidence directory was mounted writable. The containers had no network,
2 GiB memory, two CPUs, a 128-process limit, all capabilities dropped, and
`no-new-privileges`; they ran as the host UID/GID. Image metadata and source
SHA-256 manifests are retained alongside the results.

## Initial results before the compatibility fix

Each comparison built base/patched release and sanitizer binaries from exact Git
archive snapshots: **12 successful ELF64 / EM_X86_64 builds** in total. No base
binary was executed. The resolved correct-variant commits match
`docs/target-revisions.json`.

| Comparison | Release hardening | Patched sanitizer functional checks | Patched release checks |
| --- | --- | ---: | --- |
| `cjson_correct` | Base and patched: full RELRO, NX, PIE, canary and Fortify symbols | 18/18 passed | 18 runtime failures |
| `tlv_correct` | Base and patched: full RELRO, NX, PIE, canary and Fortify symbols | 22/22 passed | 22 runtime failures |
| `tlv_hardening_warn` | Patched: partial RELRO and no canary; both reductions detected | 22/22 passed | 22 runtime failures |

Only `valid`, `boundary`, and `invalid` oracle cases ran, on patched binaries.
Canary/Fortify symbols do not establish protection of every function, and PIE
does not establish runtime ASLR. The JSON retains those limitations.

Release executions failed before producing target output, reporting:

```text
rosetta error: mmap_anonymous_rw mmap failed, size=1000
```

The independent `runtime-probe.json` confirms that even `/bin/true` stops with
SIGTRAP under the runner's release `RLIMIT_AS=256 MiB`, but exits 0 using its
sanitizer execution mode, which does not impose that address-space limit. This
isolates a Rosetta/runtime incompatibility with the release limit. The configured
limits and the validator's PASS requirements were preserved.

The runner now recognizes this diagnostic as `resource-or-runtime-failure`;
`resource_limited` is true and `crashed` is false. Original results are retained
in `defensive-evidence.json`; results after the fix are in
`after-fix/defensive-evidence.json`. Neither assigns a validator exit code.

## Verification of the diagnostic fix

- The new regression test failed before the fix (`regression-before.log`).
- Native foundation, analysis, and build/diff tests: **23 passed**
  (`native-focused-tests.log`).
- Focused Linux diagnostic, analysis, build/diff, and real ELF hardening tests:
  **17 passed** (`linux-focused-tests.log`).
- The initial broader Linux selection ran 23 tests: 20 passed and three
  foundation tests failed (`unit-tests.log`). The failing tests were
  `test_excessive_output_is_a_resource_failure`,
  `test_runner_handles_empty_stdin_and_literal_paths`, and
  `test_runner_preserves_signal_and_distinguishes_timeout`; their release-mode
  subprocesses hit the same Rosetta mapping failure. The focused passing run
  does not replace that result.

## Retained collector and remaining work

`reports/linux/defensive/collect.py` records exact commits, binary hashes,
commands, build logs, ELF evidence, oracle expectations, and execution outputs.
It asserts ELF architecture, required hardening, expected degradation warnings,
and patched functional outcomes. It exits nonzero when the latter fail.

The collector can be rerun with the current project mounted read-only and a
fresh evidence directory:

```sh
mkdir -p reports/linux/defensive-repeat
docker run --rm --pull never --platform linux/amd64 --network none \
  --memory 2g --cpus 2 --pids-limit 128 --cap-drop ALL \
  --security-opt no-new-privileges --user "$(id -u):$(id -g)" \
  --env PYTHONPATH=/project --env PYTHONDONTWRITEBYTECODE=1 --workdir /project \
  -v "$PWD:/project:ro" \
  -v "$PWD/reports/linux/defensive-repeat:/evidence:rw" \
  --entrypoint python \
  sha256:6c9faf91ca727111156c5f102b95d27d351cfbee3b9ef32befaf9404b6c97690 \
  /project/reports/linux/defensive/collect.py /evidence
```

## Complete validator verification in Linux containers

The updated `patch-validator:latest` Docker image was built for `linux/amd64`
and verified across all seven target scenarios under strict sandboxed limits
(`--network none --memory 2g --cpus 2 --pids-limit 128 --cap-drop ALL --security-opt no-new-privileges`).
The saved reports match the expected scenario verdicts and pass
`ci/check_reports.py` contract checks:

| Scenario | Config | Container exit | Findings & Evidence |
| --- | --- | :---: | --- |
| `cjson_correct` | `configs/cjson_correct.yaml` | **0** | All 20 tests Fixed; Full RELRO/NX/PIE/Canary/Fortify verified; 3-run replays pass; regression reload reaches 22 Fixed |
| `cjson_incomplete` | `configs/cjson_incomplete.yaml` | **10** | `bypass_poc.json` detected as IncompleteFix |
| `cjson_regression` | `configs/cjson_regression.yaml` | **20** | `boundary_empty_object` detected as FunctionalRegression |
| `tlv_correct` | `configs/tlv_correct.yaml` | **0** | All 24 tests Fixed; Full RELRO/NX/PIE/Canary verified; 3-run replays pass; regression reload reaches 26 Fixed |
| `tlv_incomplete` | `configs/tlv_incomplete.yaml` | **10** | `bypass_poc.bin` detected as IncompleteFix |
| `tlv_regression` | `configs/tlv_regression.yaml` | **20** | `boundary_empty_label` & `boundary_max_label_16` detected as FunctionalRegression |
| `tlv_hardening_warn` | `configs/tlv_hardening_warn.yaml` | **0** | Canary & RELRO reductions detected and warned (`--expect-hardening-warning`) |

Replays inside the container confirm baseline crashes on `base_sanitized` and
clean oracle exits on `patched_sanitized --minimized`. Second-run executions
confirm that generated regression tests reload automatically.

All seven scenario evidence directories are stored in `reports/container_verified/`.
Their report contracts, bundled binary hashes, and recorded three-run replay
counts were rechecked during the repository assessment without re-executing
the target errors. The tracked `.github/workflows/validate.yml` defines all
seven scenarios and replay/reload checks for both correct targets.

[Hosted run 43708073445](https://github.com/moalimir/Security-Prj-1/actions/runs/43708073445)
passed at commit `82e90a2`. It predates later implementation changes, so a new
run against the final submitted revision is required. Instructor approval
remains pending.

`reports/` remains Git-ignored by project convention; retain the evidence
directory separately with the submission. A source checkout alone does not
include these measured files or the collector.
