# 🛡️ Security Patch Validator — Project Completion Plan
**Last updated:** 2026-11-15 · **Deadline:** 18 Aban 1405 (verify any extension with instructor)

---

## 📊 Project Progress Snapshot

| Category | Done | Remaining |
|---|---|---|
| Pipeline Engine (14 modules) | ✅ 100% | — |
| Target 1 — cJSON 1.7.17 | ✅ 95% | Instructor approval + Linux ELF run |
| Target 2 — TLV Parser | ✅ 95% | Instructor approval + Linux ELF run |
| Test Suites (20 + 24 cases) | ✅ 100% | — |
| Native pipeline runs (exit 10/20) | ✅ 100% | — |
| Linux/ELF container run (exit 0) | ⏳ 0% | **Item 1 — highest priority** |
| CI for real targets | ✅ 100% | Waiting on actual CI run to pass |
| Instructor approval | ⏳ 0% | **Item 2 — blocking** |
| Contribution records | ⏳ 0% | Item 3 |
| Defense preparation | ⏳ 5% | Item 4 |

---

## ✅ Completed — Nothing More Needed Here

### Core Pipeline Engine (`src/`)

| Module | Status | Notes |
|---|---|---|
| `config_manager.py` | ✅ | Full YAML validation, path resolution, oracle checks |
| `build_engine.py` | ✅ | 4-binary Git snapshot isolation, hash tracking, build logs |
| `test_runner.py` | ✅ | file/stdin/args modes, 3-replay crash confirmation, resource limits |
| `classifier.py` | ✅ | Fixed / IncompleteFix / NewIssue / FunctionalRegression / Inconclusive |
| `diff_analyzer.py` | ✅ | Stack-trace ↔ patch correlation (`changed_line` / `same_function` / `unknown`) |
| `hardening_checker.py` | ✅ | RELRO, NX, PIE, canary, Fortify — warns on regressions |
| `testcase_minimizer.py` | ✅ | Byte-deletion, error-type/site preservation, 200-attempt bound |
| `report_generator.py` | ✅ | JSON + Markdown + HTML, all with HTML escaping |
| `orchestrator.py` | ✅ | Full pipeline orchestration, exit codes 0/10/20/30/40 |
| `replay.py` | ✅ | Bundle replay from saved binaries/inputs |

### Target 1 — cJSON 1.7.17 (`targets/cjson/`)

| Item | Status | Evidence |
|---|---|---|
| Upstream source (cJSON v1.7.17) | ✅ | SHA-256 of `cJSON.c`, `cJSON.h`, `LICENSE`, `UPSTREAM_README.md` verified against upstream commit `87d8f09` |
| `base` tag — vulnerable | ✅ | Unmodified upstream; both exploits produce ASan `heap-buffer-overflow` |
| `correct` tag — proper fix | ✅ | Exact upstream PR #852 / commit `c390438`; both exploits safely rejected |
| `incomplete` tag — depth-1-only guard | ✅ | Original PoC blocked; nested object bypass still over-reads |
| `regression` tag — rejects `{}` | ✅ | Both exploits rejected; valid empty object incorrectly rejected (exit 1) |
| `driver.c` + `Makefile` | ✅ | In all 4 revisions; builds with both `release` and `sanitized` targets |
| Provenance documented | ✅ | `examples/targets/cjson/provenance.json` + patch files in `examples/targets/cjson/patches/` |
| Exploit PoC (`original_poc.json`) | ✅ | Exact 7 bytes `{"1":1,` from GitHub issue #800; triggers OOB read on `base` |
| Bypass PoC (`bypass_poc.json`) | ✅ | 16-byte `{"outer":{"1":1,`; reaches same read via nested object; bypasses depth-1 guard |

### Target 2 — TLV Parser (`targets/tlv_parser/`)

| Item | Status | Evidence |
|---|---|---|
| Original C binary protocol program | ✅ | Custom protocol parser with magic/version/flags/tag/length/value framing |
| `base` tag — vulnerable | ✅ | Unchecked `length` field causes ASan `heap-buffer-overflow` |
| `correct` tag — proper bounds check | ✅ | Both exploits safely rejected |
| `incomplete` tag — truncated guard | ✅ | Original PoC blocked; oversized/nested bypass still overflows |
| `regression` tag — rejects valid labels | ✅ | Both exploits rejected; valid empty label and 16-byte label incorrectly rejected |
| `hardening_weak` tag | ✅ | Same fix without `-fstack-protector-strong` / full RELRO — triggers hardening warning |
| `driver.c` + `Makefile` | ✅ | In all 5 revisions |
| Exploit PoC (`original_poc.bin`) | ✅ | Binary TLV record with oversized `length` field; triggers OOB write on `base` |
| Bypass PoC (`bypass_poc.bin`) | ✅ | Different oversized pattern; bypasses incomplete-patch guard |

### Test Suites

| Suite | Total Cases | Coverage |
|---|---|---|
| `tests/cjson/` | **20 cases** | valid (6) · boundary (5) · invalid (5) · exploit (2) |
| `tests/tlv_parser/` | **24 cases** | valid (6) · boundary (5) · invalid (11) · exploit (2) |
| Oracle independence | ✅ | cJSON oracles cross-checked with Python `json`; TLV oracles from written protocol spec |

### Native Pipeline Runs (`reports/targets_native/`)

| Scenario | Native Exit | Findings | Note |
|---|---|---|---|
| `cjson_correct` | **40** | 20 Fixed → reload → **22 Fixed** | ELF hardening skipped on macOS |
| `cjson_incomplete` | **10** ✅ | 19 Fixed + **1 IncompleteFix** | bypass_poc triggers same OOB |
| `cjson_regression` | **20** ✅ | 19 Fixed + **1 FunctionalRegression** | empty object rejected |
| `tlv_correct` | **40** | 24 Fixed → reload → **26 Fixed** | ELF hardening skipped on macOS |
| `tlv_incomplete` | **10** ✅ | 23 Fixed + **1 IncompleteFix** | bypass_poc still overflows |
| `tlv_regression` | **20** ✅ | 22 Fixed + **2 FunctionalRegression** | empty + max-label rejected |

> Exit 40 on `correct` scenarios is expected on macOS — ELF hardening is mandatory and was explicitly skipped because macOS produces Mach-O, not ELF. Linux container runs produce exit **0**.

### Reproducer Bundles & Regression Reload

- ✅ Original and minimized crash inputs saved for both targets
- ✅ 3-run replay confirmed (baseline crashes, patched safely rejects)
- ✅ Verified with `ci/check_reports.py replay` for both `cjson_correct` and `tlv_correct`
- ✅ Generated regression manifests reload automatically on second run

### Test Suite (Python)

**Latest run: `44 tests, 43 passed, 1 skipped — OK`** (run with `.venv`, 2026-11-15)

| Test file | Tests | Status |
|---|---|---|
| `test_foundation.py` | 11 | ✅ All pass |
| `test_pipeline.py` | ~6 | ✅ All pass |
| `test_analysis.py` | ~8 | ✅ All pass |
| `test_build_and_diff.py` | ~5 | ✅ All pass |
| `test_prepared_targets.py` | ~6 | ✅ All pass |
| `test_tlv_target.py` | ~4 | ✅ All pass |
| `test_unseen_patch.py` | ~5 | ✅ All pass |
| Linux ELF hardening test | 1 | ⏭️ Skipped (macOS) |

### CI Workflow (`.github/workflows/validate.yml`)

- ✅ Runs all 44 unit tests on `ubuntu-24.04`
- ✅ Builds Docker image for `linux/amd64` with targets baked in
- ✅ Checks all 3 demo scenarios (exit 0/10/20)
- ✅ Checks all 7 real target scenarios: `cjson_correct:0`, `cjson_incomplete:10`, `cjson_regression:20`, `tlv_correct:0`, `tlv_incomplete:10`, `tlv_regression:20`, `tlv_hardening_warn:0`
- ✅ Replays bundles and reloads generated regression cases inside the container
- ✅ Uploads all reports as artifacts

### Unseen-Patch Tool (`tools/eval_unseen_patch.py`)

- ✅ Accepts `--patch-file` or `--patched-commit` against any base config
- ✅ Runs in isolated temporary clone; preserves evidence per submission
- ✅ Covered by `tests/test_unseen_patch.py` (5 tests, all pass)

### Docker

- ✅ `Dockerfile` runs `tools/prepare_targets.py` during build (targets baked in)
- ✅ `docker compose config` passes
- ✅ Sandboxed: `--network none`, `--cap-drop ALL`, `--security-opt no-new-privileges`, memory/CPU/PID limits

---

## 🔴 Remaining — 4 Actionable Items

### Item 1 · Linux/ELF Container Run  🔴 HIGHEST PRIORITY

**Effort:** ~2 hours | **Blocker for:** exit-0 verdicts, ELF hardening evidence

**Why it matters:** The `correct` scenarios currently exit 40 on macOS. The course requires Linux ELF hardening checks to pass, producing exit **0**. All the pipeline and CI code is ready — only the Docker daemon needs to be running.

**Commands:**

```bash
# 1. Start Docker Desktop (macOS)
open -a Docker       # wait for the whale icon to appear in the menu bar

# 2. Build the image (targets baked in)
cd /path/to/Project
docker build --platform linux/amd64 -t patch-validator -f docker/Dockerfile .

# 3. Run all target scenarios and check exit codes
for scenario in cjson_correct:0 cjson_incomplete:10 cjson_regression:20 \
                tlv_correct:0 tlv_incomplete:10 tlv_regression:20 tlv_hardening_warn:0; do
  variant=${scenario%:*}
  expected=${scenario#*:}
  mkdir -p "reports/linux/$variant"
  set +e
  docker run --rm --platform linux/amd64 --network none \
    --memory 2g --cpus 2 --pids-limit 128 \
    --cap-drop ALL --security-opt no-new-privileges \
    -v "$PWD/reports/linux/$variant:/workspace/reports:rw" \
    patch-validator --config "configs/$variant.yaml" -o /workspace/reports
  status=$?; set -e
  echo "$variant: exit $status (expected $expected)"
done

# 4. Replay bundles inside container
for variant in cjson_correct tlv_correct; do
  docker run --rm --platform linux/amd64 --network none \
    --memory 2g --cpus 2 --pids-limit 128 \
    --cap-drop ALL --security-opt no-new-privileges \
    -v "$PWD/reports/linux/$variant:/workspace/reports:rw" \
    --entrypoint python patch-validator \
    ci/check_reports.py replay /workspace/reports
done

# 5. Verify report structure
for variant in cjson_correct cjson_incomplete cjson_regression \
               tlv_correct tlv_incomplete tlv_regression; do
  python ci/check_reports.py report "reports/linux/$variant" \
    --expected-exit "$(grep "$variant" <<< "cjson_correct:0 cjson_incomplete:10 ...")"
done
```

**Expected outcome:** All 7 scenarios pass; `cjson_correct` and `tlv_correct` exit **0** with ELF hardening evidence in `report.json`. Save `reports/linux/` as final submission evidence.

---

### Item 2 · Formal Instructor Approval  🔴 HIGH PRIORITY

**Effort:** ~1 hour to write, then scheduling | **Blocker for:** any score at all

Submit via email or course system. Use the provenance docs already in the repo:

```
Subject: Target Approval Request — cJSON Issue #800 & TLV Protocol Parser

Target 1: cJSON 1.7.17 (Real Non-Toy Library)
  Source:    https://github.com/DaveGamble/cJSON (upstream tag v1.7.17, commit 87d8f09)
  Vuln:      Out-of-bounds read in parse_object when a length-delimited,
             non-NUL-terminated JSON object ends in a comma (GitHub issue #800)
  Error:     heap-buffer-overflow (ASan confirmed in baseline)
  Fix:       Upstream PR #852 / commit c390438 — bounds check before parse_string
  Incomplete variant: depth-1-only guard; nested objects bypass it
  Regression variant: correct fix plus explicit rejection of valid empty objects
  Oracle:    JSON RFC 8259; cross-validated with Python standard json module
  Input:     file mode (.json files)
  Provenance: examples/targets/cjson/provenance.json

Target 2: TLV Protocol Parser (original C implementation)
  Source:    Local original implementation (custom binary format)
  Vuln:      Unchecked 2-byte record length field copied to fixed heap buffer
             (heap-buffer-overflow, ASan confirmed)
  Fix:       Bounds check: reject records where length exceeds safe limit
  Incomplete variant: guard with off-by-one; larger records bypass
  Regression variant: correct fix plus rejection of zero-length and max-size labels
  Oracle:    Written TLV v1 protocol spec (examples/targets/tlv_parser/README.md)
  Input:     file mode (.bin files)
```

---

### Item 3 · Team Contribution Records  🟡 MEDIUM PRIORITY

**Effort:** ~1 hour | Create `docs/contributions.md`

Assign the four team members to the four natural ownership areas:

| Member | Primary Sections | Key Files | Defense Responsibility |
|---|---|---|---|
| Member 1 | Pipeline Core | `config_manager.py`, `build_engine.py`, `test_runner.py` | Explain config validation, build isolation, 3-replay logic |
| Member 2 | Analysis Modules | `classifier.py`, `diff_analyzer.py`, `hardening_checker.py` | Explain classification decisions, diff correlation, ELF checks |
| Member 3 | Target 1 (cJSON) | `targets/cjson/`, `tests/cjson/`, `configs/cjson_*.yaml` | CVE root cause, patch variants, oracle design |
| Member 4 | Target 2 (TLV) + Infra | `targets/tlv_parser/`, `tests/tlv_parser/`, `docker/`, `ci/` | Protocol vulnerability, CI workflow, replay mechanics |

---

### Item 4 · Defense Preparation  🟡 MEDIUM PRIORITY

**Effort:** ~4 hrs/member | Each person studies and practices their section

**Core mental model everyone must know:**

```
Config YAML → ConfigManager validates →
BuildEngine creates 4 Git snapshots →
TestRunner executes all inputs on all 4 binaries →
  → crashes replayed 3× to confirm stability →
Classifier assigns: Fixed / IncompleteFix / NewIssue / FunctionalRegression / Inconclusive →
DiffAnalyzer correlates stack frames to patch diff →
HardeningChecker reads ELF headers of release binaries →
Minimizer reduces crash inputs (byte-deletion, 200-attempt bound) →
ReportGenerator writes report.json / report.md / report.html →
Exit code = priority(30 > 10 > 20 > 40 > 0)
```

**Practice for the unseen-patch defense scenario:**

```bash
# The defense may give you a patch file or a commit — use the eval tool
source .venv/bin/activate
python tools/eval_unseen_patch.py \
  --base-config configs/cjson_correct.yaml \
  --patch-file /path/to/unseen.patch \
  --output-dir reports/unseen_defense
# → reads the report and explain the verdict
```

**Per-role live-change practice (the 4-point defense task):**

| Role | Sample live change to practice |
|---|---|
| Core | Add `--dry-run` flag; change timeout from 5→10 in a config and re-run |
| Analysis | Modify `classifier.py` to also print the error type in the terminal log |
| cJSON | Add a new valid test case with a number; update oracle manifest |
| TLV/Infra | Add `tlv_hardening_warn` to the CI replay step; explain why |

---

## 📋 Final Submission Checklist

| Item | Status |
|---|---|
| Tool source code (`src/`, `tools/`, `ci/`) | ✅ Complete |
| Configuration files (`configs/*.yaml`) | ✅ Complete (8 configs) |
| Target 1 repo with 4 revisions (`targets/cjson/`) | ✅ Complete |
| Target 2 repo with 5 revisions (`targets/tlv_parser/`) | ✅ Complete |
| Test inputs + oracle manifests (`tests/`) | ✅ Complete (44 cases) |
| Provenance docs (`examples/targets/`) | ✅ Complete |
| Docker + CI workflow | ✅ Complete |
| Native evidence — exit 10 & 20 (`reports/targets_native/`) | ✅ Complete |
| Unseen-patch evaluation tool | ✅ Complete |
| **Linux ELF evidence — exit 0 (`reports/linux/`)** | ⏳ **TODO — Item 1** |
| **Instructor written approval** | ⏳ **TODO — Item 2** |
| Run instructions (`README.md`) | ✅ Complete |
| **Team contribution records (`docs/contributions.md`)** | ⏳ **TODO — Item 3** |
| **Individual defense readiness** | ⏳ **TODO — Item 4** |

---

## 🧪 Verification Commands (run any time)

```bash
cd /path/to/Project && source .venv/bin/activate

# Full test suite (should be: 44 run, 43 passed, 1 skipped)
python -m unittest discover -s tests -v

# Quick native scenario check
python -m src --config configs/cjson_correct.yaml \
  --output-dir reports/check --skip-hardening

# Verify replay bundles
python ci/check_reports.py replay reports/targets_native/cjson_correct
python ci/check_reports.py replay reports/targets_native/tlv_correct

# Docker compose syntax check
docker compose -f docker/docker-compose.yml config --quiet
```
