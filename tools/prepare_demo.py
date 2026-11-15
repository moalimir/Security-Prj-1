"""Prepare an offline C fixture repository and three runnable configurations."""
import argparse
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def prepare_demo(destination: Path) -> None:
    destination = destination.resolve()
    compiler = shutil.which("clang") or shutil.which("gcc")
    if not compiler:
        raise RuntimeError("Install Clang or GCC before preparing the demo.")
    if destination.exists() and any(destination.iterdir()):
        raise ValueError(f"Destination is not empty; refusing to overwrite it: {destination}")
    repo = destination / "repository"
    repo.mkdir(parents=True)
    env = {**os.environ, "GIT_AUTHOR_NAME": "Scaffold fixture", "GIT_COMMITTER_NAME": "Scaffold fixture",
           "GIT_AUTHOR_EMAIL": "fixture@example.invalid", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
           "GIT_AUTHOR_DATE": "2026-01-01T00:00:00+0000", "GIT_COMMITTER_DATE": "2026-01-01T00:00:00+0000"}

    def git(*args):
        subprocess.run(["git", *args], cwd=repo, env=env, check=True, capture_output=True)

    git("init", "-q")
    source = (ROOT / "examples/demo/parser.c").read_text()
    patches = {"base": "/* vulnerable baseline */", "correct": "if (length >= 8) return 1;",
               "incomplete": "if (length == 16) return 1;",
               "regression": "if (length >= 8 || length == 3) return 1;"}
    for name, guard in patches.items():
        (repo / "parser.c").write_text(source.replace("/* PATCH */", guard))
        git("add", "parser.c")
        git("-c", "commit.gpgsign=false", "commit", "-qm", f"Fixture: {name}")
        git("tag", name)
    inputs = destination / "inputs"
    inputs.mkdir()
    fixtures = {"valid": b"abc", "valid_other": b"x", "boundary": b"1234567",
                "invalid": b"", "exploit": b"A" * 16, "bypass": b"B" * 17}
    cases = []
    for name, data in fixtures.items():
        (inputs / f"{name}.input").write_bytes(data)
        category = "exploit" if name in ("exploit", "bypass") else "valid" if name.startswith("valid") else name
        case = {"name": name, "category": category, "input_file": f"{name}.input",
                "expected_exit_code": 1 if category in ("exploit", "invalid") else 0,
                "expected_stdout": "" if category in ("exploit", "invalid") else data.decode() + "\n"}
        if category == "exploit":
            case["expected_error_type"] = "heap-buffer-overflow"
        cases.append(case)
    import json
    (inputs / "oracle_manifest.json").write_text(json.dumps({"target": "scaffold-demo", "test_cases": cases}, indent=2) + "\n")
    hardening = "-fstack-protector-strong -D_FORTIFY_SOURCE=2"
    if sys.platform.startswith("linux"):
        hardening += " -fPIE -pie -Wl,-z,relro,-z,now"
    for variant in ("correct", "incomplete", "regression"):
        config = {"project_name": "scaffold_demo", "repository_path": "repository",
                  "base_commit": "base", "patched_commit": variant,
                  "build": {"release_cmd": f"{shlex.quote(compiler)} -O2 {hardening} parser.c -o {{output_dir}}/target_bin",
                            "sanitized_cmd": f"{shlex.quote(compiler)} -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer parser.c -o {{output_dir}}/target_bin",
                            "release_binary": "target_bin", "sanitized_binary": "target_bin"},
                  "execution": {"input_mode": "file", "cmd_template": "{binary} {input_file}",
                                "timeout_sec": 5, "memory_limit_mb": 256},
                  "test_suites": {"oracle_manifest": "inputs/oracle_manifest.json"}}
        (destination / f"{variant}.yaml").write_text(yaml.safe_dump(config, sort_keys=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default=".demo")
    args = parser.parse_args()
    try:
        prepare_demo(Path(args.output_dir))
    except (ValueError, RuntimeError, OSError, subprocess.CalledProcessError) as exc:
        parser.exit(30, f"Cannot prepare demo: {exc}\n")
    print(f"Demo prepared in {Path(args.output_dir).resolve()}")


if __name__ == "__main__":
    main()
