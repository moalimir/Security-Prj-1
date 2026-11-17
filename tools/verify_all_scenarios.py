#!/usr/bin/env python3
"""Run and verify all 7 target scenarios in Docker container."""
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SCENARIOS = [
    ("cjson_correct", 0, True, False),
    ("cjson_incomplete", 10, False, False),
    ("cjson_regression", 20, False, False),
    ("tlv_correct", 0, True, False),
    ("tlv_incomplete", 10, False, False),
    ("tlv_regression", 20, False, False),
    ("tlv_hardening_warn", 0, False, True),
]

def run_cmd(cmd, check=True):
    print(f"--> Running: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    res = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
    if check and res.returncode != 0:
        print(f"ERROR (exit {res.returncode}):\nSTDOUT: {res.stdout}\nSTDERR: {res.stderr}")
        sys.exit(1)
    return res

def main():
    run_cmd(["docker", "build", "--platform", "linux/amd64", "-t", "patch-validator",
             "-f", "docker/Dockerfile", "."])
    base_reports = ROOT / "reports" / "container_verified"
    base_reports.mkdir(parents=True, exist_ok=True)
    
    results = []
    
    for variant, expected_exit, test_replay_reload, expect_hardening_warn in SCENARIOS:
        report_dir = base_reports / variant
        report_dir.mkdir(parents=True, exist_ok=True)
        print(f"\n==========================================")
        print(f"Testing Scenario: {variant} (Expected Exit: {expected_exit})")
        print(f"==========================================")
        
        # 1. Run container validator
        docker_cmd = [
            "docker", "run", "--init", "--rm", "--platform", "linux/amd64",
            "--network", "none", "--memory", "2g", "--cpus", "2",
            "--pids-limit", "128", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--user", f"{os.getuid()}:{os.getgid()}",
            "-v", f"{report_dir}:/workspace/reports:rw",
            "-v", f"{ROOT}/tests/cjson/regression:/workspace/tests/cjson/regression:rw",
            "-v", f"{ROOT}/tests/tlv_parser/regression:/workspace/tests/tlv_parser/regression:rw",
            "patch-validator",
            "--config", f"configs/{variant}.yaml",
            "-o", "/workspace/reports"
        ]
        res = run_cmd(docker_cmd, check=False)
        print(f"Docker run exit code: {res.returncode}")
        if res.returncode != expected_exit:
            print(f"FAIL: Expected {expected_exit}, got {res.returncode}")
            print(f"STDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}")
            sys.exit(1)
        
        # 2. Check report with check_reports.py
        check_cmd = [sys.executable, "ci/check_reports.py", "report", str(report_dir), "--expected-exit", str(expected_exit)]
        if expect_hardening_warn:
            check_cmd.append("--expect-hardening-warning")
        res_check = run_cmd(check_cmd)
        if res_check.returncode != 0:
            print(f"FAIL report check for {variant}")
            sys.exit(1)
        print(res_check.stdout.strip())
        
        # 3. Replay and reload generated cases for both correct targets.
        if test_replay_reload:
            print(f"Testing Replay for {variant} inside container...")
            replay_cmd = [
                "docker", "run", "--init", "--rm", "--platform", "linux/amd64",
                "--network", "none", "--memory", "2g", "--cpus", "2",
                "--pids-limit", "128", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges",
                "--user", f"{os.getuid()}:{os.getgid()}",
                "-v", f"{report_dir}:/workspace/reports:rw",
                "-v", f"{ROOT}/tests/cjson/regression:/workspace/tests/cjson/regression:rw",
                "-v", f"{ROOT}/tests/tlv_parser/regression:/workspace/tests/tlv_parser/regression:rw",
                "--entrypoint", "python",
                "patch-validator",
                "ci/check_reports.py", "replay", "/workspace/reports"
            ]
            res_rep = run_cmd(replay_cmd)
            if res_rep.returncode != 0:
                print(f"FAIL replay for {variant}")
                sys.exit(1)
            print(res_rep.stdout.strip())
            
            print(f"Testing Regression Reload for {variant}...")
            res_reload = run_cmd(docker_cmd, check=False)
            if res_reload.returncode != expected_exit:
                print(f"FAIL regression reload exit code: {res_reload.returncode}")
                sys.exit(1)
            
            check_reload_cmd = [sys.executable, "ci/check_reports.py", "report", str(report_dir),
                                "--expected-exit", str(expected_exit), "--regression-loaded"]
            res_chk_rel = run_cmd(check_reload_cmd)
            if res_chk_rel.returncode != 0:
                print(f"FAIL regression-loaded check for {variant}")
                sys.exit(1)
            print(res_chk_rel.stdout.strip())
            
        results.append((variant, expected_exit, "PASSED"))
        
    print("\n\n##########################################")
    print("ALL CONTAINER SCENARIOS VERIFIED SUCCESSFULLY!")
    print("##########################################")
    for variant, code, status in results:
        print(f"  {variant:<25} -> Exit {code} [{status}]")

if __name__ == "__main__":
    main()
