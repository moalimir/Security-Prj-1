#!/usr/bin/env python3
"""Package the project submission according to the university requirements.

The Persian assignment requires:
1. Tool source code
2. Target configurations and revisions
3. Test suites (valid, boundary, invalid, exploit)
4. Reproducer bundles with replays and minimized test cases
5. Generated reports (JSON, Markdown, HTML)
6. CI/CD pipeline file (.github/workflows/validate.yml)
7. Standalone execution documentation and offline reconstruction
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "dist"

if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))

from ci.check_reports import check_report
from tools.verify_all_scenarios import SCENARIOS


def package():
    for variant, expected, _, warning in SCENARIOS:
        check_report(ROOT / "reports/container_verified" / variant, expected, hardening_warning=warning)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    archive_name = "security_patch_validator_submission.zip"
    archive_path = OUTPUT_DIR / archive_name
    
    print(f"--> Packaging submission to {archive_path}...")
    
    # 1. Collect all git-tracked files
    res = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True)
    tracked_files = [os.fsdecode(path) for path in res.stdout.split(b"\0") if path]
    
    # 2. Add extra required deliverable files (evidence & regressions)
    extra_patterns = [
        "reports/container_verified/**/*",
        "tests/cjson/regression/**/*",
        "tests/tlv_parser/regression/**/*",
    ]
    
    all_files = set(tracked_files)
    for pattern in extra_patterns:
        for p in ROOT.glob(pattern):
            if p.is_file():
                rel = str(p.relative_to(ROOT))
                all_files.add(rel)
                
    with tempfile.TemporaryDirectory(dir=OUTPUT_DIR) as temporary:
        staged = Path(temporary) / archive_name
        with zipfile.ZipFile(staged, "w", zipfile.ZIP_DEFLATED) as zipf:
            for rel in sorted(all_files):
                file_path = ROOT / rel
                zipf.write(file_path, arcname=rel)
        staged.replace(archive_path)
                
    print(f"Packaged {len(all_files)} files into {archive_path} ({archive_path.stat().st_size // 1024} KB).")
    return archive_path


if __name__ == "__main__":
    package()
