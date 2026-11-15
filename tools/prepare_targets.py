"""Prepare pinned, offline C target repositories without overwriting local work."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "examples/targets"
TARGETS = ("cjson", "tlv_parser")
SKELETON = {"base", "correct_patch", "incomplete_patch", "regression_patch"}


def check_destination(path):
    if path.is_symlink():
        raise ValueError(f"Refusing to overwrite symlink: {path}")
    if not path.exists():
        return
    if not path.is_dir() or any(
        child.is_symlink() or not child.is_dir() or child.name not in SKELETON or any(child.iterdir())
        for child in path.iterdir()
    ):
        raise ValueError(f"Refusing to overwrite nonempty target: {path}")


def prepare_targets(destination):
    destination = Path(destination).resolve()
    for target in TARGETS:
        check_destination(destination / target)
    manifest = destination / "revisions.json"
    if manifest.exists() or manifest.is_symlink():
        raise ValueError(f"Refusing to overwrite revision manifest: {manifest}")
    provenance = json.loads((TEMPLATES / "cjson/provenance.json").read_text())
    for name, expected in provenance["sha256"].items():
        actual = hashlib.sha256((TEMPLATES / "cjson/base" / name).read_bytes()).hexdigest()
        if actual != expected:
            raise ValueError(f"Vendored cJSON source checksum mismatch: {name}")
    destination.mkdir(parents=True, exist_ok=True)
    revisions = {}
    # Fixed identity and timestamps make source revision IDs independent of machine/path.
    env = {**os.environ, "GIT_AUTHOR_DATE": "2026-11-15T00:00:00+00:00",
           "GIT_COMMITTER_DATE": "2026-11-15T00:00:00+00:00",
           "GIT_AUTHOR_NAME": "Target Study", "GIT_COMMITTER_NAME": "Target Study",
           "GIT_AUTHOR_EMAIL": "targets@example.invalid", "GIT_COMMITTER_EMAIL": "targets@example.invalid",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
    with tempfile.TemporaryDirectory(prefix=".prepare-", dir=destination) as temporary:
        for target in TARGETS:
            template = TEMPLATES / target
            repo = Path(temporary) / target
            shutil.copytree(template / "base", repo)

            def git(*args):
                return subprocess.run(
                    ["git", "-c", "user.name=Target Study", "-c", "user.email=targets@example.invalid",
                     "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", *args],
                    cwd=repo, env=env, check=True, capture_output=True, text=True,
                ).stdout.strip()

            git("init", "-q", "--initial-branch=study", "--object-format=sha1", "--template=")
            git("add", "--all")
            git("commit", "-qm", f"{target}: vulnerable study baseline")
            git("tag", "base")
            variants = ["base", "correct", "incomplete", "regression"]
            if target == "tlv_parser":
                variants.append("hardening_weak")
            for variant in variants[1:]:
                git("checkout", "-q", "--detach", "base")
                git("apply", str(template / "patches" / f"{variant}.patch"))
                git("add", "--all")
                git("commit", "-qm", f"{target}: {variant} study revision")
                git("tag", variant)
            revisions[target] = {variant: git("rev-parse", variant) for variant in variants}
            git("checkout", "-q", "--detach", "correct")
        # Finish both repositories before replacing the known empty skeletons.
        for target in TARGETS:
            final = destination / target
            check_destination(final)
            if final.exists():
                for child in final.iterdir():
                    child.rmdir()
                final.rmdir()
            shutil.move(str(Path(temporary) / target), final)
    manifest.write_text(json.dumps(revisions, indent=2) + "\n")
    return revisions


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "targets")
    args = parser.parse_args()
    try:
        revisions = prepare_targets(args.output_dir)
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        detail = exc.stderr if isinstance(exc, subprocess.CalledProcessError) else str(exc)
        parser.exit(30, f"Cannot prepare targets: {detail}\n")
    for target, refs in revisions.items():
        print(f"{target}: " + ", ".join(f"{name}={commit}" for name, commit in refs.items()))


if __name__ == "__main__":
    main()
