#!/usr/bin/env python3
"""Evaluate an unseen patch in an isolated clone and retain its source evidence."""
from __future__ import annotations

from dataclasses import asdict
import json
import logging
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import yaml

from src.core.config_manager import ConfigManager
from src.orchestrator import ArgumentParser
from src.utils.exceptions import PatchValidatorError


def _git(repository: Path, *args: str, **kwargs) -> str:
    return subprocess.run(
        ["git", "-c", f"safe.directory={repository}", *args], cwd=repository,
        check=True, capture_output=True, text=True, **kwargs,
    ).stdout


def _resolve(repository: Path, ref: str) -> str:
    return _git(repository, "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}").strip()


def _run_validator(config: Path, output: Path, *, skip_minimize=False, skip_hardening=False) -> int:
    from src.orchestrator import PatchValidator

    return PatchValidator(str(config), str(output), skip_minimize=skip_minimize,
                          skip_hardening=skip_hardening).run()


def evaluate(base_config, output_dir, *, patch_file=None, patched_commit=None,
             skip_minimize=False, skip_hardening=False) -> int:
    try:
        if (patch_file is None) == (patched_commit is None):
            raise ValueError("Supply exactly one patch file or patched commit.")
        base_config = Path(base_config).resolve()
        patch_file = Path(patch_file).resolve() if patch_file is not None else None
        config = ConfigManager.load_config(str(base_config))
        source = Path(config.repository_path)
        base = _resolve(source, config.base_commit)
        patched = _resolve(source, patched_commit) if patched_commit is not None else None
        submitted = patch_file.read_bytes() if patch_file is not None else None
        output = Path(output_dir).resolve()
        evidence = output / "unseen"
        # Each evaluation owns its evidence; never replace an earlier submission.
        evidence.mkdir(parents=True, exist_ok=False)
        with tempfile.TemporaryDirectory(prefix="patch-validator-unseen-") as temporary:
            repository = Path(temporary) / "repository"
            subprocess.run(["git", "clone", "--quiet", "--no-hardlinks", "--no-checkout", "--",
                            str(source), str(repository)], check=True, capture_output=True, text=True)
            _git(repository, "checkout", "--quiet", "--detach", base)
            if submitted is not None:
                submitted_path = evidence / "submitted.patch"
                submitted_path.write_bytes(submitted)
                _git(repository, "apply", "--check", "--", str(submitted_path))
                _git(repository, "apply", "--", str(submitted_path))
                _git(repository, "add", "--all")
                env = dict(os.environ, GIT_AUTHOR_NAME="Unseen patch evaluator",
                           GIT_AUTHOR_EMAIL="validator@example.invalid",
                           GIT_COMMITTER_NAME="Unseen patch evaluator",
                           GIT_COMMITTER_EMAIL="validator@example.invalid",
                           GIT_AUTHOR_DATE="2000-01-01T00:00:00+00:00",
                           GIT_COMMITTER_DATE="2000-01-01T00:00:00+00:00")
                _git(repository, "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false",
                     "commit", "--quiet", "-m", "Evaluate unseen patch", env=env)
                patched = _resolve(repository, "HEAD")
            else:
                _git(repository, "checkout", "--quiet", "--detach", patched)
            patch_text = _git(repository, "diff", "--binary", "--no-ext-diff", "--no-textconv", base, patched)
            (evidence / "evaluated.patch").write_text(patch_text, encoding="utf-8")
            _git(repository, "update-ref", "refs/heads/unseen-base", base)
            _git(repository, "update-ref", "refs/heads/unseen-patched", patched)
            _git(repository, "symbolic-ref", "HEAD", "refs/heads/unseen-patched")
            _git(repository, "bundle", "create", str(evidence / "source.bundle"),
                 "refs/heads/unseen-base", "refs/heads/unseen-patched", "HEAD")
            derived = asdict(config)
            derived.update(repository_path=str(repository), base_commit=base, patched_commit=patched)
            config_path = evidence / "config.evaluated.yaml"
            config_path.write_text(yaml.safe_dump(derived, sort_keys=False), encoding="utf-8")
            restored = evidence / "repository"
            replay_config = evidence / "config.replay.yaml"
            replay_config.write_text(yaml.safe_dump(dict(derived, repository_path=str(restored)),
                                                    sort_keys=False), encoding="utf-8")
            flags = []
            if skip_minimize:
                flags.append("--skip-minimize")
            if skip_hardening:
                flags.append("--skip-hardening")
            metadata = {"base_config": str(base_config), "original_repository": str(source),
                        "base_commit": base, "patched_commit": patched,
                        "patch_file": str(patch_file) if patch_file is not None else None,
                        "patched_ref": patched_commit,
                        "restore_command": ["git", "clone", str(evidence / "source.bundle"), str(restored)],
                        "rerun_command": [sys.executable, "-m", "src", "--config", str(replay_config),
                                          "--output-dir", str(output / "rerun"), *flags],
                        "validator_exit_code": None}
            metadata_path = evidence / "metadata.json"
            metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
            code = _run_validator(config_path, output, skip_minimize=skip_minimize,
                                  skip_hardening=skip_hardening)
            metadata["validator_exit_code"] = code
            metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
            return code if code in (0, 10, 20, 30, 40) else 30
    except (OSError, ValueError, PatchValidatorError, subprocess.CalledProcessError) as exc:
        detail = exc.stderr.strip() if isinstance(exc, subprocess.CalledProcessError) and exc.stderr else str(exc)
        print(f"Cannot evaluate unseen patch: {detail}", file=sys.stderr)
        return 30


def main(argv=None) -> int:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--base-config", type=Path, required=True)
    candidate = parser.add_mutually_exclusive_group(required=True)
    candidate.add_argument("--patch-file", type=Path)
    candidate.add_argument("--patched-commit")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    return evaluate(args.base_config, args.output_dir, patch_file=args.patch_file,
                    patched_commit=args.patched_commit)


if __name__ == "__main__":
    raise SystemExit(main())
