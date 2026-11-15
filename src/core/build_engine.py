"""Build independent Git snapshots; never checkout or clean the user's repository."""
from __future__ import annotations

import hashlib
import shlex
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path

from src.core.config_manager import ProjectConfig
from src.utils.exceptions import BuildError


@dataclass
class BuildResult:
    success: bool
    binary_path: Path
    binary_hash: str
    build_log: str
    build_type: str
    commit_hash: str
    command: str = ""
    source_dir: Path | None = None


class BuildEngine:
    def __init__(self, config: ProjectConfig, workspace: Path):
        self._config = config
        self._repo = Path(config.repository_path)
        self._workspace = Path(workspace).resolve()

    def build_version(self, commit: str, version_label: str) -> dict[str, BuildResult]:
        results = {}
        for mode in ("release", "sanitized"):
            output = Path(tempfile.mkdtemp(prefix=f"{version_label}_{mode}_", dir=self._workspace))
            source = output / "source"
            source.mkdir()
            try:
                # A disk-backed archive avoids keeping a whole target in memory.
                with tempfile.TemporaryFile() as archive:
                    subprocess.run(["git", "-c", f"safe.directory={self._repo}", "archive", "--format=tar", commit], cwd=self._repo,
                                   stdout=archive, stderr=subprocess.PIPE, check=True)
                    archive.seek(0)
                    with tarfile.open(fileobj=archive) as tar:
                        for member in tar.getmembers():
                            dest = source / member.name
                            if not dest.resolve().is_relative_to(source):
                                raise BuildError(f"Unsafe archive path: {member.name}")
                            if member.issym() or member.islnk():
                                target = dest.parent / member.linkname if member.issym() else source / member.linkname
                                if not target.resolve().is_relative_to(source):
                                    raise BuildError(f"Archive link escapes source tree: {member.name}")
                            if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                                raise BuildError(f"Unsupported archive entry: {member.name}")
                        tar.extractall(source, filter="data")
            except (OSError, tarfile.TarError, subprocess.CalledProcessError) as exc:
                raise BuildError(f"Cannot export commit {commit}: {exc}") from exc
            command = getattr(self._config.build, f"{mode}_cmd").format(output_dir=shlex.quote(str(output)))
            binary_rel = getattr(self._config.build, f"{mode}_binary")
            result = self._run_build(command, output, source, binary_rel, mode, commit)
            results[mode] = result
        return results

    def _run_build(self, command, output, source, binary_rel, mode, commit):
        success = False
        try:
            proc = subprocess.run(command, shell=True, cwd=source, capture_output=True,
                                  text=True, errors="replace", timeout=600)
            log = proc.stdout + proc.stderr
            success = proc.returncode == 0
        except subprocess.TimeoutExpired as exc:
            decode = lambda value: value.decode(errors="replace") if isinstance(value, bytes) else value or ""
            log = decode(exc.stdout) + decode(exc.stderr) + "\nBuild timed out after 600 seconds."
        except OSError as exc:
            log = str(exc)
        binary = output / binary_rel
        if not binary.is_file():
            built = source / binary_rel
            if success and built.is_file():
                binary.parent.mkdir(parents=True, exist_ok=True)
                binary.write_bytes(built.read_bytes())
                binary.chmod(built.stat().st_mode)
        if success and (not binary.is_file() or not binary.stat().st_mode & 0o111):
            success = False
            log += f"\nExpected executable is missing: {binary}"
        digest = hashlib.sha256(binary.read_bytes()).hexdigest() if success else ""
        (output / "build.log").write_text(log, encoding="utf-8")
        return BuildResult(success, binary, digest, log, mode, commit, command, source)
