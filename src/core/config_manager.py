"""Validated project settings and non-destructive workspace preparation."""
from __future__ import annotations

import math
import shlex
import string
import subprocess
from dataclasses import dataclass, replace
from pathlib import Path

import yaml

from src.utils.exceptions import ConfigError


def validate_template(template: str, allowed: set[str], required: set[str]) -> None:
    if not isinstance(template, str) or not template.strip():
        raise ConfigError("Command templates must be nonempty strings.")
    try:
        fields = set()
        for _, name, spec, conversion in string.Formatter().parse(template):
            if name is not None:
                if name not in allowed or spec or conversion:
                    raise ValueError(f"unsupported placeholder {{{name}}}")
                fields.add(name)
        if not required <= fields:
            raise ValueError(f"missing placeholders: {sorted(required - fields)}")
        shlex.split(template)
    except ValueError as exc:
        raise ConfigError(f"Invalid command template: {exc}") from exc


@dataclass(frozen=True)
class BuildConfig:
    release_cmd: str
    sanitized_cmd: str
    release_binary: str
    sanitized_binary: str

    def __post_init__(self):
        for cmd in (self.release_cmd, self.sanitized_cmd):
            validate_template(cmd, {"output_dir"}, set())
        for binary in (self.release_binary, self.sanitized_binary):
            if not isinstance(binary, str) or not binary or Path(binary).is_absolute() or ".." in Path(binary).parts:
                raise ConfigError("Build binary paths must be relative and cannot contain '..'.")


@dataclass(frozen=True)
class ExecConfig:
    input_mode: str = "file"
    cmd_template: str = "{binary} {input_file}"
    timeout_sec: float = 5
    memory_limit_mb: int = 256

    def __post_init__(self):
        if self.input_mode not in ("file", "stdin", "args"):
            raise ConfigError("input_mode must be 'file', 'stdin', or 'args'.")
        validate_template(self.cmd_template, {"binary", "input", "input_file"}, {"binary"})
        for label, value in (("timeout_sec", self.timeout_sec), ("memory_limit_mb", self.memory_limit_mb)):
            if isinstance(value, bool) or not isinstance(value, (float, int)) or not math.isfinite(value) or value <= 0:
                raise ConfigError(f"{label} must be a positive finite number.")
        if not isinstance(self.memory_limit_mb, int):
            raise ConfigError("memory_limit_mb must be an integer.")


@dataclass(frozen=True)
class TestConfig:
    oracle_manifest: str
    regression_dir: str = ""


@dataclass(frozen=True)
class ProjectConfig:
    project_name: str
    repository_path: str
    base_commit: str
    patched_commit: str
    build: BuildConfig
    execution: ExecConfig
    test_suites: TestConfig


class ConfigManager:
    @staticmethod
    def load_config(path: str) -> ProjectConfig:
        config_path = Path(path).resolve()
        try:
            raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, yaml.YAMLError) as exc:
            raise ConfigError(f"Cannot read configuration {path}: {exc}") from exc
        if not isinstance(raw, dict):
            raise ConfigError("YAML configuration must be a mapping.")
        try:
            for key in ("project_name", "repository_path", "base_commit", "patched_commit"):
                if not isinstance(raw.get(key), str) or not raw[key].strip():
                    raise ConfigError(f"{key} must be a nonempty string.")
            for key in ("build", "execution", "test_suites"):
                if key in raw and not isinstance(raw[key], dict):
                    raise ConfigError(f"{key} must be a mapping.")
            build = BuildConfig(**raw["build"])
            execution = ExecConfig(**raw.get("execution", {}))
            suites = TestConfig(**raw["test_suites"])
            if not isinstance(suites.oracle_manifest, str) or not suites.oracle_manifest:
                raise ConfigError("test_suites.oracle_manifest is required.")
            if not isinstance(suites.regression_dir, str):
                raise ConfigError("test_suites.regression_dir must be a string.")
            resolve = lambda value: str((config_path.parent / value).resolve())
            return ProjectConfig(
                raw["project_name"], resolve(raw["repository_path"]),
                raw["base_commit"], raw["patched_commit"], build, execution,
                replace(suites, oracle_manifest=resolve(suites.oracle_manifest),
                        regression_dir=resolve(suites.regression_dir) if suites.regression_dir else ""),
            )
        except (TypeError, KeyError) as exc:
            raise ConfigError(f"Invalid or missing configuration field: {exc}") from exc

    @staticmethod
    def validate_workspace(config: ProjectConfig) -> ProjectConfig:
        """Resolve tags/branches to exact commits; Git worktrees are supported."""
        commits = {}
        for label in ("base", "patched"):
            commit = getattr(config, f"{label}_commit")
            try:
                proc = subprocess.run(
                    ["git", "-c", f"safe.directory={config.repository_path}", "rev-parse", "--verify", "--end-of-options", f"{commit}^{{commit}}"],
                    cwd=config.repository_path, capture_output=True, text=True, check=True,
                )
            except (OSError, subprocess.CalledProcessError) as exc:
                raise ConfigError(f"Cannot resolve {label} commit '{commit}' in {config.repository_path}.") from exc
            commits[f"{label}_commit"] = proc.stdout.strip()
        return replace(config, **commits)

    @staticmethod
    def setup_workspace(config: ProjectConfig, output_dir: str = "./reports") -> Path:
        root = Path(output_dir).resolve()
        try:
            for subdir in ("build", "results", "reproducers", "regression"):
                (root / subdir).mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ConfigError(f"Cannot prepare output directory {root}: {exc}") from exc
        return root
