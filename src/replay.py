"""Replay a saved bundle using the pipeline's execution and resource settings."""
import argparse
import json
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace

from src.core.config_manager import ExecConfig
from src.core.test_runner import TestRunner
from src.modules.report_generator import json_default
from src.utils.exceptions import PatchValidatorError


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--build", choices=("base_release", "base_sanitized", "patched_release", "patched_sanitized"), required=True)
    parser.add_argument("--minimized", action="store_true")
    args = parser.parse_args(argv)
    try:
        bundle = args.bundle.resolve()
        metadata = json.loads((bundle / "metadata.json").read_text())
        runner = TestRunner(SimpleNamespace(execution=ExecConfig(**metadata["execution"])))
        mode = args.build.split("_", 1)[1]
        result = runner.run_single_test(bundle / f"binary-{args.build}",
                                        bundle / ("minimized.input" if args.minimized else "original.input"), mode)
    except (OSError, ValueError, KeyError, TypeError, PatchValidatorError) as exc:
        parser.exit(40, f"Cannot replay bundle: {exc}\n")
    print(json.dumps(asdict(result), indent=2, default=json_default))
    return 128 - result.exit_code if result.exit_code < 0 else result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
