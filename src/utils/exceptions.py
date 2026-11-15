"""Custom exceptions for the security patch validation tool.

Each exception carries an ``exit_code`` that the CLI entry-point propagates
to the shell so that CI/CD pipelines can react to specific failure modes.
"""


class PatchValidatorError(Exception):
    """Base exception for all patch-validator errors.

    Attributes:
        exit_code: Numeric code returned to the shell on unhandled raise.
        message: Human-readable error description.
    """

    exit_code: int = 30

    def __init__(self, message: str, exit_code: int | None = None) -> None:
        super().__init__(message)
        self.message = message
        if exit_code is not None:
            self.exit_code = exit_code


class ConfigError(PatchValidatorError):
    """Raised when configuration loading or workspace validation fails.

    Exit code **30** — build / config error.
    """

    exit_code: int = 30

    def __init__(self, message: str) -> None:
        super().__init__(message, exit_code=30)


class BuildError(PatchValidatorError):
    """Raised when a build step (release or sanitized) fails.

    Exit code **30** — build / config error.
    """

    exit_code: int = 30

    def __init__(self, message: str) -> None:
        super().__init__(message, exit_code=30)


class TestExecutionError(PatchValidatorError):
    """Raised when the test-runner encounters an unrecoverable problem.

    Exit code **30** — execution environment/tool error.
    """

    exit_code: int = 30

    def __init__(self, message: str) -> None:
        super().__init__(message, exit_code=30)


class AnalysisError(PatchValidatorError):
    """Raised when diff analysis, correlation, or reporting fails.

    Exit code **40** — inconclusive.
    """

    exit_code: int = 40

    def __init__(self, message: str) -> None:
        super().__init__(message, exit_code=40)
