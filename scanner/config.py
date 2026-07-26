"""
config.py
=========

Centralized, typed configuration for the GitLab PII Scanner.

Design goals:
    - A single source of truth for all configurable values.
    - No hidden globals: configuration is an explicit object that is
      constructed once and passed around (or imported as a singleton).
    - Environment-variable driven, with sane, explicit defaults, so the
      same code runs locally and inside a future CI/CD pipeline
      (e.g. Azure DevOps) without modification.
    - Fails fast and loudly if given invalid values, rather than
      silently falling back to something unexpected.

Nothing in this module performs I/O beyond reading environment
variables and (optionally) a local `.env` file for developer
convenience.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

try:
    # Optional convenience for local development: if python-dotenv is
    # installed and a .env file exists, load it into the environment
    # before we read from os.environ below. This is intentionally
    # optional and silent-safe: production environments (CI/CD)
    # will simply set real environment variables instead.
    from dotenv import load_dotenv

    load_dotenv(dotenv_path=Path.cwd() / ".env", override=False)
except ImportError:  # pragma: no cover - optional dependency
    pass


class ConfigError(Exception):
    """Raised when the application configuration is invalid."""


def _env_str(name: str, default: str) -> str:
    """Read a string environment variable, falling back to a default."""
    value = os.environ.get(name)
    return value if value not in (None, "") else default


def _env_int(name: str, default: int) -> int:
    """Read an integer environment variable, falling back to a default."""
    raw = os.environ.get(name)
    if raw in (None, ""):
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(
            f"Environment variable {name!r} must be an integer, got {raw!r}."
        ) from exc


def _env_bool(name: str, default: bool) -> bool:
    """Read a boolean environment variable, falling back to a default."""
    raw = os.environ.get(name)
    if raw in (None, ""):
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_path(name: str, default: Path) -> Path:
    """Read a filesystem path environment variable."""
    raw = os.environ.get(name)
    return Path(raw).expanduser().resolve() if raw else default


def _validate_filename(name: str, variable_name: str) -> str:
    """
    Validate an environment-provided filename stays a filename.

    Output paths are joined to configured directories later. This
    rejects traversal and path input early so configuration fails before
    the scan starts.
    """
    if not name or not name.strip():
        raise ConfigError(f"{variable_name} must not be empty.")

    filename = name.strip()
    if ".." in filename:
        raise ConfigError(f"{variable_name} must not contain '..', got {name!r}.")
    if "/" in filename or "\\" in filename:
        raise ConfigError(
            f"{variable_name} must be a file name only, not a path, got {name!r}."
        )
    if Path(filename).is_absolute():
        raise ConfigError(f"{variable_name} must not be an absolute path, got {name!r}.")

    return filename


# ---------------------------------------------------------------------------
# Supported source file extensions.
#
# This lives in config.py (rather than being hardcoded deep inside the
# scanning logic added in a later phase) so it can be tuned per-project
# without touching scanning code.
# ---------------------------------------------------------------------------
DEFAULT_SUPPORTED_EXTENSIONS: tuple[str, ...] = (
    ".py",
    ".java",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".cs",
    ".go",
    ".php",
    ".rb",
    ".c",
    ".cpp",
    ".h",
    ".hpp",
    ".json",
    ".yml",
    ".yaml",
    ".xml",
    ".env",
    ".ini",
    ".cfg",
    ".properties",
    ".sql",
    ".md",
    ".txt",
)

# Directories that should never be scanned, regardless of project.
DEFAULT_EXCLUDED_DIRECTORIES: tuple[str, ...] = (
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    "dist",
    "build",
    ".idea",
    ".vscode",
    "presidio",  # the third-party reference repo must never be scanned
)


@dataclass(frozen=True, slots=True)
class ScannerSettings:
    """
    Immutable, validated application settings.

    Instances are created via `ScannerSettings.load()`, which reads
    environment variables (optionally populated from a `.env` file).
    The dataclass is frozen so that once loaded, settings cannot be
    accidentally mutated elsewhere in the codebase.
    """

    # General
    app_name: str
    environment: str  # e.g. "local", "ci", "production"
    log_level: str

    # Filesystem
    working_directory: Path
    output_directory: Path

    # Scanning behaviour (used by later phases; defined now so the
    # shape of configuration doesn't change later)
    supported_extensions: tuple[str, ...]
    excluded_directories: tuple[str, ...]
    max_file_size_bytes: int

    # Presidio (Phase 3: PII detection)
    presidio_language: str
    presidio_min_confidence: float
    presidio_spacy_model: str

    # Repository Manager (Phase 2: GitLab cloning)
    clone_base_directory: Path
    clone_shallow_depth: int  # 0 means a full (non-shallow) clone

    # Risk Engine (Task 2, Phase 1: deterministic pipeline gating)
    risk_warning_threshold: int
    risk_fail_threshold: int

    # Report Generator (Task 2, Phase 1: structured JSON report)
    report_output_directory: Path
    report_redaction_enabled: bool

    # AI Assistant (Task 2, Phase 2: AI-generated summaries only —
    # never detection, scoring, or pass/fail decisions). All fields
    # below have defaults so existing code/tests that construct
    # ScannerSettings without them keep working unchanged.
    ai_enabled: bool = True
    ai_provider: str = "null"
    ai_api_key: str = ""
    ai_model: str = "gpt-4o-mini"
    ai_temperature: float = 0.2
    ai_timeout_seconds: int = 30
    ai_azure_endpoint: str = ""
    ai_azure_api_version: str = "2024-08-01-preview"
    ai_summary_filename: str = "ai-summary.md"

    @staticmethod
    def load() -> "ScannerSettings":
        """
        Build a ScannerSettings instance from environment variables.

        Raises:
            ConfigError: if any value is present but invalid.
        """
        working_directory = _env_path("SCANNER_WORKING_DIR", Path.cwd())
        output_directory = _env_path(
            "SCANNER_OUTPUT_DIR", working_directory / "output"
        )

        min_confidence = os.environ.get("PRESIDIO_MIN_CONFIDENCE", "0.5")
        try:
            min_confidence_value = float(min_confidence)
        except ValueError as exc:
            raise ConfigError(
                "PRESIDIO_MIN_CONFIDENCE must be a float between 0 and 1, "
                f"got {min_confidence!r}."
            ) from exc

        if not (0.0 <= min_confidence_value <= 1.0):
            raise ConfigError(
                "PRESIDIO_MIN_CONFIDENCE must be between 0.0 and 1.0, "
                f"got {min_confidence_value}."
            )

        log_level = _env_str("SCANNER_LOG_LEVEL", "INFO").upper()
        valid_log_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if log_level not in valid_log_levels:
            raise ConfigError(
                f"SCANNER_LOG_LEVEL must be one of {sorted(valid_log_levels)}, "
                f"got {log_level!r}."
            )

        clone_base_directory = _env_path(
            "SCANNER_CLONE_BASE_DIR", output_directory / "cloned_repositories"
        )

        clone_shallow_depth = _env_int("SCANNER_CLONE_SHALLOW_DEPTH", 1)
        if clone_shallow_depth < 0:
            raise ConfigError(
                "SCANNER_CLONE_SHALLOW_DEPTH must be >= 0 (0 disables shallow "
                f"cloning), got {clone_shallow_depth}."
            )

        risk_warning_threshold = _env_int("RISK_WARNING_THRESHOLD", 20)
        risk_fail_threshold = _env_int("RISK_FAIL_THRESHOLD", 50)
        if risk_warning_threshold < 0 or risk_fail_threshold < 0:
            raise ConfigError(
                "RISK_WARNING_THRESHOLD and RISK_FAIL_THRESHOLD must be >= 0, "
                f"got warning={risk_warning_threshold}, fail={risk_fail_threshold}."
            )
        if risk_fail_threshold < risk_warning_threshold:
            raise ConfigError(
                "RISK_FAIL_THRESHOLD must be >= RISK_WARNING_THRESHOLD, "
                f"got warning={risk_warning_threshold}, fail={risk_fail_threshold}."
            )

        report_output_directory = _env_path(
            "REPORT_OUTPUT_DIR", output_directory / "reports"
        )
        report_redaction_enabled = _env_bool("REPORT_REDACTION_ENABLED", True)

        ai_temperature_raw = os.environ.get("AI_TEMPERATURE", "0.2")
        try:
            ai_temperature = float(ai_temperature_raw)
        except ValueError as exc:
            raise ConfigError(
                f"AI_TEMPERATURE must be a float, got {ai_temperature_raw!r}."
            ) from exc
        if not (0.0 <= ai_temperature <= 2.0):
            raise ConfigError(
                f"AI_TEMPERATURE must be between 0.0 and 2.0, got {ai_temperature}."
            )

        ai_timeout_seconds = _env_int("AI_TIMEOUT_SECONDS", 30)
        if ai_timeout_seconds <= 0:
            raise ConfigError(
                f"AI_TIMEOUT_SECONDS must be > 0, got {ai_timeout_seconds}."
            )

        ai_summary_filename = _validate_filename(
            _env_str("AI_SUMMARY_FILENAME", "ai-summary.md"),
            "AI_SUMMARY_FILENAME",
        )

        return ScannerSettings(
            app_name=_env_str("SCANNER_APP_NAME", "gitlab-pii-scanner"),
            environment=_env_str("SCANNER_ENVIRONMENT", "local"),
            log_level=log_level,
            working_directory=working_directory,
            output_directory=output_directory,
            supported_extensions=DEFAULT_SUPPORTED_EXTENSIONS,
            excluded_directories=DEFAULT_EXCLUDED_DIRECTORIES,
            max_file_size_bytes=_env_int(
                "SCANNER_MAX_FILE_SIZE_BYTES", 5 * 1024 * 1024  # 5 MB
            ),
            presidio_language=_env_str("PRESIDIO_LANGUAGE", "en"),
            presidio_min_confidence=min_confidence_value,
            presidio_spacy_model=_env_str("PRESIDIO_SPACY_MODEL", "en_core_web_lg"),
            clone_base_directory=clone_base_directory,
            clone_shallow_depth=clone_shallow_depth,
            risk_warning_threshold=risk_warning_threshold,
            risk_fail_threshold=risk_fail_threshold,
            report_output_directory=report_output_directory,
            report_redaction_enabled=report_redaction_enabled,
            ai_enabled=_env_bool("AI_ENABLED", True),
            ai_provider=_env_str("AI_PROVIDER", "null"),
            ai_api_key=_env_str("AI_API_KEY", ""),
            ai_model=_env_str("AI_MODEL", "gpt-4o-mini"),
            ai_temperature=ai_temperature,
            ai_timeout_seconds=ai_timeout_seconds,
            ai_azure_endpoint=_env_str("AI_AZURE_ENDPOINT", ""),
            ai_azure_api_version=_env_str("AI_AZURE_API_VERSION", "2024-08-01-preview"),
            ai_summary_filename=ai_summary_filename,
        )


# A process-wide singleton. Modules that need settings should import
# `get_settings()` rather than constructing their own instance, so the
# whole application shares one validated configuration object.
_settings_instance: ScannerSettings | None = None


def get_settings() -> ScannerSettings:
    """Return the process-wide ScannerSettings singleton, loading it on first use."""
    global _settings_instance
    if _settings_instance is None:
        _settings_instance = ScannerSettings.load()
    return _settings_instance
