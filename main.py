"""
main.py
=======

Command-line entry point for the GitLab PII Scanner.

Phase 3 scope
-------------
This entry point currently:
    1. Parses CLI arguments for the two scan modes (`local` and `gitlab`).
    2. Loads and validates application configuration (`scanner.config`).
    3. Configures application-wide logging (`scanner.logger`).
    4. Uses `RepositoryManager` (Phase 2) to obtain the repository to
       scan — validating a local repository, or cloning a GitLab
       repository via GitPython.
    5. Uses `ScanEngine` (Phase 3) to traverse the repository and run
       Microsoft Presidio over every in-scope file, then prints a
       findings summary.
    6. Report generation (CSV/HTML) is not yet implemented — it
       arrives in Phase 4.

Nothing here reaches into the `presidio` reference repository; Phase 3
consumes Presidio exclusively as the installed `presidio-analyzer`
package, via `scanner.pii_detector`.

Usage
-----
    python main.py local --path D:\\some\\project
    python main.py gitlab --url https://gitlab.com/group/project.git
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from scanner.config import ConfigError, get_settings
from scanner.logger import configure_logging, get_logger
from scanner.pii_detector import PIIDetectorError
from scanner.repository_manager import (
    InvalidRepository,
    InvalidRepositoryURL,
    RepositoryManager,
    RepositoryManagerError,
    RepositoryNotFound,
)
from scanner.scan_engine import ScanEngine
from scanner.utils import ensure_directory


class ExitCode:
    """Process exit codes used by this entry point."""

    SUCCESS = 0
    CONFIGURATION_ERROR = 1
    INVALID_ARGUMENTS = 2
    PATH_NOT_FOUND = 3
    INVALID_REPOSITORY = 4
    INVALID_REPOSITORY_URL = 5
    CLONE_FAILED = 6
    SCAN_ENGINE_ERROR = 7


def build_arg_parser() -> argparse.ArgumentParser:
    """
    Construct the CLI argument parser.

    Two subcommands are defined now so the CLI surface is stable for
    later phases:
        - `local`  : scan a repository already present on disk.
        - `gitlab` : clone a GitLab repository, then scan it
                     (cloning is implemented in the next phase).

    Returns:
        A configured `argparse.ArgumentParser`.
    """
    parser = argparse.ArgumentParser(
        prog="gitlab-pii-scanner",
        description=(
            "Identify PII at the code level using Microsoft Presidio. "
            "Foundation phase: validates configuration and environment only."
        ),
    )
    parser.add_argument(
        "--no-file-log",
        action="store_true",
        help="Disable writing logs to a rotating log file (console only).",
    )

    subparsers = parser.add_subparsers(dest="mode", required=True)

    local_parser = subparsers.add_parser(
        "local", help="Scan a repository that already exists on the local disk."
    )
    local_parser.add_argument(
        "--path",
        type=Path,
        required=True,
        help="Absolute or relative path to the local repository/directory to scan.",
    )

    gitlab_parser = subparsers.add_parser(
        "gitlab",
        help="Clone a GitLab repository, then scan it (cloning added in a later phase).",
    )
    gitlab_parser.add_argument(
        "--url",
        type=str,
        required=True,
        help="HTTPS clone URL of the GitLab repository, e.g. "
        "https://gitlab.com/group/project.git",
    )
    gitlab_parser.add_argument(
        "--branch",
        type=str,
        default=None,
        help="Optional branch to check out after cloning. Defaults to the "
        "repository's default branch.",
    )

    return parser


def run(argv: list[str] | None = None) -> int:
    """
    Application entry point logic, separated from `main()` for testability.

    Args:
        argv: Optional argument list (defaults to `sys.argv[1:]` when None).
            Passing this explicitly allows unit tests to invoke `run()`
            without spawning a subprocess.

    Returns:
        A process exit code (see `ExitCode`).
    """
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        settings = get_settings()
    except ConfigError as exc:
        # Logging isn't configured yet if settings failed to load, so
        # this specific failure is reported directly to stderr.
        print(f"Configuration error: {exc}", file=sys.stderr)
        return ExitCode.CONFIGURATION_ERROR

    ensure_directory(settings.output_directory)
    configure_logging(log_to_file=not args.no_file_log)
    logger = get_logger(__name__)

    logger.info("=" * 60)
    logger.info("%s starting (environment=%s)", settings.app_name, settings.environment)
    logger.info("Working directory : %s", settings.working_directory)
    logger.info("Output directory  : %s", settings.output_directory)
    logger.info("Presidio language : %s", settings.presidio_language)
    logger.info("Min confidence    : %.2f", settings.presidio_min_confidence)
    logger.info("=" * 60)

    repository_manager = RepositoryManager(settings=settings)

    if args.mode == "local":
        try:
            repository = repository_manager.obtain_local(args.path)
        except RepositoryNotFound as exc:
            logger.error("%s", exc)
            return ExitCode.PATH_NOT_FOUND
        except InvalidRepository as exc:
            logger.error("%s", exc)
            return ExitCode.INVALID_REPOSITORY

        logger.info("Repository ready at: %s", repository.local_path)

    elif args.mode == "gitlab":
        try:
            repository = repository_manager.obtain_gitlab(args.url, branch=args.branch)
        except InvalidRepositoryURL as exc:
            logger.error("%s", exc)
            return ExitCode.INVALID_REPOSITORY_URL
        except RepositoryManagerError as exc:
            # Covers CloneFailed and its subclasses (AuthenticationFailed,
            # BranchNotFound), plus any other repository manager error.
            logger.error("%s", exc)
            return ExitCode.CLONE_FAILED

        logger.info("Repository cloned and ready at: %s", repository.local_path)

    else:
        # argparse's `required=True` on the subparser makes this
        # unreachable, but it is kept as an explicit safety net rather
        # than relying on that guarantee silently.
        logger.error("Unknown mode: %s", args.mode)
        return ExitCode.INVALID_ARGUMENTS

    try:
        scan_engine = ScanEngine(settings=settings)
    except PIIDetectorError as exc:
        logger.error("Could not initialize the Presidio-based scan engine: %s", exc)
        return ExitCode.SCAN_ENGINE_ERROR

    summary = scan_engine.scan(repository)
    _log_summary(logger, summary)

    logger.info(
        "Phase 3 complete. Report generation (CSV/HTML) is implemented "
        "in the next phase."
    )
    return ExitCode.SUCCESS


def _log_summary(logger, summary) -> None:  # noqa: ANN001 - logging.Logger, ScanSummary
    """Print a human-readable findings summary to the log/console."""
    logger.info("-" * 60)
    logger.info("Scan summary for: %s", summary.source.identifier)
    logger.info("Files scanned : %d", summary.files_scanned)
    logger.info("Files skipped : %d", summary.files_skipped)
    logger.info("Total findings: %d", summary.total_findings)

    if summary.total_findings:
        for severity, count in summary.findings_by_severity.items():
            if count:
                logger.info("  %-8s : %d", severity.value, count)

        logger.info("Findings:")
        for finding in summary.findings:
            line = (
                f"  [{finding.severity.value}] {finding.entity_type} "
                f"(confidence={finding.confidence_score:.2f}) "
                f"in {finding.file.relative_path}"
            )
            if finding.line_number is not None:
                line += f":{finding.line_number}"
            logger.info(line)

    logger.info("-" * 60)


def main() -> None:
    """Console-script style entry point that exits the process with the right code."""
    sys.exit(run())


if __name__ == "__main__":
    main()
