"""
logger.py
=========

Application-wide logging configuration.

Design goals:
    - One place configures logging for the entire application.
    - Human-readable, timestamped console output for local development.
    - A rotating file handler so a full scan's logs are preserved for
      later review (useful once this runs unattended inside a CI/CD
      pipeline).
    - Idempotent setup: calling `configure_logging()` multiple times
      (e.g. in tests) will not duplicate handlers.
"""

from __future__ import annotations

import logging
import logging.handlers
import sys
from pathlib import Path

from scanner.config import get_settings

_CONSOLE_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_LOGGER_NAME = "gitlab_pii_scanner"
_configured = False


class _WindowsSafeRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """Rotating handler that keeps logging if Windows refuses a rollover rename."""

    def doRollover(self) -> None:  # noqa: N802 - logging API name
        try:
            super().doRollover()
        except PermissionError:
            if self.stream:
                self.stream.close()
                self.stream = None
            self.mode = "a"
            self.stream = self._open()


def configure_logging(*, log_to_file: bool = True) -> logging.Logger:
    """
    Configure and return the application's root logger.

    Safe to call multiple times; subsequent calls return the already
    configured logger without adding duplicate handlers.

    Args:
        log_to_file: When True, also write logs to a rotating file
            under the configured output directory. Set to False for
            environments (e.g. some CI runners) where only console
            output is desired.

    Returns:
        The configured `logging.Logger` instance for the application.
    """
    global _configured

    logger = logging.getLogger(_LOGGER_NAME)

    if _configured:
        return logger

    settings = get_settings()
    logger.setLevel(settings.log_level)
    logger.propagate = False

    formatter = logging.Formatter(fmt=_CONSOLE_FORMAT, datefmt=_DATE_FORMAT)

    console_handler = logging.StreamHandler(stream=sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(settings.log_level)
    logger.addHandler(console_handler)

    if log_to_file:
        log_directory = settings.output_directory / "logs"
        log_directory.mkdir(parents=True, exist_ok=True)
        log_file_path = log_directory / "scanner.log"

        file_handler = _WindowsSafeRotatingFileHandler(
            filename=log_file_path,
            maxBytes=2 * 1024 * 1024,  # 2 MB per file
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(settings.log_level)
        logger.addHandler(file_handler)

    _configured = True
    logger.debug(
        "Logging configured (level=%s, log_to_file=%s)",
        settings.log_level,
        log_to_file,
    )
    return logger


def get_logger(name: str | None = None) -> logging.Logger:
    """
    Return a child logger of the application's configured root logger.

    Ensures `configure_logging()` has been called so that any logger
    obtained through this function inherits the correct handlers and
    level, even if it is the first logging call in the process.

    Args:
        name: Optional dotted module name (typically `__name__`).
            When omitted, the application root logger is returned.

    Returns:
        A `logging.Logger` instance.
    """
    if not _configured:
        configure_logging()

    if name is None:
        return logging.getLogger(_LOGGER_NAME)

    return logging.getLogger(_LOGGER_NAME).getChild(name)
