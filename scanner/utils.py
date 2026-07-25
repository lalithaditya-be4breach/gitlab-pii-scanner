"""
utils.py
========

Small, dependency-free helper functions used across the project.

Nothing in this module performs network calls, Git operations, or
Presidio calls — those belong in later, dedicated modules. Everything
here is a pure or near-pure function that later phases (file
traversal, report generation) will rely on.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path


def ensure_directory(path: Path) -> Path:
    """
    Ensure a directory exists, creating parent directories as needed.

    Args:
        path: The directory path to create.

    Returns:
        The same path, guaranteed to exist as a directory.

    Raises:
        NotADirectoryError: if `path` already exists but is a file.
    """
    if path.exists() and not path.is_dir():
        raise NotADirectoryError(f"Expected a directory, found a file: {path}")
    path.mkdir(parents=True, exist_ok=True)
    return path


def is_supported_extension(file_path: Path, supported_extensions: tuple[str, ...]) -> bool:
    """
    Determine whether a file's extension is one we scan.

    Args:
        file_path: Path to the file being checked.
        supported_extensions: Extensions to allow, e.g. (".py", ".js").
            Comparison is case-insensitive.

    Returns:
        True if the file's suffix matches one of the supported extensions.
    """
    return file_path.suffix.lower() in {ext.lower() for ext in supported_extensions}


def is_excluded_directory(directory_name: str, excluded_directories: tuple[str, ...]) -> bool:
    """
    Determine whether a directory name should be skipped during traversal.

    Args:
        directory_name: The bare name of a directory (not a full path).
        excluded_directories: Directory names to always skip.

    Returns:
        True if the directory should be excluded from scanning.
    """
    return directory_name in excluded_directories


def human_readable_size(size_bytes: int) -> str:
    """
    Convert a byte count into a human-readable string.

    Args:
        size_bytes: Size in bytes. Must be non-negative.

    Returns:
        A string such as "512 B", "13.4 KB", or "2.1 MB".

    Raises:
        ValueError: if `size_bytes` is negative.
    """
    if size_bytes < 0:
        raise ValueError(f"size_bytes must be non-negative, got {size_bytes}")

    size = float(size_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024.0:
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


def safe_relative_path(absolute_path: Path, base_path: Path) -> Path:
    """
    Compute a path relative to `base_path`, falling back gracefully.

    Args:
        absolute_path: The path to make relative.
        base_path: The directory `absolute_path` should be relative to.

    Returns:
        `absolute_path` relative to `base_path` when possible; otherwise
        the original `absolute_path` unchanged (e.g. if the paths are
        on different drives on Windows).
    """
    try:
        return absolute_path.relative_to(base_path)
    except ValueError:
        return absolute_path


def utc_now() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


def format_timestamp_for_filename(moment: datetime) -> str:
    """
    Format a datetime for safe use inside a filename.

    Example:
        2026-07-25 07:19:00 -> "20260725_071900"

    Args:
        moment: The datetime to format.

    Returns:
        A filesystem-safe timestamp string.
    """
    return moment.strftime("%Y%m%d_%H%M%S")
