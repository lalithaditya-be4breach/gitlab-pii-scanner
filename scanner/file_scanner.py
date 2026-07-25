"""
file_scanner.py
================

Phase 3: File traversal.

Walks a repository's working tree and produces the `ScannedFile`
candidates that `PIIDetector` (also Phase 3) will analyze, honoring
the rules already defined in `ScannerSettings`:

    - only files whose extension is in `supported_extensions`
    - never descending into `excluded_directories`
    - skipping files larger than `max_file_size_bytes`

Reading a candidate file's text content safely (encoding fallback,
undecodable/binary detection) lives here too, since it is the natural
companion to "which files do we scan" — downstream code should only
ever have to deal with text it already knows is decodable.

Nothing in this module imports Presidio; detection stays entirely in
`pii_detector.py`, keeping traversal and analysis independently
testable.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator, Tuple

from scanner.config import ScannerSettings, get_settings
from scanner.logger import get_logger
from scanner.models import ScannedFile
from scanner.utils import is_excluded_directory, is_supported_extension, safe_relative_path

logger = get_logger(__name__)

# Text-decoding attempts, in order. UTF-8 (the overwhelming common
# case) is tried first; latin-1 never raises (it maps every byte to a
# code point) so it acts as a safe last resort before giving up.
_TEXT_ENCODINGS: Tuple[str, ...] = ("utf-8", "utf-8-sig", "latin-1")


class FileScanner:
    """
    Traverses a repository directory and yields scannable files.

    Instances are cheap and stateless aside from configuration, mirroring
    `RepositoryManager`. A single instance can be reused across multiple
    `iter_files_with_content()` calls; `skipped_count` reflects only the
    most recent call.
    """

    def __init__(self, settings: ScannerSettings | None = None) -> None:
        """
        Args:
            settings: Optional explicit settings object. Defaults to the
                process-wide singleton from `scanner.config.get_settings()`.
        """
        self._settings = settings or get_settings()
        self._skipped_count = 0

    @property
    def skipped_count(self) -> int:
        """Number of candidate files skipped during the most recent traversal."""
        return self._skipped_count

    def iter_files(self, repository_root: Path) -> Iterator[ScannedFile]:
        """
        Yield `ScannedFile` metadata for every in-scope file under `repository_root`.

        Args:
            repository_root: Root directory of the repository to walk.

        Yields:
            `ScannedFile` instances for files that pass the extension,
            exclusion, and size filters. Nothing is read from disk here
            beyond `stat()` — use `read_text()` to get file contents.
        """
        self._skipped_count = 0
        repository_root = repository_root.expanduser().resolve()

        for scanned_file in self._walk(repository_root):
            yield scanned_file

    def iter_files_with_content(
        self, repository_root: Path
    ) -> Iterator[Tuple[ScannedFile, str]]:
        """
        Yield `(ScannedFile, text)` pairs for every readable, in-scope file.

        Files that pass the traversal filters but cannot be decoded as
        text (e.g. genuinely binary files that happen to have a
        supported extension) are counted in `skipped_count` and not
        yielded.

        Args:
            repository_root: Root directory of the repository to walk.

        Yields:
            Tuples of `(ScannedFile, text_content)`.
        """
        for scanned_file in self.iter_files(repository_root):
            text = self.read_text(scanned_file)
            if text is None:
                self._skipped_count += 1
                logger.debug(
                    "Skipping unreadable/undecodable file: %s", scanned_file.absolute_path
                )
                continue
            yield scanned_file, text

    def read_text(self, scanned_file: ScannedFile) -> str | None:
        """
        Read a scanned file's contents as text.

        Args:
            scanned_file: The file to read.

        Returns:
            The decoded file contents, or None if the file could not be
            read or decoded with any of the supported encodings.
        """
        for encoding in _TEXT_ENCODINGS:
            try:
                return scanned_file.absolute_path.read_text(encoding=encoding)
            except UnicodeDecodeError:
                continue
            except OSError as exc:
                logger.warning("Could not read %s: %s", scanned_file.absolute_path, exc)
                return None
        return None

    # -- Internal helpers -------------------------------------------------------

    def _walk(self, repository_root: Path) -> Iterator[ScannedFile]:
        """Walk the tree, pruning excluded directories and filtering files."""
        if not repository_root.is_dir():
            logger.warning("Repository root is not a directory: %s", repository_root)
            return

        excluded = self._settings.excluded_directories
        supported = self._settings.supported_extensions
        max_size = self._settings.max_file_size_bytes

        for current_dir, dir_names, file_names in os.walk(repository_root):
            # Prune excluded directories in place so os.walk never
            # descends into them (e.g. .git, node_modules, presidio).
            dir_names[:] = sorted(
                name for name in dir_names if not is_excluded_directory(name, excluded)
            )

            current_path = Path(current_dir)
            for file_name in sorted(file_names):
                absolute_path = current_path / file_name

                if not is_supported_extension(absolute_path, supported):
                    continue

                try:
                    size_bytes = absolute_path.stat().st_size
                except OSError as exc:
                    logger.warning("Could not stat %s: %s", absolute_path, exc)
                    self._skipped_count += 1
                    continue

                if size_bytes > max_size:
                    logger.debug(
                        "Skipping file larger than max_file_size_bytes: %s (%d bytes)",
                        absolute_path,
                        size_bytes,
                    )
                    self._skipped_count += 1
                    continue

                yield ScannedFile(
                    absolute_path=absolute_path,
                    relative_path=safe_relative_path(absolute_path, repository_root),
                    size_bytes=size_bytes,
                    extension=absolute_path.suffix.lower(),
                )
