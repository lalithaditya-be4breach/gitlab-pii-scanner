"""
test_file_scanner.py
=====================

Tests for Phase 3's `FileScanner`, covering:
    - supported vs. unsupported extensions
    - excluded directories are never descended into
    - files larger than max_file_size_bytes are skipped
    - undecodable/binary files are skipped, not yielded
    - relative paths are computed correctly
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scanner.config import ScannerSettings
from scanner.file_scanner import FileScanner


def _build_test_settings(
    tmp_path: Path,
    *,
    supported_extensions: tuple[str, ...] = (".py", ".txt"),
    excluded_directories: tuple[str, ...] = (".git", "node_modules", "presidio"),
    max_file_size_bytes: int = 1024,
) -> ScannerSettings:
    """Construct a ScannerSettings instance pointed entirely at a tmp_path sandbox."""
    output_directory = tmp_path / "output"
    return ScannerSettings(
        app_name="gitlab-pii-scanner-test",
        environment="test",
        log_level="DEBUG",
        working_directory=tmp_path,
        output_directory=output_directory,
        supported_extensions=supported_extensions,
        excluded_directories=excluded_directories,
        max_file_size_bytes=max_file_size_bytes,
        presidio_language="en",
        presidio_min_confidence=0.5,
        presidio_spacy_model="en_core_web_lg",
        clone_base_directory=output_directory / "cloned_repositories",
        clone_shallow_depth=1,
        risk_warning_threshold=20,
        risk_fail_threshold=50,
        report_output_directory=output_directory / "reports",
        report_redaction_enabled=True,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A small fake repository tree exercising every traversal rule."""
    root = tmp_path / "repo"
    root.mkdir()

    (root / "app.py").write_text("email = 'someone@example.com'\n")
    (root / "notes.txt").write_text("just some notes")
    (root / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00")  # unsupported ext

    excluded_dir = root / "node_modules"
    excluded_dir.mkdir()
    (excluded_dir / "should_be_ignored.py").write_text("print('ignored')")

    git_dir = root / ".git"
    git_dir.mkdir()
    (git_dir / "config.py").write_text("print('also ignored')")

    nested = root / "src" / "pkg"
    nested.mkdir(parents=True)
    (nested / "module.py").write_text("phone = '555-0100'\n")

    too_big = root / "huge.txt"
    too_big.write_text("x" * 2048)  # exceeds max_file_size_bytes=1024

    return root


@pytest.fixture
def scanner(tmp_path: Path) -> FileScanner:
    return FileScanner(settings=_build_test_settings(tmp_path))


def test_iter_files_only_yields_supported_extensions(scanner: FileScanner, repo: Path) -> None:
    """Files with extensions outside supported_extensions are never yielded."""
    results = list(scanner.iter_files(repo))
    yielded_names = {f.absolute_path.name for f in results}

    assert "app.py" in yielded_names
    assert "notes.txt" in yielded_names
    assert "image.png" not in yielded_names


def test_iter_files_prunes_excluded_directories(scanner: FileScanner, repo: Path) -> None:
    """Files inside excluded directories are never yielded, even with a supported extension."""
    results = list(scanner.iter_files(repo))
    yielded_paths = {str(f.relative_path) for f in results}

    assert not any("node_modules" in path for path in yielded_paths)
    assert not any(".git" in path for path in yielded_paths)


def test_iter_files_descends_into_nested_directories(scanner: FileScanner, repo: Path) -> None:
    """Supported files several directories deep are still found."""
    results = list(scanner.iter_files(repo))
    yielded_names = {f.absolute_path.name for f in results}

    assert "module.py" in yielded_names


def test_iter_files_skips_oversized_files(scanner: FileScanner, repo: Path) -> None:
    """Files larger than max_file_size_bytes are excluded and counted as skipped."""
    results = list(scanner.iter_files(repo))
    yielded_names = {f.absolute_path.name for f in results}

    assert "huge.txt" not in yielded_names
    assert scanner.skipped_count >= 1


def test_iter_files_relative_path_is_relative_to_repository_root(
    scanner: FileScanner, repo: Path
) -> None:
    """`relative_path` is computed against the repository root, not an absolute path."""
    results = list(scanner.iter_files(repo))
    app_py = next(f for f in results if f.absolute_path.name == "app.py")

    assert app_py.relative_path == Path("app.py")
    assert not app_py.relative_path.is_absolute()


def test_read_text_returns_file_contents(scanner: FileScanner, repo: Path) -> None:
    """A readable text file's contents are returned as-is."""
    results = list(scanner.iter_files(repo))
    app_py = next(f for f in results if f.absolute_path.name == "app.py")

    text = scanner.read_text(app_py)

    assert text is not None
    assert "someone@example.com" in text


def test_iter_files_with_content_yields_readable_text_files(
    scanner: FileScanner, tmp_path: Path
) -> None:
    """A readable text file is yielded as an (ScannedFile, text) pair.

    Note: the latin-1 fallback in `read_text()` means almost any byte
    sequence decodes as *something*, so a dedicated "undecodable file"
    case isn't practical to construct portably. `read_text()`'s
    encoding fallback chain is exercised directly instead, below.
    """
    root = tmp_path / "text_repo"
    root.mkdir()
    (root / "ok.py").write_text("token = 'abc'\n")

    pairs = list(scanner.iter_files_with_content(root))

    assert len(pairs) == 1
    assert pairs[0][0].absolute_path.name == "ok.py"
    assert "token" in pairs[0][1]


def test_read_text_falls_back_to_latin1_for_non_utf8_bytes(
    scanner: FileScanner, tmp_path: Path
) -> None:
    """A file with bytes that are invalid UTF-8 is still read via the latin-1 fallback."""
    root = tmp_path / "latin1_repo"
    root.mkdir()
    latin1_file = root / "legacy.txt"
    # 0xE9 is invalid as a UTF-8 continuation/lead byte here, but is a
    # valid latin-1 code point ('é').
    latin1_file.write_bytes(b"caf\xe9\n")

    results = list(scanner.iter_files(root))
    scanned = next(f for f in results if f.absolute_path.name == "legacy.txt")

    text = scanner.read_text(scanned)

    assert text is not None
    assert text.startswith("caf")


def test_iter_files_with_content_counts_skipped_stat_failures(
    scanner: FileScanner, tmp_path: Path
) -> None:
    """A broken symlink (fails stat) is counted as skipped, not yielded."""
    root = tmp_path / "broken_link_repo"
    root.mkdir()
    broken_link = root / "dangling.py"
    try:
        broken_link.symlink_to(root / "does_not_exist.py")
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks are not supported in this environment.")

    results = list(scanner.iter_files(root))

    assert results == []
    assert scanner.skipped_count == 1
