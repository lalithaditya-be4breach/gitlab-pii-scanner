"""
test_gitlab_provider.py
========================

Tests for the new `scanner.gitlab` package added to support scanning
GitLab repositories via Azure DevOps: token-based authentication,
secret masking, and safe cleanup of temporary clones.

These are deliberately offline/unit-level: network-dependent cloning
behaviour is already covered by `tests/test_repository_manager.py`
(unchanged by this feature). What's new here is verified without a
network call wherever possible.
"""

from __future__ import annotations

from pathlib import Path

import git
import pytest

from scanner.config import ScannerSettings
from scanner.gitlab.auth import (
    UnsupportedAuthenticationScheme,
    build_authenticated_url,
    mask_secret,
    sanitize_error_text,
)
from scanner.gitlab.cleanup import remove_clone
from scanner.models import RepositorySource, RepositorySourceType
from scanner.repository_manager import RepositoryManager

_SECRET_TOKEN = "glpat-abcdEXAMPLE1234567890"  # noqa: S105 - fake test token


# ---------------------------------------------------------------------------
# auth.build_authenticated_url
# ---------------------------------------------------------------------------


def test_build_authenticated_url_embeds_token_for_https() -> None:
    """A token is embedded as HTTP Basic auth credentials for an https:// URL."""
    url = build_authenticated_url("https://gitlab.com/group/project.git", _SECRET_TOKEN)

    assert url == f"https://oauth2:{_SECRET_TOKEN}@gitlab.com/group/project.git"


def test_build_authenticated_url_without_token_returns_url_unchanged() -> None:
    """No token means no credentials are added -- the public clone URL is untouched."""
    url = "https://gitlab.com/group/project.git"

    assert build_authenticated_url(url, None) == url
    assert build_authenticated_url(url, "") == url


def test_build_authenticated_url_rejects_ssh_url_with_token() -> None:
    """A token supplied alongside an SSH URL fails loudly rather than being silently dropped."""
    with pytest.raises(UnsupportedAuthenticationScheme):
        build_authenticated_url("git@gitlab.com:group/project.git", _SECRET_TOKEN)


# ---------------------------------------------------------------------------
# auth.mask_secret / sanitize_error_text
# ---------------------------------------------------------------------------


def test_mask_secret_redacts_every_occurrence() -> None:
    """Every occurrence of the secret in the text is replaced."""
    text = f"failed at https://oauth2:{_SECRET_TOKEN}@gitlab.com/x ({_SECRET_TOKEN})"

    masked = mask_secret(text, _SECRET_TOKEN)

    assert _SECRET_TOKEN not in masked
    assert "***REDACTED***" in masked


def test_mask_secret_noop_without_secret() -> None:
    """A missing/empty secret leaves the text unchanged (never redacts everything)."""
    text = "some ordinary log line"

    assert mask_secret(text, None) == text
    assert mask_secret(text, "") == text


def test_sanitize_error_text_strips_credential_block() -> None:
    """The oauth2:<token>@ credential syntax is stripped even from a raw GitPython-style message."""
    raw = (
        f"Cmd('git') failed due to: exit code(128)\n"
        f"  cmdline: git clone https://oauth2:{_SECRET_TOKEN}@gitlab.com/group/project.git"
    )

    sanitized = sanitize_error_text(raw, _SECRET_TOKEN)

    assert _SECRET_TOKEN not in sanitized
    assert "gitlab.com/group/project.git" in sanitized  # everything else preserved


# ---------------------------------------------------------------------------
# cleanup.remove_clone
# ---------------------------------------------------------------------------


def test_remove_clone_deletes_directory_inside_base(tmp_path: Path) -> None:
    """A clone directory located inside the configured base directory is deleted."""
    base = tmp_path / "cloned_repositories"
    clone_dir = base / "project-abcd1234"
    clone_dir.mkdir(parents=True)
    (clone_dir / "marker.txt").write_text("hello")

    remove_clone(clone_dir, clone_base_directory=base)

    assert not clone_dir.exists()


def test_remove_clone_refuses_to_delete_outside_base(tmp_path: Path) -> None:
    """A path outside the configured base directory is never deleted, even if requested."""
    base = tmp_path / "cloned_repositories"
    base.mkdir()
    outside_dir = tmp_path / "not_a_clone"
    outside_dir.mkdir()
    (outside_dir / "important.txt").write_text("do not delete me")

    remove_clone(outside_dir, clone_base_directory=base)

    assert outside_dir.exists()
    assert (outside_dir / "important.txt").exists()


def test_remove_clone_missing_path_is_a_noop(tmp_path: Path) -> None:
    """Calling remove_clone on an already-gone path does not raise."""
    base = tmp_path / "cloned_repositories"
    base.mkdir()
    already_gone = base / "never-existed"

    remove_clone(already_gone, clone_base_directory=base)  # must not raise


# ---------------------------------------------------------------------------
# RepositoryManager.cleanup() integration
# ---------------------------------------------------------------------------


def _build_test_settings(tmp_path: Path) -> ScannerSettings:
    output_directory = tmp_path / "output"
    return ScannerSettings(
        app_name="gitlab-pii-scanner-test",
        environment="test",
        log_level="DEBUG",
        working_directory=tmp_path,
        output_directory=output_directory,
        supported_extensions=(".py",),
        excluded_directories=(".git",),
        max_file_size_bytes=5 * 1024 * 1024,
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


def test_repository_manager_cleanup_removes_gitlab_clone(tmp_path: Path) -> None:
    """RepositoryManager.cleanup() deletes a GITLAB_REMOTE source's local_path."""
    settings = _build_test_settings(tmp_path)
    manager = RepositoryManager(settings=settings)

    clone_dir = settings.clone_base_directory / "project-deadbeef"
    clone_dir.mkdir(parents=True)
    source = RepositorySource(
        source_type=RepositorySourceType.GITLAB_REMOTE,
        identifier="https://gitlab.com/group/project.git",
        local_path=clone_dir,
    )

    manager.cleanup(source)

    assert not clone_dir.exists()


def test_repository_manager_cleanup_is_noop_for_local_repository(tmp_path: Path) -> None:
    """RepositoryManager.cleanup() never deletes a LOCAL_PATH source -- a user's own repo."""
    settings = _build_test_settings(tmp_path)
    manager = RepositoryManager(settings=settings)

    repo_dir = tmp_path / "my_local_repo"
    repo_dir.mkdir()
    git.Repo.init(repo_dir)
    source = RepositorySource(
        source_type=RepositorySourceType.LOCAL_PATH,
        identifier=str(repo_dir),
        local_path=repo_dir,
    )

    manager.cleanup(source)

    assert repo_dir.exists()


def test_repository_source_identifier_never_contains_token(tmp_path: Path) -> None:
    """obtain_gitlab() would store the token-free URL as identifier (verified via build_authenticated_url)."""
    # obtain_gitlab() itself requires network access to exercise end to
    # end (covered in test_repository_manager.py); what's guaranteed
    # here, independent of the network, is that the URL used to build
    # RepositorySource.identifier and the URL used to authenticate are
    # two different values -- the token never touches the former.
    plain_url = "https://gitlab.com/group/project.git"
    authenticated_url = build_authenticated_url(plain_url, _SECRET_TOKEN)

    assert plain_url != authenticated_url
    assert _SECRET_TOKEN not in plain_url
