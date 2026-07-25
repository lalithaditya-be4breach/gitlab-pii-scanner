"""
test_repository_manager.py
===========================

Tests for Phase 2's RepositoryManager, covering:
    - valid local repository
    - invalid local repository (not a git repo, non-existent, a file, bare)
    - valid remote repository (clone)
    - invalid remote repository URL
    - invalid branch

Note on network tests
----------------------
Cloning tests use a small, stable public repository on GitHub rather
than GitLab. GitPython/Git's cloning behaviour is host-agnostic — the
exact same `git.Repo.clone_from()` code path in `repository_manager.py`
is used for gitlab.com, github.com, or any other Git host. GitHub is
used here only because it is reachable from this test environment;
nothing in `RepositoryManager` is GitHub- or GitLab-specific.
Network-dependent tests are skipped automatically if the network is
unavailable, so the rest of the suite still runs offline.
"""

from __future__ import annotations

import socket
from pathlib import Path

import git
import pytest

from scanner.config import ScannerSettings
from scanner.models import RepositorySourceType
from scanner.repository_manager import (
    AuthenticationFailed,
    BranchNotFound,
    CloneFailed,
    InvalidRepository,
    InvalidRepositoryURL,
    RepositoryManager,
    RepositoryNotFound,
)

# A small, stable, public repository used only to exercise the generic
# clone code path (see module docstring above).
_PUBLIC_TEST_REPO_URL = "https://github.com/octocat/Hello-World.git"


def _network_available(host: str = "github.com", port: int = 443) -> bool:
    """Best-effort check for outbound network access, used to skip clone tests."""
    try:
        with socket.create_connection((host, port), timeout=3):
            return True
    except OSError:
        return False


def _build_test_settings(tmp_path: Path) -> ScannerSettings:
    """Construct a ScannerSettings instance pointed entirely at a tmp_path sandbox."""
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
    )


@pytest.fixture
def manager(tmp_path: Path) -> RepositoryManager:
    """A RepositoryManager backed by isolated, temporary settings."""
    return RepositoryManager(settings=_build_test_settings(tmp_path))


# ---------------------------------------------------------------------------
# Local repository tests
# ---------------------------------------------------------------------------


def test_obtain_local_valid_repository(manager: RepositoryManager, tmp_path: Path) -> None:
    """A directory that is a real, non-bare Git repository is accepted."""
    repo_dir = tmp_path / "valid_repo"
    repo_dir.mkdir()
    git.Repo.init(repo_dir)

    source = manager.obtain_local(repo_dir)

    assert source.source_type == RepositorySourceType.LOCAL_PATH
    assert source.local_path == repo_dir.resolve()


def test_obtain_local_nonexistent_path(manager: RepositoryManager, tmp_path: Path) -> None:
    """A path that does not exist raises RepositoryNotFound."""
    missing_path = tmp_path / "does_not_exist"

    with pytest.raises(RepositoryNotFound):
        manager.obtain_local(missing_path)


def test_obtain_local_path_is_a_file(manager: RepositoryManager, tmp_path: Path) -> None:
    """A path that points at a file (not a directory) raises InvalidRepository."""
    file_path = tmp_path / "not_a_directory.txt"
    file_path.write_text("this is a file, not a repository")

    with pytest.raises(InvalidRepository):
        manager.obtain_local(file_path)


def test_obtain_local_not_a_git_repository(manager: RepositoryManager, tmp_path: Path) -> None:
    """A directory that exists but has no .git metadata raises InvalidRepository."""
    plain_dir = tmp_path / "plain_folder"
    plain_dir.mkdir()

    with pytest.raises(InvalidRepository):
        manager.obtain_local(plain_dir)


def test_obtain_local_bare_repository(manager: RepositoryManager, tmp_path: Path) -> None:
    """A bare repository (no working tree) raises InvalidRepository."""
    bare_repo_dir = tmp_path / "bare_repo"
    bare_repo_dir.mkdir()
    git.Repo.init(bare_repo_dir, bare=True)

    with pytest.raises(InvalidRepository):
        manager.obtain_local(bare_repo_dir)


# ---------------------------------------------------------------------------
# GitLab / remote repository tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_url",
    [
        "",
        "   ",
        "not-a-url-at-all",
        "ftp://gitlab.com/group/project.git",
        "https://",
    ],
)
def test_obtain_gitlab_invalid_url(
    manager: RepositoryManager, bad_url: str
) -> None:
    """Malformed or unsupported URLs raise InvalidRepositoryURL before any network call."""
    with pytest.raises(InvalidRepositoryURL):
        manager.obtain_gitlab(bad_url)


def test_obtain_gitlab_ssh_style_url_is_accepted_as_valid_format(
    manager: RepositoryManager,
) -> None:
    """SSH-shorthand URLs are recognized as a valid format (network not required to reach this)."""
    # This will still attempt a clone and likely fail without SSH keys
    # configured in this environment; we only assert it gets past URL
    # validation and fails later with a CloneFailed-family error rather
    # than InvalidRepositoryURL.
    with pytest.raises(CloneFailed):
        manager.obtain_gitlab("git@gitlab.com:nonexistent/should-not-exist.git")


@pytest.mark.skipif(
    not _network_available(), reason="No outbound network access in this environment."
)
def test_obtain_gitlab_valid_repository_clones_successfully(
    manager: RepositoryManager,
) -> None:
    """A valid, public repository URL clones successfully and returns its path."""
    source = manager.obtain_gitlab(_PUBLIC_TEST_REPO_URL)

    assert source.source_type == RepositorySourceType.GITLAB_REMOTE
    assert source.local_path.exists()
    assert (source.local_path / ".git").exists()


@pytest.mark.skipif(
    not _network_available(), reason="No outbound network access in this environment."
)
def test_obtain_gitlab_invalid_branch_raises_branch_not_found(
    manager: RepositoryManager,
) -> None:
    """Requesting a branch that does not exist on the remote raises BranchNotFound."""
    with pytest.raises(BranchNotFound):
        manager.obtain_gitlab(
            _PUBLIC_TEST_REPO_URL, branch="this-branch-does-not-exist-12345"
        )


@pytest.mark.skipif(
    not _network_available(), reason="No outbound network access in this environment."
)
def test_obtain_gitlab_nonexistent_repository_raises_clone_failed(
    manager: RepositoryManager,
) -> None:
    """A syntactically valid URL pointing at a repository that doesn't exist fails to clone."""
    with pytest.raises(CloneFailed):
        manager.obtain_gitlab(
            "https://github.com/this-org-should-not-exist-xyz/nope.git"
        )


# ---------------------------------------------------------------------------
# Dispatcher tests
# ---------------------------------------------------------------------------


def test_obtain_requires_exactly_one_source(manager: RepositoryManager, tmp_path: Path) -> None:
    """Calling obtain() with neither or both sources raises ValueError."""
    with pytest.raises(ValueError):
        manager.obtain()

    with pytest.raises(ValueError):
        manager.obtain(local_path=tmp_path, gitlab_url=_PUBLIC_TEST_REPO_URL)


def test_obtain_dispatches_to_local(manager: RepositoryManager, tmp_path: Path) -> None:
    """obtain() routes to obtain_local() when local_path is provided."""
    repo_dir = tmp_path / "dispatch_repo"
    repo_dir.mkdir()
    git.Repo.init(repo_dir)

    source = manager.obtain(local_path=repo_dir)

    assert source.source_type == RepositorySourceType.LOCAL_PATH
