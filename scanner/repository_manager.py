"""
repository_manager.py
======================

Phase 2: Repository Manager.

Single entry point for obtaining a repository to scan, regardless of
whether it already exists on the local disk or needs to be cloned
from GitLab first. Every later phase (file traversal, Presidio
integration, reporting) should only ever depend on the
`RepositorySource` this module returns — never on *how* the repository
was obtained.

Design:
    - `RepositoryManager.obtain_local(path)`
      Validates that `path` exists, is a directory, and is a genuine
      (non-bare) Git repository.

    - `RepositoryManager.obtain_gitlab(url, branch=None)`
      Validates the URL, clones the repository (via GitPython — no
      shelling out to the `git` CLI) into a unique directory under
      `settings.clone_base_directory`, optionally checking out a
      specific branch, and returns the cloned path.

    - `RepositoryManager.obtain(local_path=None, gitlab_url=None, branch=None)`
      Convenience dispatcher: exactly one of `local_path` / `gitlab_url`
      must be provided.

Both paths return a `scanner.models.RepositorySource`, so downstream
code has a single, uniform type to work with no matter where the
repository came from.
"""

from __future__ import annotations

import shutil
import uuid
from pathlib import Path
from urllib.parse import urlparse

import git
from git.exc import GitCommandError, InvalidGitRepositoryError, NoSuchPathError

from scanner.config import ScannerSettings, get_settings
from scanner.logger import get_logger
from scanner.models import RepositorySource, RepositorySourceType
from scanner.utils import ensure_directory

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------


class RepositoryManagerError(Exception):
    """Base class for all errors raised by the Repository Manager."""


class RepositoryNotFound(RepositoryManagerError):
    """Raised when a local repository path does not exist on disk."""


class InvalidRepository(RepositoryManagerError):
    """
    Raised when a local path exists but is not usable as a repository.

    Examples: the path is a file (not a directory), the directory is
    not a Git repository, or it is a bare repository with no working
    tree to scan.
    """


class InvalidRepositoryURL(RepositoryManagerError):
    """Raised when a GitLab repository URL is malformed or unsupported."""


class CloneFailed(RepositoryManagerError):
    """Raised when cloning a GitLab repository fails for a generic reason."""


class AuthenticationFailed(CloneFailed):
    """Raised when cloning fails because of missing/invalid credentials."""


class BranchNotFound(CloneFailed):
    """Raised when the requested branch does not exist on the remote."""


# ---------------------------------------------------------------------------
# Repository Manager
# ---------------------------------------------------------------------------


class RepositoryManager:
    """
    Obtains a repository to scan from either a local path or a GitLab URL.

    Instances are cheap and stateless aside from configuration; the
    typical usage is to construct one per run (or reuse a shared one)
    and call `obtain_local()` / `obtain_gitlab()` / `obtain()`.
    """

    def __init__(self, settings: ScannerSettings | None = None) -> None:
        """
        Args:
            settings: Optional explicit settings object. Defaults to the
                process-wide singleton from `scanner.config.get_settings()`.
        """
        self._settings = settings or get_settings()

    # -- Local repositories --------------------------------------------------

    def obtain_local(self, path: Path) -> RepositorySource:
        """
        Validate a local directory as a usable Git repository.

        Args:
            path: Path to the local repository.

        Returns:
            A `RepositorySource` describing the validated repository.

        Raises:
            RepositoryNotFound: if `path` does not exist.
            InvalidRepository: if `path` exists but is not a directory,
                is not a Git repository, or is a bare repository.
        """
        resolved_path = path.expanduser().resolve()
        logger.info("Validating local repository: %s", resolved_path)

        if not resolved_path.exists():
            raise RepositoryNotFound(f"Path does not exist: {resolved_path}")

        if not resolved_path.is_dir():
            raise InvalidRepository(
                f"Path exists but is not a directory: {resolved_path}"
            )

        try:
            repo = git.Repo(resolved_path, search_parent_directories=False)
        except (InvalidGitRepositoryError, NoSuchPathError) as exc:
            raise InvalidRepository(
                f"Not a valid Git repository: {resolved_path}"
            ) from exc

        if repo.bare:
            raise InvalidRepository(
                f"Repository is bare (no working tree to scan): {resolved_path}"
            )

        logger.info("Local repository validated successfully: %s", resolved_path)
        return RepositorySource(
            source_type=RepositorySourceType.LOCAL_PATH,
            identifier=str(resolved_path),
            local_path=resolved_path,
        )

    # -- GitLab repositories --------------------------------------------------

    def obtain_gitlab(self, url: str, branch: str | None = None) -> RepositorySource:
        """
        Clone a GitLab (or any Git-compatible) repository and return its path.

        Args:
            url: HTTPS or SSH clone URL, e.g.
                "https://gitlab.com/group/project.git" or
                "git@gitlab.com:group/project.git".
            branch: Optional branch to check out. Defaults to the
                repository's default branch when omitted.

        Returns:
            A `RepositorySource` pointing at the cloned repository.

        Raises:
            InvalidRepositoryURL: if `url` is malformed or uses an
                unsupported scheme.
            AuthenticationFailed: if the remote rejected credentials
                (e.g. a private repository with no/invalid access).
            BranchNotFound: if the requested branch does not exist.
            CloneFailed: for any other cloning failure (network errors,
                unreachable host, repository does not exist, etc.).
        """
        self._validate_url(url)

        destination = self._new_clone_destination(url)
        logger.info(
            "Cloning repository %s%s into %s",
            url,
            f" (branch={branch})" if branch else "",
            destination,
        )

        clone_kwargs: dict[str, object] = {
            # Never let Git prompt interactively for credentials; a
            # missing/invalid credential should fail fast instead of
            # hanging the process waiting for terminal input.
            "env": {"GIT_TERMINAL_PROMPT": "0"},
        }
        if branch:
            clone_kwargs["branch"] = branch
        if self._settings.clone_shallow_depth > 0:
            clone_kwargs["depth"] = self._settings.clone_shallow_depth

        try:
            git.Repo.clone_from(url, destination, **clone_kwargs)
        except GitCommandError as exc:
            self._cleanup_failed_clone(destination)
            raise self._translate_clone_error(exc, url=url, branch=branch) from exc
        except Exception as exc:  # noqa: BLE001 - translate any unexpected failure
            self._cleanup_failed_clone(destination)
            raise CloneFailed(
                f"Unexpected error while cloning {url!r}: {exc}"
            ) from exc

        logger.info("Repository cloned successfully: %s", destination)
        return RepositorySource(
            source_type=RepositorySourceType.GITLAB_REMOTE,
            identifier=url,
            local_path=destination,
        )

    # -- Dispatcher -----------------------------------------------------------

    def obtain(
        self,
        *,
        local_path: Path | None = None,
        gitlab_url: str | None = None,
        branch: str | None = None,
    ) -> RepositorySource:
        """
        Obtain a repository from exactly one source.

        Args:
            local_path: A local repository path (mutually exclusive
                with `gitlab_url`).
            gitlab_url: A GitLab clone URL (mutually exclusive with
                `local_path`).
            branch: Optional branch, only meaningful with `gitlab_url`.

        Returns:
            A `RepositorySource` from either `obtain_local()` or
            `obtain_gitlab()`.

        Raises:
            ValueError: if both or neither of `local_path` /
                `gitlab_url` are provided.
        """
        if (local_path is None) == (gitlab_url is None):
            raise ValueError(
                "Exactly one of 'local_path' or 'gitlab_url' must be provided."
            )

        if local_path is not None:
            return self.obtain_local(local_path)

        assert gitlab_url is not None  # narrowed by the check above
        return self.obtain_gitlab(gitlab_url, branch=branch)

    # -- Internal helpers -------------------------------------------------------

    @staticmethod
    def _validate_url(url: str) -> None:
        """Raise InvalidRepositoryURL if `url` is not a usable Git URL."""
        if not url or not url.strip():
            raise InvalidRepositoryURL("Repository URL must not be empty.")

        # SSH-style URLs (e.g. git@gitlab.com:group/project.git) don't
        # parse cleanly with urlparse's scheme detection, so they're
        # accepted based on a simple, explicit pattern instead.
        if url.startswith("git@") and ":" in url:
            return

        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https", "ssh", "git"}:
            raise InvalidRepositoryURL(
                f"Unsupported or missing URL scheme in {url!r}. "
                "Expected one of: http, https, ssh, git, or an "
                "SSH shorthand like 'git@host:group/project.git'."
            )
        if not parsed.netloc:
            raise InvalidRepositoryURL(f"Repository URL is missing a host: {url!r}")

    def _new_clone_destination(self, url: str) -> Path:
        """Build a unique destination directory for a fresh clone."""
        repo_name = url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git") or "repository"
        unique_suffix = uuid.uuid4().hex[:8]
        destination = self._settings.clone_base_directory / f"{repo_name}-{unique_suffix}"
        ensure_directory(self._settings.clone_base_directory)
        return destination

    @staticmethod
    def _cleanup_failed_clone(destination: Path) -> None:
        """Remove a partially-cloned directory left behind by a failed clone."""
        if destination.exists():
            shutil.rmtree(destination, ignore_errors=True)

    @staticmethod
    def _translate_clone_error(
        exc: GitCommandError, *, url: str, branch: str | None
    ) -> RepositoryManagerError:
        """Map a low-level GitCommandError to a specific, meaningful exception."""
        message = str(exc).lower()

        if branch and (
            "remote branch" in message
            or "not found in upstream" in message
            or "couldn't find remote ref" in message
        ):
            return BranchNotFound(
                f"Branch {branch!r} was not found on remote repository {url!r}."
            )

        if any(
            marker in message
            for marker in (
                "authentication failed",
                "could not read username",
                "could not read password",
                "permission denied",
                "403",
            )
        ):
            return AuthenticationFailed(
                f"Authentication failed while cloning {url!r}. "
                "Verify credentials/access rights for this repository."
            )

        if "repository not found" in message or "not found" in message:
            return CloneFailed(
                f"Repository not found or inaccessible: {url!r}"
            )

        return CloneFailed(f"Failed to clone {url!r}: {exc}")
