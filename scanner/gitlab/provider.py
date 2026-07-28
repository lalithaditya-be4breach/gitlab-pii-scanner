"""
provider.py
===========

`RepositoryProvider` abstraction and the GitLab implementation of it.

Today `RepositoryManager` only ever obtains repositories from two
places: the local disk, or GitLab. This module exists so that adding
a *third* place later (GitHub, Azure Repos, Bitbucket — all mentioned
as "tomorrow" in the project's requirements) means writing one new
class that implements `RepositoryProvider`, not touching the scan
engine, risk engine, reports, or any other already-stable module.

`RepositoryManager` (in `scanner/repository_manager.py`) is still the
single place `main.py` and every other caller talks to — this module
only supplies the GitLab-specific mechanics `RepositoryManager`
delegates to for the "gitlab" branch of its `obtain_gitlab()` method.
Nothing outside `scanner/gitlab/` needs to import from here directly.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from scanner.gitlab.auth import build_authenticated_url
from scanner.gitlab.clone import clone as _run_clone


class RepositoryProvider(Protocol):
    """
    What `RepositoryManager` needs from any remote repository source.

    A future `GitHubRepositoryProvider`, `AzureReposProvider`, or
    `BitbucketRepositoryProvider` would implement this same, small
    surface. `RepositoryManager` (or a future provider registry keyed
    by hostname/URL prefix, should more than one remote source be
    supported at once) can then treat every remote source uniformly,
    exactly as it already treats `LOCAL_PATH` vs `GITLAB_REMOTE`
    uniformly via `RepositorySource`.
    """

    def clone(
        self,
        url: str,
        destination: Path,
        *,
        branch: str | None = None,
        token: str | None = None,
        shallow_depth: int = 0,
    ) -> None:
        """Clone `url` into `destination`, authenticating with `token` if given."""
        ...  # pragma: no cover - Protocol method body


class GitLabRepositoryProvider:
    """
    `RepositoryProvider` implementation for GitLab (and GitLab-compatible
    Git hosts reachable over plain HTTPS clone URLs).

    This class does not validate URLs or translate low-level Git
    errors into the scanner's exception types — `RepositoryManager`
    still owns that, exactly as it did before GitLab authentication
    support was added, so existing error-handling/tests keep working
    unchanged. This class's only job is: given a URL, a destination,
    and an optional token, produce a clone on disk.
    """

    def clone(
        self,
        url: str,
        destination: Path,
        *,
        branch: str | None = None,
        token: str | None = None,
        shallow_depth: int = 0,
    ) -> None:
        """
        Clone a GitLab repository, injecting `token` for authentication if given.

        Args:
            url: The plain (token-free) HTTPS or SSH clone URL. This
                is the value that ends up in logs, reports, and
                `RepositorySource.identifier` — it never contains a
                credential.
            destination: Directory to clone into.
            branch: Optional branch to check out.
            token: Optional GitLab Personal Access Token for private
                repositories. Embedded into the clone URL used for
                this call only; never returned, stored, or logged by
                this method.
            shallow_depth: If > 0, requests a shallow clone of this depth.

        Raises:
            scanner.gitlab.auth.UnsupportedAuthenticationScheme: if
                `token` is supplied alongside a non-HTTP(S) URL.
            git.exc.GitCommandError: on any Git-level clone failure.
        """
        authenticated_url = build_authenticated_url(url, token)
        _run_clone(
            authenticated_url,
            destination,
            branch=branch,
            shallow_depth=shallow_depth,
        )
