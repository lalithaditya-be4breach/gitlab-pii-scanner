"""
scanner.gitlab
==============

GitLab repository provider: authentication, cloning, and post-scan
cleanup for remote GitLab repositories.

`RepositoryManager` (in `scanner/repository_manager.py`) is the only
intended caller of this package. It remains the single entry point
`main.py` and every other module talk to for obtaining a repository
to scan, regardless of source.

Public surface:
    - `GitLabRepositoryProvider` — clones a GitLab repository,
      optionally authenticating with a Personal Access Token.
    - `build_authenticated_url` / `sanitize_error_text` — token
      handling, kept small and isolated since they touch secrets.
    - `remove_clone` — deletes a temporary clone after scanning,
      restricted to paths inside the configured clone base directory.
"""

from __future__ import annotations

from scanner.gitlab.auth import (
    UnsupportedAuthenticationScheme,
    build_authenticated_url,
    mask_secret,
    sanitize_error_text,
)
from scanner.gitlab.cleanup import remove_clone
from scanner.gitlab.provider import GitLabRepositoryProvider, RepositoryProvider

__all__ = [
    "GitLabRepositoryProvider",
    "RepositoryProvider",
    "UnsupportedAuthenticationScheme",
    "build_authenticated_url",
    "mask_secret",
    "remove_clone",
    "sanitize_error_text",
]
