"""
cleanup.py
==========

Deletes temporary GitLab clones once a scan is finished.

The scanner must never permanently store a cloned repository, so every
successful `python main.py gitlab ...` run deletes its clone as its
last step (see `main.py`'s `finally` block). A failed clone is already
cleaned up by `repository_manager._cleanup_failed_clone`; this module
handles the "clone succeeded, scan ran (or failed), now delete it"
case.

This is intentionally a separate module from `repository_manager.py`
rather than another method on `RepositoryManager`, so it's obvious at
a glance that deletion is scoped to GitLab clones only — it is never
given a chance to touch a user's local repository.

Why deletion fails on Windows with `WinError 5`
------------------------------------------------
Git itself (the `git` binary, independent of GitPython) writes packed
and loose objects read-only, on every platform, for every clone —
public or private:

    -r--r--r--  .git/objects/pack/pack-<hash>.idx
    -r--r--r--  .git/objects/pack/pack-<hash>.pack
    -rw-r--r--  <ordinary working-tree file>

On Windows, mode `0444` becomes `FILE_ATTRIBUTE_READONLY`, and
`shutil.rmtree()` (via `os.unlink()` / `os.rmdir()`) has no built-in
handling for read-only files there — it raises
`PermissionError: [WinError 5] Access is denied` (`ERROR_ACCESS_DENIED`,
a permission problem) on exactly these files and no others. This is
unrelated to GitPython object handles, mmaps, or process lifetime,
which is why closing every `git.Repo` this codebase constructs
(`scanner/gitlab/clone.py`, `RepositoryManager.obtain_local()`) is
still correct hygiene but does not by itself fix this: there was
never a handle involved. It's why manual deletion via Windows
Explorer works (its delete path clears read-only attributes
transparently) while `shutil.rmtree()` does not, and why the failure
is identical for public and private repositories (the read-only bit
has nothing to do with auth).

`shutil.rmtree()` exposes an error-handling hook for exactly this
situation. `remove_clone()` uses it to clear the read-only attribute
on the one file that failed and retry only that specific operation,
synchronously and once — not a blind retry loop, and no sleeping.
"""

from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path

from scanner.logger import get_logger

logger = get_logger(__name__)


def _clear_readonly_and_retry(func, path, exc: BaseException) -> None:
    """
    `shutil.rmtree(onexc=...)` handler: clear a read-only attribute and retry.

    `shutil.rmtree()` calls this with the specific failing operation
    (`func`, one of `os.unlink`, `os.rmdir`, or `os.listdir`), the
    specific path that failed, and the exception instance raised. Git
    writes packed/loose objects read-only (see module docstring);
    this handler exists solely to correct that one, specific
    condition on that one, specific path.

    Args:
        func: The function that raised (e.g. `os.unlink`).
        path: The specific path that failed to be removed.
        exc: The exception raised by `func(path)`.

    Raises:
        BaseException: re-raises `exc` unchanged for anything other
            than a permission failure, so this handler never masks an
            unrelated error (a genuinely locked file, a missing path,
            a real permissions/ACL problem unrelated to the read-only
            attribute, etc.) — those still propagate out of
            `shutil.rmtree()` exactly as they would without this
            handler.
    """
    if not isinstance(exc, PermissionError):
        raise exc

    os.chmod(path, stat.S_IWRITE)
    func(path)


def remove_clone(path: Path, *, clone_base_directory: Path) -> None:
    """
    Delete a cloned repository directory, if it's safe to do so.

    Args:
        path: The cloned repository directory to remove.
        clone_base_directory: The configured base directory all
            clones are created under (`settings.clone_base_directory`).
            `path` is only ever deleted if it is actually located
            inside this directory — a deliberate guard so this
            function can never be pointed at an arbitrary path (e.g.
            a user's local repository) and delete it.

    This never raises: deletion failures are logged and swallowed,
    since a cleanup failure must not turn a successful scan into a
    failed pipeline run. Anthropic's design goal here mirrors the
    existing AI/Intelligence layers in `main.py`: best-effort,
    non-fatal.
    """
    try:
        resolved_path = path.resolve()
        resolved_base = clone_base_directory.resolve()
    except OSError as exc:
        logger.warning("Could not resolve clone path for cleanup: %s", exc)
        return

    if resolved_base not in resolved_path.parents and resolved_path != resolved_base:
        logger.warning(
            "Refusing to delete %s: it is not inside the configured clone "
            "base directory (%s). This should be unreachable in normal "
            "operation and indicates a misconfiguration.",
            resolved_path,
            resolved_base,
        )
        return

    if not resolved_path.exists():
        return

    try:
        # This project targets Python 3.12+ (see README.md), so the
        # modern, non-deprecated `onexc` hook is used here rather than
        # the legacy `onerror` (which passes a `sys.exc_info()` tuple
        # instead of the exception instance, and is deprecated as of
        # 3.12).
        shutil.rmtree(resolved_path, onexc=_clear_readonly_and_retry)
        logger.info("Deleted temporary clone: %s", resolved_path)
    except OSError as exc:
        logger.warning("Failed to delete temporary clone %s: %s", resolved_path, exc)