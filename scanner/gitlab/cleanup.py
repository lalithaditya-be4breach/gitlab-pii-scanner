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

Python 3.11 vs. 3.12+ compatibility
------------------------------------
`shutil.rmtree()`'s error-handling hook changed its keyword and its
callback signature in Python 3.12:

  - Python 3.12+: `onexc=callback`, and `callback(func, path, exc)` is
    called with the exception *instance*.
  - Python <3.12 (including 3.11): `onerror=callback` (the modern
    `onexc` keyword doesn't exist yet), and
    `callback(func, path, exc_info)` is called with a
    `sys.exc_info()`-style `(type, value, traceback)` *tuple*, not an
    exception instance.

This project's minimum supported version includes 3.11, so both
keywords must be supported. Rather than branching the retry logic
itself, `_clear_readonly_and_retry()` stays the single source of
truth for "clear read-only and retry, or re-raise anything else,"
and takes the exception instance directly. `_onerror_shim()` adapts
the legacy `(type, value, traceback)` tuple down to that same
instance so both code paths share identical behaviour. Which keyword
`remove_clone()` passes to `shutil.rmtree()` is chosen once, at call
time, based on the running interpreter's version.
"""

from __future__ import annotations

import os
import shutil
import stat
import sys
from pathlib import Path

from scanner.logger import get_logger

logger = get_logger(__name__)

# `shutil.rmtree(onexc=...)` was added in Python 3.12; before that,
# only the legacy `onerror=...` keyword (with a different callback
# signature) is available.
_HAS_ONEXC = sys.version_info[:2] >= (3, 12)


def _clear_readonly_and_retry(func, path, exc: BaseException) -> None:
    """
    Shared retry handler: clear a read-only attribute and retry.

    This is the single source of truth for the "clear read-only and
    retry, or re-raise anything else" behaviour, called from both the
    Python 3.12+ `onexc` path and the Python <3.12 `onerror` path
    (via `_onerror_shim`, which adapts the legacy callback signature
    down to this one).

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


def _onerror_shim(func, path, exc_info) -> None:
    """
    `shutil.rmtree(onerror=...)` handler for Python <3.12.

    The legacy `onerror` callback receives a `sys.exc_info()`-style
    `(type, value, traceback)` tuple instead of the exception
    instance that `onexc` (3.12+) receives. This adapts that tuple
    down to the instance and delegates to `_clear_readonly_and_retry`
    so both code paths share identical retry behaviour.

    Args:
        func: The function that raised (e.g. `os.unlink`).
        path: The specific path that failed to be removed.
        exc_info: The `(type, value, traceback)` tuple `shutil.rmtree()`
            passes on Python <3.12.
    """
    _clear_readonly_and_retry(func, path, exc_info[1])


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
        # Python 3.12+ provides the modern, non-deprecated `onexc`
        # hook (exception instance). Python 3.11 only has the legacy
        # `onerror` hook (a `sys.exc_info()` tuple), so we fall back
        # to it there via `_onerror_shim`, which adapts the tuple down
        # to the same exception instance `_clear_readonly_and_retry`
        # expects — identical behaviour on both versions.
        if _HAS_ONEXC:
            shutil.rmtree(resolved_path, onexc=_clear_readonly_and_retry)
        else:
            shutil.rmtree(resolved_path, onerror=_onerror_shim)
        logger.info("Deleted temporary clone: %s", resolved_path)
    except OSError as exc:
        logger.warning("Failed to delete temporary clone %s: %s", resolved_path, exc)