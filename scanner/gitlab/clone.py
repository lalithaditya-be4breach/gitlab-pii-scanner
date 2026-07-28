"""
clone.py
========

Low-level Git clone execution for the GitLab provider.

This module knows how to run a single `git clone` (via GitPython, the
same dependency the project already used before this feature) and
nothing else. It doesn't know about GitLab, URL validation, exception
translation, or cleanup — those live in `repository_manager.py`
(orchestration + error translation, unchanged in spirit from before
this feature) and `cleanup.py` (deletion) respectively.

Keeping this module this thin is deliberate: it's the one place that
actually shells out to Git with a URL that may contain embedded
credentials, so the less it does, the smaller the surface area for a
credential to accidentally end up somewhere it shouldn't (a log line,
a stored variable, a report).

Handle lifecycle
----------------
`git.Repo.clone_from()` does not just run `git clone` and hand back a
plain path — it returns a live `git.Repo` object, and constructing
that object opens resources on disk:

    - A `git.cmd.Git` command wrapper.
    - A `GitCmdObjectDB` object database, which memory-maps (`mmap`)
      the repository's pack index/pack files (the
      `.git/objects/pack/pack-*.idx` / `.pack` files) the first time
      anything touches them, for fast object lookup.

Nothing before this change ever kept a reference to that `Repo`
object, but "unreferenced" is not the same as "released": GitPython
and its `gitdb` dependency hold these mmap handles in a small
internal cache with reference cycles, so CPython's ordinary
refcounting does not free them the moment the `Repo` object goes out
of scope. On Linux this is harmless — the OS allows deleting a file
out from under an open handle or mapping. On Windows it is fatal to a
later `shutil.rmtree()`: Windows refuses to delete a file that is
still memory-mapped, which is exactly the `WinError 5 - Access is
denied` seen on `pack-*.idx` files.

`git.Repo` exposes `close()` for precisely this reason — it clears
the command cache and explicitly drops the mmap manager's cached
mappings (calling `gc.collect()` on Windows first, since that's what
it takes to break the reference cycles keeping those mappings alive).
This module now calls it deterministically, in a `finally` block,
before `clone()` returns — so the handle is released here, at the
one place it was opened, rather than leaking into `cleanup.py` or
relying on the garbage collector's timing.
"""

from __future__ import annotations

from pathlib import Path
from venv import logger

import git


def clone(
    authenticated_url: str,
    destination: Path,
    *,
    branch: str | None = None,
    shallow_depth: int = 0,
) -> None:
    """
    Clone a repository with GitPython.

    Args:
        authenticated_url: The URL to clone, already carrying any
            required credentials (see `auth.build_authenticated_url`).
            This function does not log this value.
        destination: Directory to clone into. Must not already exist.
        branch: Optional branch to check out. Omit for the remote's
            default branch.
        shallow_depth: If > 0, passed to Git as `--depth`. 0 requests
            a full clone.

    Raises:
        git.exc.GitCommandError: on any Git-level failure (bad
            credentials, missing branch, unreachable host, repository
            not found, etc.). Translating this into a specific,
            GitLab-scanner exception type is the caller's job — this
            function stays a thin, honest wrapper around GitPython.

    Note:
        This function intentionally does not return the `git.Repo`
        object `clone_from()` produces. Callers only ever need the
        clone's *side effect* (files on disk at `destination`); they
        never need to run further Git commands against it. Keeping
        the `Repo` object's lifetime scoped entirely to this function
        means the handles it opens (see module docstring) are always
        released here, deterministically, rather than depending on
        every caller remembering to close a repo they never asked
        for.
    """
    clone_kwargs: dict[str, object] = {
        # Never let Git prompt interactively for credentials; a
        # missing/invalid credential should fail fast instead of
        # hanging the process waiting for terminal input that will
        # never come in an unattended pipeline.
        "env": {"GIT_TERMINAL_PROMPT": "0"},
    }
    if branch:
        clone_kwargs["branch"] = branch
    if shallow_depth > 0:
        clone_kwargs["depth"] = shallow_depth

    repo = git.Repo.clone_from(authenticated_url, destination, **clone_kwargs)
    try:
        # Nothing further is done with the clone here — this call
        # exists purely to release the mmap'd pack-file handles and
        # command-wrapper state opened by clone_from() (see module
        # docstring) before this function returns, instead of leaving
        # that to the garbage collector's timing.
        repo.close()
    except Exception as exc:
        logger.debug("Failed to close GitPython repository cleanly: %s", exc)