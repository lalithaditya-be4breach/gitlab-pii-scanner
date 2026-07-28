"""
auth.py
=======

Credential handling for cloning private GitLab repositories.

This module has exactly two responsibilities, kept small and isolated
on purpose because they touch secrets:

    1. `build_authenticated_url()` — turn a plain HTTPS clone URL plus
       a GitLab Personal Access Token (PAT) into a URL Git can use to
       authenticate, without the caller having to know GitLab's
       credential convention.

    2. `mask_secret()` / `sanitize_error_text()` — make sure a token
       can never leak into a log line, an exception message, or a
       report, even if some lower-level library (GitPython, the `git`
       CLI) echoes the full remote URL back in an error.

Nothing in this module logs anything. Callers are responsible for only
ever logging the *sanitized* text this module returns.
"""

from __future__ import annotations

from urllib.parse import urlparse, urlunparse

# GitLab accepts any non-empty username with a PAT as the password over
# HTTPS; "oauth2" is the conventional username GitLab's own docs and CI
# templates use (see GITLAB_CI's `CI_JOB_TOKEN` usage), so we mirror it
# for familiarity rather than inventing our own convention.
_GITLAB_TOKEN_USERNAME = "oauth2"

_REDACTED = "***REDACTED***"  # noqa: S105 - not a secret, a placeholder label


class UnsupportedAuthenticationScheme(Exception):
    """Raised when a token is supplied for a URL that can't carry HTTP auth."""


def build_authenticated_url(url: str, token: str | None) -> str:
    """
    Return a clone URL with `token` embedded, or `url` unchanged if no token.

    Args:
        url: The plain HTTPS clone URL, e.g.
            "https://gitlab.com/group/project.git". Never returned
            with credentials if `token` is falsy.
        token: A GitLab Personal Access Token, or None/empty for a
            public repository.

    Returns:
        A URL suitable for `git clone`, with the token embedded as
        HTTP Basic auth credentials when provided.

    Raises:
        UnsupportedAuthenticationScheme: if a token is supplied for a
            non-HTTP(S) URL (e.g. an SSH URL). SSH authenticates via
            keys, not tokens, so silently ignoring the token would be
            more surprising than failing loudly.
    """
    if not token:
        return url

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise UnsupportedAuthenticationScheme(
            "A GitLab token can only be used with an http(s):// clone URL, "
            f"got scheme {parsed.scheme!r}. SSH URLs authenticate via SSH "
            "keys instead — omit the token and configure a deploy key."
        )

    netloc = f"{_GITLAB_TOKEN_USERNAME}:{token}@{parsed.hostname}"
    if parsed.port:
        netloc += f":{parsed.port}"

    return urlunparse(parsed._replace(netloc=netloc))


def mask_secret(text: str, secret: str | None) -> str:
    """
    Replace every occurrence of `secret` in `text` with a redaction marker.

    Safe to call unconditionally: if `secret` is falsy, `text` is
    returned unchanged rather than attempting to redact an empty
    string (which would otherwise match everywhere).

    Args:
        text: Text that might contain the secret (e.g. an exception
            message that echoed back an authenticated clone URL).
        secret: The token value to redact, or None/empty to skip.

    Returns:
        `text` with every occurrence of `secret` replaced.
    """
    if not secret or not text:
        return text
    return text.replace(secret, _REDACTED)


def sanitize_error_text(text: str, token: str | None) -> str:
    """
    Best-effort cleanup of an error message before it is logged or raised.

    In addition to masking the raw `token` value (see `mask_secret`),
    this also strips any `oauth2:...@` credential block that may have
    survived in a different form (e.g. URL-encoded), so a malformed or
    partially-matching token still doesn't leak the surrounding
    credential syntax.

    Args:
        text: The raw error text to sanitize.
        token: The token that was used for this clone attempt, if any.

    Returns:
        Sanitized text, safe to log or include in a raised exception.
    """
    sanitized = mask_secret(text, token)
    if token:
        # Catches "https://oauth2:<token>@host/..." even if `token`
        # itself only partially matched above (e.g. due to shell/URL
        # re-encoding of special characters by an intermediate layer).
        sanitized = sanitized.replace(f"{_GITLAB_TOKEN_USERNAME}:{token}@", f"{_REDACTED}@")
    return sanitized
