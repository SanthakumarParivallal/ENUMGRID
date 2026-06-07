"""
security.py — shared authorization guardrails for the web API.

The CLI (`purple_recon.py`) enforces a strict scope policy via `ScopeValidator`
(no loopback / multicast / broadcast / link-local / reserved space, plus a host
cap). Historically the FastAPI backend only ran a character-level anti-injection
regex, which meant the dashboard could be pointed at `127.0.0.1`, a public host,
or a huge CIDR — bypassing the project's headline safety guarantee.

This module closes that gap by reusing the *same* `ScopeValidator` for every web
entry point, and layers on three web-specific controls:

  * a public-target policy — internet-routable addresses are refused unless
    `ENUMGRID_ALLOW_PUBLIC=1` (there is no interactive "are you sure?" prompt
    over HTTP, so we fail safe);
  * a concurrency cap — at most `ENUMGRID_MAX_SCANS` scans run at once, so a
    burst of requests can't fork-bomb the host with nmap processes;
  * an optional bearer/token gate — enabled only when `ENUMGRID_API_TOKEN`
    is set, so the default localhost dev experience is unchanged.
"""

from __future__ import annotations

import asyncio
import hmac
import os
import sys

# Reuse the CLI's already-tested guardrails (one source of truth for scope).
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
from scanner import validate_target as _safe_chars  # noqa: E402

import purple_recon as pr  # noqa: E402  (path set above)


# --- policy knobs (all overridable via environment) ------------------------ #
def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return default


ALLOW_PUBLIC = _env_flag("ENUMGRID_ALLOW_PUBLIC")
MAX_CONCURRENT_SCANS = _env_int("ENUMGRID_MAX_SCANS", 4)
MAX_HOSTS = _env_int("ENUMGRID_MAX_HOSTS", 4096)
API_TOKEN = os.environ.get("ENUMGRID_API_TOKEN") or None

# --- role-based access control (RBAC) -------------------------------------- #
# Two roles: ADMIN (can launch scans / credentialed checks) and VIEWER
# (read-only: health, history, audit). The legacy ENUMGRID_API_TOKEN counts as
# admin. When NO tokens are configured at all, access is open — preserving the
# zero-config localhost dev flow. Configure tokens before exposing the API.
# (Effective tokens are resolved at call time so they stay overridable/testable.)
ADMIN_TOKEN = os.environ.get("ENUMGRID_ADMIN_TOKEN") or None
VIEWER_TOKEN = os.environ.get("ENUMGRID_VIEWER_TOKEN") or None

# A single process-wide gate on concurrent scans (set once at import).
scan_semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)


class ScopeRejected(Exception):
    """A target failed the authorization/scope policy (safe to surface)."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def vet_target(target: str) -> None:
    """Validate a web request's target against the *full* CLI scope policy.

    Raises :class:`ScopeRejected` (with an operator-readable reason) when the
    target contains injectable characters, resolves to forbidden/reserved
    space, exceeds the host cap, or — unless explicitly permitted — includes
    public/internet-routable addresses. Returns ``None`` when the target is
    cleared for scanning.
    """
    if not target or not _safe_chars(target):
        raise ScopeRejected("target contains invalid characters")

    try:
        scope = pr.ScopeValidator(max_hosts=MAX_HOSTS).validate(target)
    except pr.ScopeError as exc:
        # Loopback / multicast / broadcast / reserved / oversized — same policy
        # as the CLI, which raises ScopeError for these.
        raise ScopeRejected(str(exc)) from exc

    if scope.has_public and not ALLOW_PUBLIC:
        raise ScopeRejected(
            "target includes public/internet-routable addresses; refused. "
            "Set ENUMGRID_ALLOW_PUBLIC=1 to permit (authorized use only)."
        )


def _provided(token: str | None, authorization: str | None) -> str | None:
    """Pull the token from ``?token=`` or an ``Authorization: Bearer …`` header."""
    if token:
        return token
    if authorization:
        scheme, _, value = authorization.partition(" ")
        if scheme.lower() == "bearer" and value:
            return value.strip()
    return None


def role_for(token: str | None, authorization: str | None) -> str | None:
    """Resolve the caller's role: 'admin', 'viewer', or None (unauthorized).

    Open ('admin') when no tokens are configured, so localhost dev needs none.
    Effective tokens are read at call time (ENUMGRID_ADMIN_TOKEN, or the legacy
    ENUMGRID_API_TOKEN, as admin; ENUMGRID_VIEWER_TOKEN as viewer).
    """
    admin = ADMIN_TOKEN or API_TOKEN
    viewer = VIEWER_TOKEN
    if not (admin or viewer):
        return "admin"  # no auth configured → open dev mode
    provided = _provided(token, authorization)
    if not provided:
        return None
    # Constant-time comparison so a token can't be recovered by timing the
    # response to byte-by-byte guesses (hmac.compare_digest is length-safe).
    if admin and hmac.compare_digest(provided, admin):
        return "admin"
    if viewer and hmac.compare_digest(provided, viewer):
        return "viewer"
    return None


def token_ok(token: str | None, authorization: str | None) -> bool:
    """Authorized for READ access (viewer or admin)."""
    return role_for(token, authorization) is not None


def admin_ok(token: str | None, authorization: str | None) -> bool:
    """Authorized for WRITE/scan actions (admin only)."""
    return role_for(token, authorization) == "admin"


class scan_slot:
    """Async context manager that holds one concurrency slot for a scan.

    Use ``async with scan_slot() as ok:`` — ``ok`` is False when the host is
    already at `MAX_CONCURRENT_SCANS`, letting the caller reject fast instead of
    queueing an unbounded backlog of nmap processes.
    """

    def __init__(self) -> None:
        self._held = False

    async def __aenter__(self) -> bool:
        try:
            await asyncio.wait_for(scan_semaphore.acquire(), timeout=0.01)
            self._held = True
        except (asyncio.TimeoutError, TimeoutError):
            self._held = False
        return self._held

    async def __aexit__(self, *exc) -> bool:
        if self._held:
            scan_semaphore.release()
            self._held = False
        return False
