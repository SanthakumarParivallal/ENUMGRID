"""
provenance.py — a reproducibility manifest for the backend.

Records *what produced a result*: tool + version, the exact git commit, the nmap
build, the Python runtime and OS, and when it ran. Embedded in `/api/health` and
in the PDF report so a saved artifact reproduces by itself. Best-effort and
honest — unknowns are labelled ("unknown" / "not found"), never fabricated.

The git/nmap probes shell out once per process and are cached (`_probe`), so a
frequently-polled endpoint like /api/health never spawns a subprocess per call.
"""

from __future__ import annotations

import os
import platform
import re
import subprocess  # nosec B404 - fixed argv, no user input
from datetime import datetime, timezone
from functools import lru_cache

TOOL = "ENUMGRID"
VERSION = "1.0.0"
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def git_commit(root: str | None = None) -> str | None:
    """Short git SHA of the working tree, or None when run outside a checkout."""
    try:
        out = subprocess.run(  # nosec B603 B607 - fixed args, no user input
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=root or _REPO_ROOT,
            capture_output=True, text=True, check=False, timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    sha = out.stdout.strip()
    return sha or None


def nmap_version() -> str | None:
    """nmap's reported version (e.g. ``7.95``), or None if nmap is not installed."""
    try:
        out = subprocess.run(  # nosec B603 B607 - fixed args, no user input
            ["nmap", "--version"],
            capture_output=True, text=True, check=False, timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r"Nmap version\s+(\S+)", out.stdout)
    return match.group(1) if match else None


@lru_cache(maxsize=1)
def _probe() -> tuple[str, str]:
    """(git_commit, nmap_version) resolved once per process — subprocess-backed."""
    return (git_commit() or "unknown", nmap_version() or "not found")


def build_info(*, commit: str | None = None, nmap: str | None = None) -> dict:
    """The static provenance fields (no timestamp). Injected values skip probing,
    so this is deterministic under test."""
    if commit is None or nmap is None:
        probed_commit, probed_nmap = _probe()
        commit = probed_commit if commit is None else commit
        nmap = probed_nmap if nmap is None else nmap
    return {
        "tool": TOOL,
        "tool_version": VERSION,
        "git_commit": commit,
        "nmap_version": nmap,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
    }


def manifest(*, commit: str | None = None, nmap: str | None = None) -> dict:
    """Full provenance manifest = static build info + the generation timestamp."""
    return {
        **build_info(commit=commit, nmap=nmap),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
