"""
osfp.py — unprivileged OS-family hint from the ICMP reply TTL.

nmap's authoritative OS detection (`-O`) needs raw sockets (root). Without it,
the **initial TTL** of a host's ping reply is a classic, honest OS-family
signal: most stacks start at 64 (Linux / macOS / Unix / Android / iOS), 128
(Windows), or 255 (routers, printers, many IoT). On a LAN there are ~0 hops, so
the observed TTL ≈ the initial TTL.

We label the *family* — never a fabricated exact version — and return "" when
the TTL is missing or ambiguous. This closes the "OS column is always Unknown"
gap for unprivileged scans without inventing data.
"""

from __future__ import annotations

import platform
import re
import subprocess

_TTL_RE = re.compile(r"ttl[=\s:]*(\d+)", re.IGNORECASE)


def _ping_command(ip: str, timeout_s: float) -> list[str]:
    system = platform.system().lower()
    if system == "windows":
        return ["ping", "-n", "1", "-w", str(int(timeout_s * 1000)), ip]
    if system == "darwin":
        return ["ping", "-c", "1", "-t", str(max(1, int(timeout_s))), ip]
    return ["ping", "-c", "1", "-W", str(max(1, int(timeout_s))), ip]


def ping_ttl(ip: str, timeout_s: float = 2.0) -> int | None:
    """Return the TTL of one ICMP echo reply, or None if no reply/parsed TTL."""
    try:
        out = subprocess.run(
            _ping_command(ip, timeout_s),
            capture_output=True, text=True, timeout=timeout_s + 1, check=False,
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = _TTL_RE.search(out or "")
    return int(match.group(1)) if match else None


def os_from_ttl(ttl: int | None) -> str:
    """Map an observed TTL to an OS family (allowing a few hops), or "".

    Buckets by the nearest standard initial TTL above the observed value:
    ≤64 → Linux/macOS/Unix, ≤128 → Windows, ≤255 → network device / IoT.
    """
    if ttl is None or ttl <= 0:
        return ""
    if ttl <= 64:
        return "Linux / macOS / Unix"
    if ttl <= 128:
        return "Windows"
    if ttl <= 255:
        return "Network device / IoT"
    return ""


def os_hint(ip: str, timeout_s: float = 2.0) -> str:
    """Best-effort OS-family label for `ip` from its ping-reply TTL ("" if none)."""
    return os_from_ttl(ping_ttl(ip, timeout_s))
