"""
osfp.py — best-effort OS identification WITHOUT root (no raw sockets).

nmap's authoritative OS detection (`-O`) needs raw sockets (root). When the
backend isn't privileged we still want a *specific*, honest OS label instead of
a vague "Linux / macOS / Unix" lump. We get there by fusing several real,
observable signals:

  1. the **initial TTL** of the host's ICMP reply  → coarse family
     (64 = Linux/macOS/Unix/Android/iOS, 128 = Windows, 255 = router/IoT);
  2. the **OUI vendor** (from the MAC)             → Apple / Android-maker / …;
  3. the **hostname**                              → "Johns-MacBook", "iPhone";
  4. the **device type** already classified by `fingerprint.py`.

`refine_os()` combines them into the most specific label the evidence supports
(e.g. "macOS (Apple)", "Android", "Windows", "Router/embedded Linux") and never
fabricates an exact version — that only comes from a privileged `nmap -O` scan,
which the per-host scan performs when the backend runs as root.
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


# --------------------------------------------------------------------------- #
# Signal fusion: turn the coarse TTL family into a specific OS using vendor,
# hostname and the already-computed device type. Every branch is grounded in a
# real observation — we sharpen the label, we never invent a version.
# --------------------------------------------------------------------------- #

# Android handset / tablet makers (their phones run Android = Linux kernel).
_ANDROID_VENDORS = (
    "samsung", "xiaomi", "redmi", "oneplus", "vivo", "oppo", "honor", "huawei",
    "nothing", "motorola", "realme", "lge", "lg electronics", "sony mobile",
    "tcl", "fairphone", "asus",
)
# Hostname tokens that pin a personal device's OS precisely.
_HOST_OS = (
    (("macbook", "imac", "mac-mini", "macmini", "mac-pro", "macpro", "macstudio"), "macOS (Apple)"),
    (("iphone",), "iOS (Apple)"),
    (("ipad",), "iPadOS (Apple)"),
    (("apple-watch", "applewatch"), "watchOS (Apple)"),
    (("apple-tv", "appletv"), "tvOS (Apple)"),
    (("pixel", "galaxy", "redmi", "oneplus", "android"), "Android"),
    (("openwrt",), "OpenWrt (Linux)"),
    (("raspberrypi", "raspberry"), "Linux (Raspberry Pi OS)"),
    (("ubuntu",), "Linux (Ubuntu)"),
)


def _apple_os_from_hostname(hostname: str | None) -> str:
    low = (hostname or "").lower()
    if "iphone" in low:
        return "iOS (Apple)"
    if "ipad" in low:
        return "iPadOS (Apple)"
    if any(k in low for k in ("macbook", "imac", "mac-mini", "macmini", "mac-pro", "macstudio")):
        return "macOS (Apple)"
    return "macOS / iOS (Apple)"


def refine_os(
    ttl_family: str,
    vendor: str | None = None,
    hostname: str | None = None,
    device_type: str | None = None,
) -> str:
    """Sharpen a coarse TTL family into the most specific honest OS label.

    Returns ``ttl_family`` unchanged when no stronger signal is available, so
    this can only ever improve (never degrade) the label.
    """
    vlow = (vendor or "").lower()
    hlow = (hostname or "").lower()
    dtype = device_type or ""

    # 1) Hostname is the most direct, user-set signal.
    for tokens, label in _HOST_OS:
        if any(t in hlow for t in tokens):
            return label

    # 2) Apple OUI → macOS/iOS (sharpen with hostname if we can).
    if "apple" in vlow or dtype == "Apple device":
        return _apple_os_from_hostname(hostname)

    # 3) Known Android maker → Android (Linux kernel).
    if any(v in vlow for v in _ANDROID_VENDORS) or dtype in ("Phone / Tablet", "Phone / Laptop"):
        # A laptop-or-phone (random MAC) on a 128-TTL stack is Windows; else Android.
        if ttl_family == "Windows":
            return "Windows"
        return "Android" if (vlow and any(v in vlow for v in _ANDROID_VENDORS)) else "Android / iOS"

    # 4) Infrastructure / embedded by device class.
    if dtype == "Router / Gateway":
        if "mikrotik" in vlow:
            return "MikroTik RouterOS"
        return "Router firmware (Linux)"
    if dtype == "Printer":
        return "Printer firmware"
    if dtype == "Camera":
        return "Embedded Linux (camera)"
    if dtype in ("Smart-home", "IoT / Embedded"):
        return "Embedded / RTOS"
    if dtype == "Media / TV":
        return "Smart TV OS (Linux-based)"
    if dtype == "NAS / Storage":
        return "Linux (NAS)"

    # 5) Windows family stays Windows; otherwise keep the honest TTL family.
    return ttl_family


def os_hint(ip: str, timeout_s: float = 2.0) -> str:
    """Best-effort OS-family label for `ip` from its ping-reply TTL ("" if none)."""
    return os_from_ttl(ping_ttl(ip, timeout_s))
