"""
mdns.py — Bonjour / mDNS device-name + service discovery (Fing-style).

Many LAN devices that have *no* reverse-DNS record still announce themselves over
multicast DNS (printers, Apple devices, Chromecasts, Sonos, HomeKit accessories).
Browsing a handful of well-known service types for a few seconds resolves real
device names (e.g. "Living-Room-TV", "Brother-HL-L2350DW") and a confident
device type from the advertised services — exactly what fills the "— no PTR —"
gaps in the inventory.

This is best-effort and dependency-optional: if `zeroconf` isn't installed it
returns `{}` and discovery proceeds unchanged. Everything returned is observed
from real announcements — never inferred or invented.
"""

from __future__ import annotations

import time

try:
    from zeroconf import ServiceBrowser, ServiceListener, Zeroconf

    _HAVE_ZEROCONF = True
except Exception:  # pragma: no cover - import environment dependent
    _HAVE_ZEROCONF = False

# Service types we browse. The short token (e.g. "_ipp") is what we collect.
_SERVICE_TYPES: tuple[str, ...] = (
    "_ipp._tcp.local.", "_ipps._tcp.local.", "_printer._tcp.local.", "_pdl-datastream._tcp.local.",
    "_airplay._tcp.local.", "_raop._tcp.local.", "_companion-link._tcp.local.",
    "_googlecast._tcp.local.", "_sonos._tcp.local.", "_spotify-connect._tcp.local.",
    "_homekit._tcp.local.", "_hap._tcp.local.",
    "_workstation._tcp.local.", "_smb._tcp.local.", "_ssh._tcp.local.",
    "_http._tcp.local.", "_device-info._tcp.local.", "_googlezone._tcp.local.",
)


def device_type_from_mdns(services: set[str]) -> str:
    """Map a set of advertised mDNS service tokens to a device type (or "").

    Ordered most-specific first so, e.g., a Mac advertising AirPlay + Bonjour
    companion is labelled an Apple device (not a TV), while a standalone AirPlay
    speaker/Apple-TV is Media.
    """
    s = services
    if s & {"_ipp", "_ipps", "_printer", "_pdl-datastream"}:
        return "Printer"
    if s & {"_googlecast", "_sonos", "_spotify-connect"}:
        return "Media / TV"
    if s & {"_homekit", "_hap"}:
        return "Smart-home"
    if s & {"_workstation", "_smb"}:
        return "Computer"
    if "_companion-link" in s:
        return "Apple device"
    if s & {"_airplay", "_raop"}:
        return "Media / TV"  # standalone AirPlay receiver (Apple TV / HomePod)
    return ""


def _clean_hostname(server: str | None) -> str | None:
    if not server:
        return None
    name = server.rstrip(".")
    if name.endswith(".local"):
        name = name[: -len(".local")]
    return name or None


def discover_mdns(timeout: float = 4.0) -> dict[str, dict]:
    """Browse mDNS for `timeout` seconds.

    Returns ``{ipv4: {"hostname": str|None, "services": list[str],
    "device_type": str}}``. Empty when zeroconf is unavailable.
    """
    if not _HAVE_ZEROCONF:
        return {}

    raw: dict[str, dict] = {}

    class _Listener(ServiceListener):
        def add_service(self, zc, type_, name):
            try:
                info = zc.get_service_info(type_, name, timeout=2000)
            except Exception:  # pragma: no cover - network timing
                return
            if not info:
                return
            token = type_.split(".")[0]
            host = _clean_hostname(info.server)
            try:
                addrs = info.parsed_addresses()
            except Exception:  # pragma: no cover
                addrs = []
            for addr in addrs:
                if ":" in addr:  # IPv4 only for now
                    continue
                rec = raw.setdefault(addr, {"hostname": None, "services": set()})
                rec["services"].add(token)
                if host and not rec["hostname"]:
                    rec["hostname"] = host

        def update_service(self, *a):  # noqa: D401 - required by interface
            pass

        def remove_service(self, *a):
            pass

    zc = Zeroconf()
    try:
        listener = _Listener()
        for stype in _SERVICE_TYPES:
            ServiceBrowser(zc, stype, listener)
        time.sleep(max(1.0, timeout))
    finally:
        try:
            zc.close()
        except Exception:  # pragma: no cover
            pass

    return {
        ip: {
            "hostname": rec["hostname"],
            "services": sorted(rec["services"]),
            "device_type": device_type_from_mdns(rec["services"]),
        }
        for ip, rec in raw.items()
    }
