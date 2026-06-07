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


# Apple `model=` prefix → (specific product, OS). Deterministic and exact for
# the device class — the prefix *is* the product line, so this is observed fact,
# never a guess. Order matters: check longer prefixes first.
_APPLE_MODEL_MAP: tuple[tuple[str, str, str], ...] = (
    ("macbookpro", "MacBook Pro", "macOS (Apple)"),
    ("macbookair", "MacBook Air", "macOS (Apple)"),
    ("macbook", "MacBook", "macOS (Apple)"),
    ("imacpro", "iMac Pro", "macOS (Apple)"),
    ("imac", "iMac", "macOS (Apple)"),
    ("macmini", "Mac mini", "macOS (Apple)"),
    ("macstudio", "Mac Studio", "macOS (Apple)"),
    ("macpro", "Mac Pro", "macOS (Apple)"),
    ("mac", "Mac", "macOS (Apple)"),  # Mac14,x (Apple-silicon generic)
    ("iphone", "iPhone", "iOS (Apple)"),
    ("ipad", "iPad", "iPadOS (Apple)"),
    ("ipod", "iPod touch", "iOS (Apple)"),
    ("watch", "Apple Watch", "watchOS (Apple)"),
    ("appletv", "Apple TV", "tvOS (Apple)"),
    ("audioaccessory", "HomePod", "audioOS (HomePod)"),
)

# Darwin major (from `osxvers` TXT) → macOS marketing version. Exact mapping.
_OSXVERS_MAP = {
    "25": "macOS 26 (Tahoe)", "24": "macOS 15 (Sequoia)", "23": "macOS 14 (Sonoma)",
    "22": "macOS 13 (Ventura)", "21": "macOS 12 (Monterey)", "20": "macOS 11 (Big Sur)",
    "19": "macOS 10.15 (Catalina)", "18": "macOS 10.14 (Mojave)",
}


def product_from_model(model: str | None) -> str:
    """Specific Apple product line from a `model=` code ("" if not Apple/known).

    e.g. ``MacBookPro18,3`` → "MacBook Pro", ``iPhone14,5`` → "iPhone",
    ``iPad13,4`` → "iPad". The prefix is the product line, so this is exact.
    """
    low = (model or "").strip().lower()
    for prefix, product, _os in _APPLE_MODEL_MAP:
        if low.startswith(prefix):
            return product
    return ""


def os_from_model(model: str | None, osxvers: str | None = None) -> str:
    """Map an Apple `_device-info` model code to its OS (authoritative, observed).

    Apple devices advertise a `model=` TXT record (e.g. ``MacBookPro18,3``,
    ``iPhone14,5``, ``iPad13,4``). The product prefix maps deterministically to
    the OS. When a Mac also advertises `osxvers=NN` we resolve the exact macOS
    version (e.g. ``osxvers=23`` → "macOS 14 (Sonoma)"). Unknown/board codes
    (e.g. ``J413AP``) return "" and we fall back to softer signals.
    """
    low = (model or "").strip().lower()
    if not low:
        return ""
    for prefix, _product, os_label in _APPLE_MODEL_MAP:
        if low.startswith(prefix):
            # Sharpen Macs to the exact macOS version when osxvers is present.
            if os_label.startswith("macOS") and osxvers and str(osxvers).strip() in _OSXVERS_MAP:
                return f"{_OSXVERS_MAP[str(osxvers).strip()]} (Apple)"
            return os_label
    return ""


def _txt_get(properties: dict | None, key: str) -> str | None:
    """Read one TXT-record value from zeroconf `info.properties` (bytes keys)."""
    if not properties:
        return None
    for raw_key, raw_val in properties.items():
        try:
            k = raw_key.decode() if isinstance(raw_key, bytes) else str(raw_key)
        except Exception:  # pragma: no cover  # nosec B112 - skip TXT keys with exotic encodings
            continue
        if k.lower() == key.lower() and raw_val is not None:
            try:
                return raw_val.decode() if isinstance(raw_val, bytes) else str(raw_val)
            except Exception:  # pragma: no cover
                return None
    return None


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
            # `_device-info` carries `model=` (+ sometimes `osxvers=`) TXT — an
            # authoritative product + OS signal the device announces about itself.
            props = getattr(info, "properties", None)
            model = _txt_get(props, "model")
            osxvers = _txt_get(props, "osxvers")
            try:
                addrs = info.parsed_addresses()
            except Exception:  # pragma: no cover
                addrs = []
            for addr in addrs:
                if ":" in addr:  # IPv4 only for now
                    continue
                rec = raw.setdefault(
                    addr, {"hostname": None, "services": set(), "model": None, "osxvers": None}
                )
                rec["services"].add(token)
                if host and not rec["hostname"]:
                    rec["hostname"] = host
                if model and not rec.get("model"):
                    rec["model"] = model
                if osxvers and not rec.get("osxvers"):
                    rec["osxvers"] = osxvers

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

    out: dict[str, dict] = {}
    for ip, rec in raw.items():
        # A specific Apple product from the announced model wins over the
        # generic service-derived type ("Apple device").
        product = product_from_model(rec.get("model"))
        out[ip] = {
            "hostname": rec["hostname"],
            "services": sorted(rec["services"]),
            "device_type": product or device_type_from_mdns(rec["services"]),
            "os": os_from_model(rec.get("model"), rec.get("osxvers")),
        }
    return out
