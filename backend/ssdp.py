"""
ssdp.py — SSDP / UPnP device-name + model discovery (Fing-style).

A large class of LAN devices that have *no* reverse-DNS record and don't answer
mDNS or NetBIOS still announce themselves over SSDP (UPnP): home routers, smart
TVs and media renderers, game consoles, NAS boxes, printers and a lot of IoT.
We send the standard ``M-SEARCH`` multicast, collect the unicast replies, then
fetch each responder's UPnP *device description* XML to read its
``friendlyName`` / ``manufacturer`` / ``modelName`` / ``deviceType`` — exactly
what fills the "— no PTR —" gaps in the inventory.

Pure stdlib (sockets + urllib), best-effort and bounded: any error just yields
no data for that host. Everything returned is the device's *own* announced
description — never inferred or invented.

SECURITY
--------
A reply's ``LOCATION`` URL is only fetched when its host matches the IP that
actually answered (and the scheme is http/https) — so a rogue device can't use
its SSDP reply to make us fetch an arbitrary internal URL (SSRF). The XML is
scraped with targeted regexes (no XML entity expansion), so a hostile
description can't trigger an XXE / billion-laughs parse.
"""

from __future__ import annotations

import re
import socket
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900

_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
).encode("ascii")

# Pull a single header value out of an SSDP/HTTP response (case-insensitive).
_LOCATION_RE = re.compile(rb"^location:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)
_SERVER_RE = re.compile(rb"^server:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)

# Targeted scrapes of the UPnP device-description XML (no XML parser → no XXE).
_FRIENDLY_RE = re.compile(r"<friendlyName>\s*(.*?)\s*</friendlyName>", re.IGNORECASE | re.DOTALL)
_MANUF_RE = re.compile(r"<manufacturer>\s*(.*?)\s*</manufacturer>", re.IGNORECASE | re.DOTALL)
_MODEL_RE = re.compile(r"<modelName>\s*(.*?)\s*</modelName>", re.IGNORECASE | re.DOTALL)
_DEVTYPE_RE = re.compile(r"<deviceType>\s*(.*?)\s*</deviceType>", re.IGNORECASE | re.DOTALL)

# UPnP deviceType URN keyword → coarse device type (matches fingerprint.py labels).
_UPNP_TYPE_HINTS: tuple[tuple[str, str], ...] = (
    ("internetgatewaydevice", "Router / Gateway"),
    ("wandevice", "Router / Gateway"),
    ("wlanaccesspoint", "Router / Gateway"),
    ("mediaserver", "Media / TV"),
    ("mediarenderer", "Media / TV"),
    ("tvdevice", "Media / TV"),
    ("printer", "Printer"),
    ("printbasic", "Printer"),
    ("nas", "NAS / Storage"),
)


def _device_type_from_upnp(device_type_urn: str) -> str:
    """Map a UPnP ``deviceType`` URN to a coarse device type (or "")."""
    low = (device_type_urn or "").lower()
    for needle, label in _UPNP_TYPE_HINTS:
        if needle in low:
            return label
    return ""


def _scrape(pattern: re.Pattern[str], text: str) -> str:
    m = pattern.search(text)
    return m.group(1).strip() if m else ""


def _collect_responses(timeout: float) -> dict[str, dict]:
    """Send the M-SEARCH and gather ``{ip: {"location": str, "server": str}}``."""
    out: dict[str, dict] = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(max(0.5, timeout))
        # Send a couple of times — UDP multicast is lossy and some stacks only
        # answer the second probe.
        for _ in range(2):
            try:
                sock.sendto(_MSEARCH, (SSDP_ADDR, SSDP_PORT))
            except OSError:
                break
        deadline = max(0.5, timeout)
        sock.settimeout(deadline)
        import time

        end = time.monotonic() + deadline
        while time.monotonic() < end:
            try:
                sock.settimeout(max(0.1, end - time.monotonic()))
                data, addr = sock.recvfrom(4096)
            except (TimeoutError, OSError):
                break
            ip = addr[0]
            loc_m = _LOCATION_RE.search(data)
            srv_m = _SERVER_RE.search(data)
            rec = out.setdefault(ip, {"location": "", "server": ""})
            if loc_m and not rec["location"]:
                rec["location"] = loc_m.group(1).decode("ascii", "ignore")
            if srv_m and not rec["server"]:
                rec["server"] = srv_m.group(1).decode("ascii", "ignore")
    finally:
        sock.close()
    return out


def _location_is_safe(location: str, source_ip: str) -> bool:
    """True only when LOCATION points back at the device that answered.

    Guards against an SSRF where a rogue SSDP reply names a LOCATION on some
    other (internal) host to make us fetch it.
    """
    try:
        parsed = urlparse(location)
    except ValueError:
        return False
    return parsed.scheme in ("http", "https") and parsed.hostname == source_ip


def _fetch_description(location: str, timeout: float) -> dict:
    """Fetch + scrape one UPnP device-description XML (best-effort)."""
    try:
        req = urllib.request.Request(location, headers={"User-Agent": "ENUMGRID/SSDP"})
        # Scheme is constrained to http/https by _location_is_safe before we get
        # here, so urlopen can't be steered to a file:// or other local scheme.
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
            raw = resp.read(65536)
    except Exception:  # noqa: BLE001 - network/parse failures are non-fatal
        return {}
    text = raw.decode("utf-8", "replace")
    return {
        "friendly": _scrape(_FRIENDLY_RE, text),
        "manufacturer": _scrape(_MANUF_RE, text),
        "model": _scrape(_MODEL_RE, text),
        "device_type": _device_type_from_upnp(_scrape(_DEVTYPE_RE, text)),
    }


def _os_from_server(server: str) -> str:
    """Best-effort OS family from an SSDP ``SERVER`` header (e.g. 'Linux/3.14 ...')."""
    low = (server or "").lower()
    if "windows" in low:
        return "Windows"
    if "linux" in low or "unix" in low:
        return "Embedded Linux"
    return ""


def discover_ssdp(timeout: float = 2.5, fetch_timeout: float = 1.5, max_fetch: int = 64) -> dict[str, dict]:
    """Discover UPnP devices via SSDP.

    Returns ``{ipv4: {"hostname": str|None, "manufacturer": str, "model": str,
    "device_type": str, "os": str}}``. The ``hostname`` is the device's
    ``friendlyName`` (a real, human label like "Living Room TV"). Empty dict on
    any failure or when nothing answers.
    """
    responses = _collect_responses(timeout)
    if not responses:
        return {}

    # Only fetch descriptions whose LOCATION points back at the responder.
    fetchable = {
        ip: rec["location"]
        for ip, rec in responses.items()
        if rec.get("location") and _location_is_safe(rec["location"], ip)
    }
    # Bound the number of HTTP fetches so a chatty subnet can't stall discovery.
    items = list(fetchable.items())[:max_fetch]

    descriptions: dict[str, dict] = {}
    if items:
        with ThreadPoolExecutor(max_workers=min(32, len(items)), thread_name_prefix="ssdp") as pool:
            for (ip, _loc), desc in zip(
                items, pool.map(lambda kv: _fetch_description(kv[1], fetch_timeout), items)
            ):
                descriptions[ip] = desc

    out: dict[str, dict] = {}
    for ip, rec in responses.items():
        desc = descriptions.get(ip, {})
        friendly = desc.get("friendly") or ""
        out[ip] = {
            "hostname": friendly or None,
            "manufacturer": desc.get("manufacturer", ""),
            "model": desc.get("model", ""),
            "device_type": desc.get("device_type", ""),
            "os": _os_from_server(rec.get("server", "")),
        }
    return out
