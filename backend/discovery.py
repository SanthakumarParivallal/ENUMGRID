"""
discovery.py — fast network *device* discovery for the web dashboard.

This is the "show me the live devices on my network" engine (like Angry IP /
the CLI's `--discover`): ICMP + ARP host discovery, a proxy-ARP guard so a
router can't make every address look "up", MAC + OUI-vendor resolution, and
parallel reverse-DNS for hostnames. It streams `ScanState` snapshots so the
dashboard fills in live — and deliberately does NOT run nmap. The slow
service/vuln scan is on-demand, per device, via `/api/host/scan`.

It reuses the already-tested primitives from the CLI tool (`purple_recon.py`)
at the project root, so the ARP/proxy/vendor logic lives in exactly one place.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor

# Import the reusable discovery primitives from the CLI tool one level up.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
from fingerprint import guess_device_type  # noqa: E402
from mdns import discover_mdns  # noqa: E402
from models import Host, HostStatus, ScanPhase, ScanState  # noqa: E402
from osfp import os_hint  # noqa: E402

import purple_recon as pr  # noqa: E402  (path set above)

# Cache the (large) OUI vendor table once per process.
_OUI_TABLE: dict[str, str] | None = None


def _oui_table() -> dict[str, str]:
    global _OUI_TABLE
    if _OUI_TABLE is None:
        path = pr.resolve_oui_path(None)
        _OUI_TABLE = pr.load_oui_table(path) if path else {}
    return _OUI_TABLE


def _ip_key(ip: str) -> tuple[int, ...]:
    try:
        return tuple(int(o) for o in ip.split("."))
    except ValueError:
        return (0,)


def expand_target(target: str, max_hosts: int = 4096) -> list[str]:
    """Expand 'CIDR / IP / comma-list' into candidate host IPs (IPv4)."""
    out: list[str] = []
    seen: set[str] = set()
    for part in target.split(","):
        part = part.strip()
        if not part or ":" in part:
            continue
        try:
            net = ipaddress.ip_network(part, strict=False)
        except ValueError:
            continue
        if net.num_addresses == 1:
            members: list = [net.network_address]
        elif net.prefixlen == net.max_prefixlen - 1:  # /31
            members = list(net)
        else:
            members = net.hosts()
        for addr in members:
            ip = str(addr)
            if ip not in seen:
                seen.add(ip)
                out.append(ip)
                if len(out) >= max_hosts:
                    return out
    return out


def _reverse_dns(ip: str) -> tuple[str, str | None]:
    socket.setdefaulttimeout(1.5)
    try:
        return ip, socket.gethostbyaddr(ip)[0]
    except OSError:
        return ip, None


async def run_discovery(target: str, scan_id: str | None):
    """Async generator yielding `ScanState` snapshots as devices are found."""
    loop = asyncio.get_running_loop()
    started = time.time()
    oui = _oui_table()

    engine = pr.DiscoveryEngine(
        timeout=1.0, workers=128, use_ping=True,
        ping_timeout=3.0, use_arp=True, oui_table=oui,
    )

    candidates = expand_target(target)
    total = len(candidates) or 1
    candidate_set = set(candidates)
    hosts: dict[str, Host] = {}

    def snapshot(phase: ScanPhase, progress: int, finished: bool = False) -> ScanState:
        ordered = [hosts[ip] for ip in sorted(hosts, key=_ip_key)]
        return ScanState(
            scan_id=scan_id, target=target, phase=phase, progress=progress,
            started_at=started, finished_at=time.time() if finished else None,
            hosts=ordered,
        )

    yield snapshot(ScanPhase.PING_SWEEP, 2)

    # --- 1) active probe (ICMP + TCP), streamed as hosts respond ----------- #
    pool = ThreadPoolExecutor(max_workers=128, thread_name_prefix="discover")
    done = 0
    try:
        tasks = [
            loop.run_in_executor(pool, lambda ip=ip: (ip, engine.is_alive(ip)))
            for ip in candidates
        ]
        for future in asyncio.as_completed(tasks):
            ip, result = await future
            done += 1
            up, via, _ports, _conf = result
            if up and ip not in hosts:
                hosts[ip] = Host(ip=ip, status=HostStatus.UP, discovered_via=via)
            if done % 12 == 0 or done == total:
                yield snapshot(ScanPhase.PING_SWEEP, min(60, 2 + int(done / total * 58)))
    finally:
        pool.shutdown(wait=False)

    # --- 2) ARP pass (+ proxy-ARP guard) — catches devices that ignore ICMP  #
    arp = {ip: mac for ip, mac in pr._read_arp_table().items() if ip in candidate_set}
    proxy = pr._proxy_macs(arp, max(8, len(candidates) // 10))
    for ip, mac in arp.items():
        if mac in proxy:
            continue  # router proxying — not a distinct device
        host = hosts.get(ip) or Host(ip=ip, status=HostStatus.UP, discovered_via="arp")
        host.mac = mac
        host.vendor = pr._mac_vendor(mac, oui)
        host.device_type = guess_device_type(vendor=host.vendor, hostname=host.hostname)
        hosts[ip] = host
    yield snapshot(ScanPhase.NMAP_ENUMERATION, 75)

    # --- 3) reverse-DNS hostnames in parallel ------------------------------ #
    previous_timeout = socket.getdefaulttimeout()
    try:
        with ThreadPoolExecutor(max_workers=32, thread_name_prefix="dns") as dns_pool:
            for ip, name in dns_pool.map(_reverse_dns, list(hosts)):
                if name and not hosts[ip].hostname:
                    hosts[ip].hostname = name
    finally:
        socket.setdefaulttimeout(previous_timeout)

    # --- 3b) OS-family hint from ping-reply TTL (unprivileged, parallel) ---- #
    # Real `nmap -O` needs root; this gives an honest OS family without it. A
    # later nmap service scan can still refine it (CPE/banner), and the client
    # keeps the better of the two.
    with ThreadPoolExecutor(max_workers=32, thread_name_prefix="ttl") as ttl_pool:
        for ip, os_label in zip(list(hosts), ttl_pool.map(os_hint, list(hosts))):
            if os_label and hosts[ip].os in ("", "Unknown"):
                hosts[ip].os = os_label

    # --- 3c) IPv6 neighbour cache (NDP): show each device's IPv6, by MAC ----- #
    # The IPv6 analogue of the ARP pass — correlates IPv6 addresses to the same
    # device discovered over IPv4 via its MAC (dual-stack visibility).
    try:
        ndp = pr._read_ndp_table()
    except Exception:
        ndp = {}
    if ndp:
        by_mac = {h.mac: h for h in hosts.values() if h.mac}
        for mac, v6_addrs in ndp.items():
            host = by_mac.get(mac)
            if host is not None:
                host.ipv6 = v6_addrs

    # --- 4) mDNS/Bonjour enrichment: real names + authoritative device types  #
    # Run *after* the active probe so the 128-thread sweep isn't dropping the
    # multicast replies; the quiet window makes name resolution reliable.
    try:
        mdns = await loop.run_in_executor(None, lambda: discover_mdns(5.0))
    except Exception:
        mdns = {}
    for ip, info in mdns.items():
        if ip not in candidate_set:
            continue  # keep results inside the requested scope
        host = hosts.get(ip)
        if host is None:
            # Announced over mDNS but missed by ICMP/ARP — still a real device.
            host = Host(ip=ip, status=HostStatus.UP, discovered_via="mdns")
            hosts[ip] = host
        if info.get("hostname") and not host.hostname:
            host.hostname = info["hostname"]
        if info.get("device_type"):
            host.device_type = info["device_type"]  # service-based type is authoritative

    # Fill any still-empty device types from vendor + hostname (mDNS wins above).
    for host in hosts.values():
        if not host.device_type:
            host.device_type = guess_device_type(vendor=host.vendor, hostname=host.hostname)

    yield snapshot(ScanPhase.COMPLETE, 100, finished=True)
