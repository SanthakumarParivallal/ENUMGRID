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
def _ensure_on_path(root: str, path: list[str] | None = None) -> None:
    """Put `root` on the import path if absent (see security._ensure_on_path)."""
    target = sys.path if path is None else path
    if root not in target:
        target.insert(0, root)


_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ensure_on_path(_ROOT)
import snmp  # noqa: E402
from fingerprint import guess_device_type  # noqa: E402
from mdns import discover_mdns  # noqa: E402
from models import Host, HostStatus, Port, PortState, Protocol, ScanPhase, ScanState  # noqa: E402
from nbns import nbns_names  # noqa: E402
from osfp import os_hint, refine_os  # noqa: E402
from ssdp import discover_ssdp  # noqa: E402

import purple_recon as pr  # noqa: E402  (path set above)

# Cache the (large) OUI vendor table once per process.
_OUI_TABLE: dict[str, str] | None = None


def _oui_table() -> dict[str, str]:
    global _OUI_TABLE
    if _OUI_TABLE is None:
        path = pr.resolve_oui_path(None)
        _OUI_TABLE = pr.load_oui_table(path) if path else {}
    return _OUI_TABLE


# --- discover-mode TCP port probe (fast, unprivileged) --------------------- #
# A short connect-scan of the common service ports so the live grid shows open
# ports immediately — without nmap or root. The full -sV/vuln enumeration stays
# on-demand per host (/api/host/scan). Tunable via env so it can be turned off
# or made more/less aggressive.
PORT_PROBE = os.environ.get("ENUMGRID_DISCOVER_PORTS", "1").lower() not in ("0", "false", "no")
PORT_PROBE_TIMEOUT = float(os.environ.get("ENUMGRID_PORT_TIMEOUT", "0.5"))
# How long to listen for mDNS/Bonjour announcements. Longer = more device names
# resolved (printers, Apple/IoT) at the cost of a slightly longer scan.
MDNS_SECS = float(os.environ.get("ENUMGRID_MDNS_SECS", "6.0"))
# How long to wait for SSDP/UPnP replies (routers, smart TVs, media, IoT).
SSDP_SECS = float(os.environ.get("ENUMGRID_SSDP_SECS", "2.5"))

# The common TCP ports knocked per host (reuses the CLI's curated top-ports set).
_COMMON_PORTS: tuple[int, ...] = pr.FALLBACK_PORTS
# Open ports that are inherently risky/high-signal on a LAN — flagged so the UI
# highlights them even before a full service scan.
_CRITICAL_PORTS = frozenset({21, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 5985, 6379})


def _probe_pair(pair: tuple[str, int]) -> bool:
    """True when a TCP connect to ``(ip, port)`` completes (a real open service).

    A full handshake can't be forged by a silent-drop firewall, so an ``open``
    here is trustworthy — unlike nmap's ``filtered``. Best-effort: any socket
    error is treated as not-open.
    """
    ip, port = pair
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(PORT_PROBE_TIMEOUT)
            return sock.connect_ex((ip, port)) == 0
    except OSError:
        return False


def _make_port(port: int) -> Port:
    """A discover-mode Port record (state OPEN, friendly service label)."""
    return Port(
        port=port,
        protocol=Protocol.TCP,
        service=pr.COMMON_SERVICES.get(port, "unknown"),
        state=PortState.OPEN,
        critical=port in _CRITICAL_PORTS,
    )


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
    # Open ports observed during the active TCP knock — reused as seeds for the
    # common-port probe below so we never re-test a port we already confirmed.
    seed_ports: dict[str, set[int]] = {}

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
            up, via, open_ports, _conf = result
            if up and ip not in hosts:
                hosts[ip] = Host(ip=ip, status=HostStatus.UP, discovered_via=via)
            if up and open_ports:
                seed_ports.setdefault(ip, set()).update(open_ports)
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

    # --- 2b) fast TCP connect-scan of the common ports (unprivileged) ------- #
    # Fills the live grid's "ports" column right away — no nmap, no root. The
    # full -sV/vuln enumeration stays on-demand per host (/api/host/scan). Open
    # ports also feed the device-type classifier below (port signatures are its
    # strongest hint), so this sharpens DEVICE/OS for free. Probes are fanned out
    # across (ip, port) pairs so a host full of filtered ports doesn't serialize.
    if PORT_PROBE and hosts:
        targets = list(hosts)
        pairs = [(ip, port) for ip in targets for port in _COMMON_PORTS]
        found: dict[str, set[int]] = {ip: set(seed_ports.get(ip, ())) for ip in targets}
        with ThreadPoolExecutor(
            max_workers=min(256, max(16, len(pairs))), thread_name_prefix="portprobe"
        ) as pp_pool:
            for (ip, port), is_open in zip(pairs, pp_pool.map(_probe_pair, pairs)):
                if is_open:
                    found[ip].add(port)
        for ip in targets:
            if found[ip]:
                hosts[ip].ports = [_make_port(p) for p in sorted(found[ip])]
        yield snapshot(ScanPhase.NMAP_ENUMERATION, 85)

    # --- 3) reverse-DNS hostnames in parallel ------------------------------ #
    previous_timeout = socket.getdefaulttimeout()
    try:
        with ThreadPoolExecutor(max_workers=32, thread_name_prefix="dns") as dns_pool:
            for ip, name in dns_pool.map(_reverse_dns, list(hosts)):
                if name and not hosts[ip].hostname:
                    hosts[ip].hostname = name
    finally:
        socket.setdefaulttimeout(previous_timeout)

    # --- 3a) NetBIOS (NBNS) names for hosts still lacking one --------------- #
    # Catches Windows PCs, printers, NAS and IoT that have no reverse-DNS record
    # but answer a NetBIOS node-status query (the Angry IP / Fing technique).
    no_name = [ip for ip, h in hosts.items() if not h.hostname]
    if no_name:
        try:
            nb = await loop.run_in_executor(None, lambda: nbns_names(no_name, 1.0))
        except Exception:
            nb = {}
        for ip, name in nb.items():
            if name and not hosts[ip].hostname:
                hosts[ip].hostname = name

    # --- 3a2) SNMP names for still-unnamed hosts (switches/APs/printers) ---- #
    # Network gear with no DNS/mDNS often answers SNMP (default community
    # "public") with its sysName/sysDescr. Parallel + short timeout, so devices
    # that don't speak SNMP cost ~1s total, not per-host.
    unnamed = [ip for ip, h in hosts.items() if not h.hostname]
    if unnamed:
        try:
            with ThreadPoolExecutor(max_workers=32, thread_name_prefix="snmp") as snmp_pool:
                for ip, info in zip(unnamed, snmp_pool.map(lambda i: snmp.sysinfo(i, timeout=1.0), unnamed)):
                    if info.get("name") and not hosts[ip].hostname:
                        hosts[ip].hostname = info["name"]
                    if info.get("descr") and hosts[ip].os in ("", "Unknown"):
                        hosts[ip].os = info["descr"][:60]
        except Exception:
            pass

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
        mdns = await loop.run_in_executor(None, lambda: discover_mdns(MDNS_SECS))
    except Exception:
        mdns = {}
    # IPs whose device type came from a *service announcement* (mDNS or SSDP) —
    # authoritative (device-declared), so the heuristic fill below must not
    # override them.
    typed_by_service: set[str] = set()
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
            typed_by_service.add(ip)
        if info.get("os"):
            host.os = info["os"]  # device-announced model → exact OS class

    # --- 4b) SSDP/UPnP enrichment: friendly names + models for the devices ---- #
    # that don't speak mDNS/NBNS (routers, smart TVs, media renderers, consoles,
    # many IoT). The announced `friendlyName` is a real human label and the
    # `modelName`/`manufacturer` give a confident device type + vendor.
    try:
        ssdp_info = await loop.run_in_executor(None, lambda: discover_ssdp(SSDP_SECS))
    except Exception:
        ssdp_info = {}
    for ip, info in ssdp_info.items():
        if ip not in candidate_set:
            continue
        host = hosts.get(ip)
        if host is None:
            host = Host(ip=ip, status=HostStatus.UP, discovered_via="ssdp")
            hosts[ip] = host
        if info.get("hostname") and not host.hostname:
            host.hostname = info["hostname"]
        # UPnP manufacturer is a useful vendor when ARP gave us no MAC/OUI.
        if info.get("manufacturer") and not host.vendor:
            host.vendor = info["manufacturer"]
        if info.get("device_type"):
            host.device_type = info["device_type"]  # device-declared type is authoritative
            typed_by_service.add(ip)
        if info.get("os") and host.os in ("", "Unknown"):
            host.os = info["os"]

    # (Re)classify device type from every signal we now have — crucially the open
    # ports, whose signatures are the *strongest* hint (e.g. 9100→Printer,
    # 554→Camera, 445+139→Computer). Skip hosts already typed by a service
    # announcement (mDNS/SSDP). guess_device_type returns "" when no signal is
    # strong enough, so we never blank an existing label.
    for host in hosts.values():
        if host.ip in typed_by_service:
            continue
        open_ports = [p.port for p in host.ports if p.state in (PortState.OPEN, PortState.OPEN_FILTERED)]
        services = [p.service for p in host.ports]
        guessed = guess_device_type(
            vendor=host.vendor, hostname=host.hostname, ports=open_ports, services=services,
        )
        if guessed:
            host.device_type = guessed

    # Sharpen each host's coarse TTL family into a *specific* OS using the
    # vendor, hostname and device type we now have — e.g. the vague
    # "Linux / macOS / Unix" becomes "macOS (Apple)", "Android",
    # "Router firmware (Linux)", etc. We only touch the coarse TTL families (or
    # an empty/Unknown OS); an authoritative mDNS model label is left alone. This
    # stays honest: it's still a family unless a privileged `nmap -O` per-host
    # scan supplies the exact version (the OS column then upgrades in place).
    _coarse = {"", "Unknown", "Linux / macOS / Unix", "Windows", "Network device / IoT"}
    for host in hosts.values():
        if host.os in _coarse:
            refined = refine_os(
                host.os if host.os and host.os != "Unknown" else "",
                vendor=host.vendor,
                hostname=host.hostname,
                device_type=host.device_type,
            )
            if refined:
                host.os = refined

    yield snapshot(ScanPhase.COMPLETE, 100, finished=True)
