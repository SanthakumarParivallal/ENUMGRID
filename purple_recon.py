#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PurpleRecon — a two-tiered, single-terminal network enumeration cockpit.

Author : santhakumarParivallal
Project: Industrial-Level Network Enumeration Platform (Master's security project)
License: Authorized / educational use only.

PHILOSOPHY ("Purple Teaming")
-----------------------------
This tool thinks like an offensive weapon but acts like a defensive asset
mapper.  It discovers and inventories the hosts you are *authorized* to
assess, and presents them through a calm, industrial "cockpit" so that even a
non-technical operator can understand the picture at a glance.

ARCHITECTURE
------------
A single, self-contained Python file with four cooperating layers:

  1. Guardrails  (``ScopeValidator``) — strictly refuses loopback, multicast,
     broadcast, link-local, unspecified and reserved space to prevent a
     self-inflicted denial of service, and caps the scan size.
  2. Phase 1     (``DiscoveryEngine``) — a fast, *unprivileged-friendly*
     horizontal sweep (threaded TCP connect + system ICMP) to find live hosts.
  3. Phase 2     (``EnumerationEngine``) — a threaded, vertical deep-dive that
     runs nmap service/version detection strictly on the live hosts.
  4. Cockpit     (``rich`` Layout + Live) — a fixed header, a live-updating
     asset matrix, and a progress footer, all in one terminal window.

Everything is defensively coded: network timeouts, missing privileges, a
missing nmap binary, missing dependencies, invalid input and Ctrl-C are all
handled gracefully — never with a raw traceback.

USAGE
-----
    python3 purple_recon.py 192.168.1.0/24
    python3 purple_recon.py 10.0.0.5,10.0.0.10 --top-ports 200
    python3 purple_recon.py 192.168.1.0/28 --full -y
"""

from __future__ import annotations

# --------------------------------------------------------------------------- #
# Standard library imports (kept minimal and explicit for auditability).
# --------------------------------------------------------------------------- #
import argparse
import copy
import csv
import errno
import html
import ipaddress
import json
import math
import os
import platform
import re
import socket
import subprocess
import sys
import threading
import time
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from types import SimpleNamespace

# --------------------------------------------------------------------------- #
# Third-party dependency: rich.  Fail loudly but cleanly if it is missing.
# (Requirement: gracefully handle missing dependencies — no raw traceback.)
# --------------------------------------------------------------------------- #
try:
    from rich import box
    from rich.align import Align
    from rich.console import Console, Group
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.progress import (
        BarColumn,
        MofNCompleteColumn,
        Progress,
        TaskProgressColumn,
        TextColumn,
    )
    from rich.prompt import Confirm
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text
except ImportError:  # pragma: no cover - environment dependent
    sys.stderr.write(
        "\n[PurpleRecon] Missing required dependency 'rich'.\n"
        "Install it with:  python3 -m pip install rich\n\n"
    )
    raise SystemExit(1)

# nmap is *optional at import time*: if the python-nmap module or the nmap
# binary is unavailable we degrade Phase 2 to a built-in socket scanner.
try:
    import nmap  # type: ignore

    _HAVE_PYNMAP = True
except ImportError:
    nmap = None  # type: ignore
    _HAVE_PYNMAP = False


# --------------------------------------------------------------------------- #
# Constants & palette
# --------------------------------------------------------------------------- #
APP_NAME = "PURPLERECON"
VERSION = "1.0.0"
AUTHOR = "santhakumarParivallal"

# Industrial "cockpit" palette — restrained, signal-only accent colours.
C_AMBER = "#FFB300"   # energised / in-progress
C_GREEN = "#00E676"   # healthy / up / done
C_CRIMSON = "#D32F2F"  # critical / blocked / error
C_STEEL = "grey42"    # chrome / dim

# A small, high-signal set of TCP ports knocked during discovery. These are a
# *fallback* for hosts that block ICMP but expose a service (see DiscoveryEngine
# — ICMP is the primary signal, so this list is kept short for speed).
SWEEP_PORTS: tuple[int, ...] = (80, 443, 22, 445, 3389)

# A compact "top ports" list used by the built-in fallback scanner when nmap
# is unavailable, plus friendly service labels for both engines.
COMMON_SERVICES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 587: "submission", 631: "ipp", 993: "imaps", 995: "pop3s",
    1433: "ms-sql", 1521: "oracle", 2049: "nfs", 2375: "docker", 3000: "http-alt",
    3306: "mysql", 3389: "ms-wbt-server", 5060: "sip", 5432: "postgresql",
    5900: "vnc", 5985: "wsman", 6379: "redis", 8000: "http-alt", 8080: "http-proxy",
    8443: "https-alt", 9000: "http-alt", 9200: "elasticsearch", 11211: "memcached",
    27017: "mongodb",
}
FALLBACK_PORTS: tuple[int, ...] = tuple(sorted(COMMON_SERVICES))

# UI lifecycle states for a host row -> (glyph, style).
STATE_STYLE: dict[str, tuple[str, str]] = {
    "DISCOVERED": ("●", "bright_yellow"),
    "SCANNING": ("◐", C_AMBER),
    "DONE": ("✔", C_GREEN),
    "ERROR": ("✖", C_CRIMSON),
}

# Label for devices using a randomized / locally-administered MAC (modern phones
# with "private Wi-Fi address" — there is no real vendor to look up).
VENDOR_RANDOM = "(private/random)"

# A curated OUI→vendor subset of the IEEE registry so common devices get a
# vendor name out-of-the-box. For FULL coverage, download the IEEE registry
# (--download-oui) or pass --oui-file / drop an oui.csv next to this script.
_OUI_FALLBACK: dict[str, str] = {
    '00:04:3C': 'SONOS',
    '00:0F:15': 'Icotera',
    '00:1E:80': 'Icotera',
    '00:26:18': 'ASUSTek',
    '00:E0:4C': 'REALTEK',
    '04:09:86': 'Arcadyan',
    '04:92:26': 'ASUSTek',
    '08:C3:B3': 'TCL King Electrical',
    '0C:75:D2': 'Hangzhou Hikvision',
    '0C:B9:83': 'Honor Device',
    '10:06:1C': 'Espressif',
    '10:0C:6B': 'NETGEAR',
    '14:9C:EF': 'Texas Instruments',
    '14:D8:64': 'TP-LINK',
    '18:31:BF': 'ASUSTek',
    '18:A5:FF': 'Arcadyan',
    '1C:90:FF': 'Tuya Smart',
    '1C:E4:DD': 'Technicolor',
    '20:16:42': 'Microsoft',
    '24:29:34': 'Google',
    '24:48:45': 'Hangzhou Hikvision',
    '28:73:F6': 'Amazon',
    '28:BE:43': 'vivo Mobile',
    '2C:30:1A': 'Technicolor',
    '2C:9E:00': 'Sony Interactive',
    '2C:B3:01': 'Honor Device',
    '2C:BE:EB': 'Nothing',
    '2C:BE:EE': 'Nothing',
    '2C:D1:C6': 'Murata',
    '30:D1:6B': 'Liteon',
    '38:8A:06': 'Samsung',
    '3C:B0:ED': 'Nothing',
    '40:5D:82': 'NETGEAR',
    '40:8B:F6': 'Shenzhen TCL',
    '40:D4:F6': 'Honor Device',
    '40:F3:B0': 'Texas Instruments',
    '44:49:88': 'Intel',
    '48:1B:A4': 'Cisco',
    '48:D8:90': 'FN-LINK',
    '4C:C4:49': 'Icotera',
    '50:26:EF': 'Murata',
    '50:5A:65': 'AzureWave',
    '50:FE:0C': 'AzureWave',
    '54:2A:1B': 'Sonos',
    '54:44:3B': 'HUAWEI',
    '54:8C:81': 'Hangzhou Hikvision',
    '54:E0:19': 'Ring',
    '58:AD:12': 'Apple',
    '58:EF:68': 'Belkin',
    '58:FD:B1': 'LG',
    '5C:17:CF': 'OnePlus',
    '60:1A:C7': 'Nintendo',
    '60:70:6C': 'Google',
    '60:FD:A6': 'Apple',
    '64:1B:2F': 'Samsung',
    '64:EC:65': 'vivo Mobile',
    '68:DD:B7': 'TP-LINK',
    '6C:03:B5': 'Cisco',
    '6C:D1:99': 'vivo Mobile',
    '70:F8:AE': 'Microsoft',
    '78:28:CA': 'Sonos',
    '78:8A:20': 'Ubiquiti',
    '80:2A:A8': 'Ubiquiti',
    '80:48:2C': 'Wyze Labs',
    '80:C4:1B': 'Texas Instruments',
    '84:28:59': 'Amazon',
    '84:90:0A': 'Arcadyan',
    '8C:98:6B': 'Apple',
    '8C:D0:B2': 'Xiaomi',
    '9C:73:B1': 'Samsung',
    'A0:02:A5': 'Intel',
    'A0:91:A2': 'OnePlus',
    'A0:A3:F0': 'D-Link',
    'AC:5A:F0': 'LG',
    'AC:64:CF': 'FN-LINK',
    'AC:80:0A': 'Sony',
    'AC:84:C6': 'TP-LINK',
    'AC:9F:C3': 'Ring',
    'AC:C0:48': 'OnePlus',
    'B0:37:95': 'LG',
    'B0:A7:37': 'Roku',
    'B0:EE:7B': 'Roku',
    'B4:8C:9D': 'AzureWave',
    'B8:EA:98': 'Xiaomi',
    'BC:0F:9A': 'D-Link',
    'BC:22:28': 'D-Link',
    'BC:9E:BB': 'Nintendo',
    'C0:09:25': 'FN-Link',
    'C0:79:82': 'TCL King Electrical',
    'C4:61:C7': 'Microsoft',
    'C8:2A:DD': 'Google',
    'CC:5B:31': 'Nintendo',
    'CC:EB:5E': 'Xiaomi',
    'D0:39:57': 'Liteon',
    'D0:3F:27': 'Wyze Labs',
    'D0:4D:2C': 'Roku',
    'D4:8A:3B': 'HUNAN FN-LINK',
    'D4:8A:FC': 'Espressif',
    'D4:BA:FA': 'OPPO Mobile',
    'D8:3A:DD': 'Raspberry Pi',
    'D8:44:89': 'TP-Link',
    'D8:DA:F1': 'HUAWEI',
    'D8:EC:5E': 'Belkin',
    'DC:A6:32': 'Raspberry Pi',
    'DC:B4:CA': 'OPPO Mobile',
    'DC:EF:09': 'NETGEAR',
    'E0:06:30': 'HUAWEI',
    'E0:CB:1D': 'Amazon',
    'E4:40:97': 'OPPO Mobile',
    'E4:5F:01': 'Raspberry Pi',
    'E4:65:B8': 'Espressif',
    'E4:AE:E4': 'Tuya Smart',
    'E4:C7:67': 'Intel',
    'E8:0A:B9': 'Cisco',
    'E8:2A:44': 'Liteon',
    'E8:9F:80': 'Belkin',
    'F0:16:28': 'Technicolor',
    'F0:9F:C2': 'Ubiquiti',
    'F0:C8:8B': 'Wyze Labs',
    'F0:EE:7A': 'Apple',
    'F4:64:12': 'Sony Interactive',
    'FC:3C:D7': 'Tuya Smart',
    'FC:84:A7': 'Murata',
}


# --------------------------------------------------------------------------- #
# Custom exceptions
# --------------------------------------------------------------------------- #
class ScopeError(ValueError):
    """Raised when a requested target is forbidden or otherwise unscannable."""


# --------------------------------------------------------------------------- #
# Data models (normalised, JSON-serialisable asset records)
# --------------------------------------------------------------------------- #
@dataclass
class PortRecord:
    """A single discovered port/service on a host."""

    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = "unknown"
    product: str = ""
    version: str = ""


@dataclass
class HostRecord:
    """A normalised host asset, enriched as the pipeline progresses."""

    ip: str
    hostname: str | None = None
    os: str = "Unknown"
    status: str = "up"          # nmap-style reachability
    state: str = "DISCOVERED"   # UI lifecycle: DISCOVERED/SCANNING/DONE/ERROR
    discovered_via: str = ""    # e.g. "tcp/80", "icmp" or "arp"
    confidence: str = "strong"  # discovery confidence: "strong" | "weak"
    mac: str | None = None      # L2 address (from the ARP cache, local subnet)
    vendor: str | None = None   # OUI vendor, or "(private/random)" for randomized
    open_count: int = 0
    seed_ports: list[int] = field(default_factory=list)  # Phase-1 open knocks
    ports: list[PortRecord] = field(default_factory=list)
    error: str | None = None


# --------------------------------------------------------------------------- #
# Guardrails — the security-critical pre-scan validator (Requirement 5)
# --------------------------------------------------------------------------- #
class ScopeValidator:
    """Strictly validate a target specification before any packet is sent.

    The validator *hard-refuses* explicitly dangerous targets (loopback,
    multicast, broadcast, link-local, unspecified, reserved) so the tool can
    never be turned against the host it runs on, and caps the total host count
    so a fat-fingered CIDR cannot launch a runaway scan.
    """

    def __init__(self, max_hosts: int = 4096) -> None:
        self.max_hosts = max_hosts

    @staticmethod
    def _classify(
        addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
    ) -> str | None:
        """Return a human reason if ``addr`` is forbidden, else ``None``.

        Works for both IPv4 and IPv6 — the ``ipaddress`` properties below are
        defined on both, so loopback (``127.0.0.0/8`` / ``::1``), multicast
        (``224.0.0.0/4`` / ``ff00::/8``), link-local, unspecified and reserved
        space are all refused regardless of family.
        """
        if addr.is_loopback:
            return "loopback (127.0.0.0/8 or ::1)"
        if addr.is_multicast:
            return "multicast (224.0.0.0/4 or ff00::/8)"
        if addr.is_unspecified:
            return "unspecified (0.0.0.0 or ::)"
        if addr.is_link_local:
            return "link-local (169.254.0.0/16 or fe80::/10)"
        if addr.is_reserved:
            return "reserved / broadcast space"
        # The all-ones limited broadcast is reserved, but guard it explicitly.
        if isinstance(addr, ipaddress.IPv4Address) and int(addr) == 0xFFFFFFFF:
            return "limited broadcast (255.255.255.255)"
        return None

    def validate(self, spec: str) -> SimpleNamespace:
        """Parse ``spec`` (CIDR / IP / comma-list) into a vetted host list.

        Returns a namespace with ``hosts`` (list[str]), ``n_hosts``,
        ``has_public`` and ``blocked`` (list of ``(entry, reason)``).
        Raises :class:`ScopeError` on any explicitly forbidden entry, on
        unparseable input, on an empty result, or on an oversized scope.
        """
        if not spec or not spec.strip():
            raise ScopeError("No target supplied.")

        entries = [e.strip() for e in spec.split(",") if e.strip()]
        if not entries:
            raise ScopeError("Target specification is empty after parsing.")

        hosts: list[ipaddress.IPv4Address] = []
        blocked: list[tuple[str, str]] = []
        seen: set[int] = set()

        for entry in entries:
            network = self._parse_entry(entry)

            # Refuse a whole forbidden network (e.g. 127.0.0.0/8, 224.0.0.0/4)
            # or a single forbidden address, by inspecting its base address.
            base_reason = self._classify(network.network_address)
            if base_reason is not None:
                blocked.append((entry, base_reason))
                continue

            # Expand to usable hosts *lazily*.  ``.hosts()`` already excludes the
            # network and directed-broadcast addresses for prefixes shorter than
            # /31.  Using a generator (not list()) means an oversized CIDR like a
            # /8 trips the host cap below after a few thousand iterations instead
            # of trying to materialise ~16M addresses first.
            if network.num_addresses == 1:           # explicit single /32 host
                candidates: object = iter([network.network_address])
            elif network.prefixlen == 31:            # RFC 3021 point-to-point
                candidates = iter(network)
            else:
                candidates = network.hosts()

            for addr in candidates:
                reason = self._classify(addr)
                if reason is not None:
                    blocked.append((str(addr), reason))
                    continue
                key = int(addr)
                if key not in seen:
                    seen.add(key)
                    hosts.append(addr)

                # Fail fast on an oversized scope rather than building a huge
                # list in memory.
                if len(hosts) > self.max_hosts:
                    raise ScopeError(
                        f"Scope too large: more than {self.max_hosts} hosts. "
                        f"Narrow the range or raise --max-hosts (use with care)."
                    )

        # If the operator explicitly aimed *only* at forbidden space, stop hard.
        if not hosts:
            if blocked:
                reasons = ", ".join(sorted({r for _, r in blocked}))
                raise ScopeError(
                    f"All requested targets are forbidden ({reasons}). "
                    f"PurpleRecon refuses to scan protected address space."
                )
            raise ScopeError("No scannable hosts resolved from the target.")

        hosts.sort(key=int)
        has_public = any(not h.is_private for h in hosts)
        return SimpleNamespace(
            hosts=[str(h) for h in hosts],
            n_hosts=len(hosts),
            has_public=has_public,
            blocked=blocked,
        )

    @staticmethod
    def _parse_entry(entry: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
        """Parse a single entry into an IPv4 *or* IPv6 network.

        ``ip_network`` auto-detects the family. An oversized IPv6 prefix (e.g. a
        ``/64``) is not rejected here — it simply trips the host cap in
        :meth:`validate` once expansion exceeds ``max_hosts``, which is the
        correct behaviour (you can't sweep 2^64 addresses).
        """
        try:
            # strict=False lets the user pass a host bit set in a CIDR.
            return ipaddress.ip_network(entry, strict=False)
        except ValueError as exc:
            raise ScopeError(f"Invalid target '{entry}': {exc}") from exc


# --------------------------------------------------------------------------- #
# Thread-safe shared state (the single source of truth the cockpit renders)
# --------------------------------------------------------------------------- #
class SharedState:
    """All mutable scan state, guarded by a lock for the worker/render split.

    Worker threads mutate it through the small, locked API below; the render
    loop reads a consistent :meth:`snapshot` so it never tears a frame.
    """

    def __init__(self, target: str, privileged: bool, engine_label: str) -> None:
        self._lock = threading.Lock()
        self.target = target
        self.privileged = privileged
        self.engine_label = engine_label
        self.started_dt = datetime.now(timezone.utc)
        self._t0 = time.monotonic()
        self.phase = "INITIALISING"
        self.sweep_total = 0
        self.sweep_done = 0
        self.enum_total = 0
        self.enum_done = 0
        self._hosts: dict[str, HostRecord] = {}
        self._log: deque[str] = deque(maxlen=4)
        self._aborted = False
        self._done = False

    # -- mutation API (each call is atomic) -------------------------------- #
    def set_phase(self, phase: str) -> None:
        with self._lock:
            self.phase = phase

    def set_sweep_total(self, total: int) -> None:
        with self._lock:
            self.sweep_total = total

    def mark_swept(self, count: int = 1) -> None:
        with self._lock:
            self.sweep_done += count

    def add_live_host(
        self, ip: str, via: str, seed_ports: list[int], confidence: str = "strong"
    ) -> None:
        with self._lock:
            if ip not in self._hosts:
                self._hosts[ip] = HostRecord(
                    ip=ip,
                    state="DISCOVERED",
                    discovered_via=via,
                    confidence=confidence,
                    seed_ports=sorted(seed_ports),
                    open_count=len(seed_ports),
                )

    def set_enum_total(self, total: int) -> None:
        with self._lock:
            self.enum_total = total

    def mark_enum_done(self, count: int = 1) -> None:
        with self._lock:
            self.enum_done += count

    def set_host_state(self, ip: str, state: str, error: str | None = None) -> None:
        with self._lock:
            host = self._hosts.get(ip)
            if host is not None:
                host.state = state
                if error is not None:
                    host.error = error

    def set_host_mac(self, ip: str, mac: str) -> None:
        with self._lock:
            host = self._hosts.get(ip)
            if host is not None and not host.mac:
                host.mac = mac

    def set_host_hostname(self, ip: str, hostname: str) -> None:
        with self._lock:
            host = self._hosts.get(ip)
            if host is not None and not host.hostname:
                host.hostname = hostname

    def set_host_vendor(self, ip: str, vendor: str | None) -> None:
        with self._lock:
            host = self._hosts.get(ip)
            if host is not None and vendor and not host.vendor:
                host.vendor = vendor

    def update_host_record(self, record: HostRecord) -> None:
        """Replace a host's enriched fields after Phase 2 completes."""
        with self._lock:
            existing = self._hosts.get(record.ip)
            if existing is None:
                self._hosts[record.ip] = record
                return
            existing.hostname = record.hostname or existing.hostname
            existing.os = record.os
            existing.status = record.status
            existing.ports = record.ports
            existing.open_count = len(record.ports)
            existing.state = "DONE"
            existing.error = record.error

    def push_log(self, message: str) -> None:
        with self._lock:
            stamp = time.strftime("%H:%M:%S")
            self._log.append(f"{stamp}  {message}")

    def abort(self) -> None:
        with self._lock:
            self._aborted = True

    def finish(self) -> None:
        with self._lock:
            self._done = True

    # -- read API ---------------------------------------------------------- #
    def is_aborted(self) -> bool:
        with self._lock:
            return self._aborted

    def is_done(self) -> bool:
        with self._lock:
            return self._done

    def live_ips(self) -> list[str]:
        with self._lock:
            return sorted(self._hosts, key=lambda s: tuple(int(o) for o in s.split(".")))

    def live_count(self) -> int:
        with self._lock:
            return len(self._hosts)

    def seed_ports_of(self, ip: str) -> list[int]:
        with self._lock:
            host = self._hosts.get(ip)
            return list(host.seed_ports) if host else []

    def hosts(self) -> list[HostRecord]:
        with self._lock:
            return [copy.copy(h) for h in self._hosts.values()]

    def snapshot(self) -> SimpleNamespace:
        """Return an immutable, render-safe view of the whole state."""
        with self._lock:
            return SimpleNamespace(
                target=self.target,
                privileged=self.privileged,
                engine_label=self.engine_label,
                phase=self.phase,
                elapsed=time.monotonic() - self._t0,
                sweep_total=self.sweep_total,
                sweep_done=self.sweep_done,
                enum_total=self.enum_total,
                enum_done=self.enum_done,
                hosts=[copy.copy(h) for h in self._hosts.values()],
                live=len(self._hosts),
                log=list(self._log),
                aborted=self._aborted,
                done=self._done,
            )


# --------------------------------------------------------------------------- #
# Phase 1 — high-speed horizontal discovery (sockets + ICMP, threaded)
# --------------------------------------------------------------------------- #
class DiscoveryEngine:
    """Find live hosts quickly and *without requiring root* — with a deliberate
    bias against false positives.

    Liveness is graded by **confidence**, because not every "response" proves a
    host is really there:

      * ``strong`` — a *completed* TCP handshake (a real listening service) or
        an ICMP echo reply.  Neither can be forged by a silent ``drop`` firewall,
        so these are trusted.
      * ``weak``   — only a TCP **RST** (connection refused) was observed.  A
        real host with a closed port produces this, but a ``reject``-style
        firewall *also* sends RSTs on behalf of **dead** addresses — which makes
        every IP in a protected range look "up".  This is the classic discovery
        false positive, so weak-only hosts are **suppressed by default** and
        reported only when ``rst_up=True`` (CLI ``--rst-up``).

    Probing is fanned out across a thread pool for speed.
    """

    # connect_ex returns this errno on a TCP RST (the ambiguous "weak" signal).
    _UP_ERRNOS = {errno.ECONNREFUSED}

    def __init__(
        self,
        timeout: float,
        workers: int,
        use_ping: bool,
        rst_up: bool = False,
        ping_timeout: float = 3.0,
        ping_attempts: int = 2,
        use_arp: bool = True,
        oui_table: dict[str, str] | None = None,
    ) -> None:
        self.timeout = max(0.05, timeout)
        self.workers = max(1, workers)
        self.use_ping = use_ping and _ping_available()
        self.rst_up = rst_up
        # Generous ICMP timeout + a retry: high-latency Wi-Fi devices answer
        # slowly and packets are sometimes lost.
        self.ping_timeout = max(1.0, ping_timeout)
        self.ping_attempts = max(1, ping_attempts)
        # ARP-cache discovery catches local devices that ignore ICMP entirely.
        self.use_arp = use_arp
        self.oui_table = oui_table or {}

    @staticmethod
    def _decide(strong: bool, saw_rst: bool, rst_up: bool) -> tuple[bool, str]:
        """Pure liveness policy — extracted so it can be unit-tested.

        Returns ``(is_up, confidence)``.  A strong signal always wins; a
        RST-only ("weak") host counts as up only when the operator opted in.
        """
        if strong:
            return True, "strong"
        if saw_rst:
            return (True, "weak") if rst_up else (False, "weak")
        return False, "none"

    def is_alive(self, ip: str) -> tuple[bool, str, list[int], str]:
        """Probe one host -> ``(up, discovered_via, open_ports, confidence)``.

        ICMP is tried **first**: most end-user devices (phones, tablets, IoT)
        expose no open ports but answer echo — just slowly. A TCP knock is the
        fallback for hosts that block ICMP but run a service.
        """
        # 1) ICMP echo — primary, trusted, and tolerant of slow Wi-Fi replies.
        if self.use_ping and self._ping(ip):
            return True, "icmp", [], "strong"

        # 2) TCP knock — for ICMP-blocked hosts/servers; grades a RST as weak.
        open_ports: list[int] = []
        via = ""
        strong = False
        saw_rst = False
        for port in SWEEP_PORTS:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.timeout)
                    rc = sock.connect_ex((ip, port))
            except OSError:
                # Per-port failures (no route, etc.) are non-fatal; keep going.
                continue
            if rc == 0:                    # full handshake — a real open service
                open_ports.append(port)
                strong = True
                if not via:
                    via = f"tcp/{port}"
            elif rc in self._UP_ERRNOS:    # RST — ambiguous (host *or* firewall)
                saw_rst = True

        up, confidence = self._decide(strong, saw_rst, self.rst_up)
        if up and confidence == "weak":
            via = "tcp-rst (unconfirmed)"
        return up, via, open_ports, confidence

    def sweep(self, hosts: list[str], state: SharedState) -> None:
        """Probe every candidate host, recording confirmed live ones."""
        state.set_sweep_total(len(hosts))
        candidates = set(hosts)
        suppressed = 0
        pool = ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="sweep")
        try:
            futures = {pool.submit(self.is_alive, ip): ip for ip in hosts}
            for future in as_completed(futures):
                if state.is_aborted():
                    break
                ip = futures[future]
                state.mark_swept()
                try:
                    up, via, open_ports, confidence = future.result()
                except Exception:  # defensive: never let one host kill the sweep
                    up, via, open_ports, confidence = False, "", [], "none"
                if up:
                    state.add_live_host(ip, via, open_ports, confidence)
                elif confidence == "weak":
                    suppressed += 1
        finally:
            # Cancel anything still queued; let in-flight probes drain quickly.
            pool.shutdown(wait=False, cancel_futures=True)

        # Tell the operator *why* RST-only hosts didn't show — and how to see them.
        if suppressed and not self.rst_up:
            state.push_log(
                f"Suppressed {suppressed} RST-only host(s) — likely a firewall; "
                f"re-run with --rst-up to include them"
            )

        # ARP pass: the active probe above forced the OS to ARP every candidate.
        # Any in-scope IP now resolved to a real MAC is *definitively* present on
        # the local segment — even if it ignored ICMP (Wi-Fi power-save devices).
        if self.use_arp and not state.is_aborted():
            scoped = {ip: mac for ip, mac in _read_arp_table().items() if ip in candidates}
            # Proxy-ARP guard: a router that answers ARP for the whole subnet with
            # a single MAC would otherwise mark every address "live".
            proxy = _proxy_macs(scoped, max(8, len(candidates) // 10))
            if proxy:
                state.push_log(
                    f"Proxy-ARP detected — {len(proxy)} MAC(s) answer for many IPs; "
                    f"ignoring those ARP entries (set may be client-isolated)"
                )
            before = state.live_count()
            for ip, mac in scoped.items():
                if mac in proxy:
                    continue  # router proxying — not a distinct device
                state.add_live_host(ip, "arp", [], "strong")  # idempotent
                state.set_host_mac(ip, mac)
                state.set_host_vendor(ip, _mac_vendor(mac, self.oui_table))
            gained = state.live_count() - before
            if gained:
                state.push_log(
                    f"ARP discovery added {gained} host(s) that answer ARP but not ICMP"
                )

    def _ping(self, ip: str) -> bool:
        """Unprivileged ICMP echo (system ``ping``): generous timeout + retry.

        Returns True on the first successful echo across ``ping_attempts`` tries
        — the retry absorbs the packet loss that is normal on busy Wi-Fi.
        """
        cmd = _ping_command(ip, self.ping_timeout)
        deadline = self.ping_timeout + 1.0
        for _ in range(self.ping_attempts):
            try:
                result = subprocess.run(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=deadline,
                    check=False,
                )
                if result.returncode == 0:
                    return True
            except (subprocess.TimeoutExpired, OSError):
                continue
        return False


# --------------------------------------------------------------------------- #
# Phase 2 — vertical deep-dive enumeration (nmap, threaded) with fallback
# --------------------------------------------------------------------------- #
class EnumerationEngine:
    """Run service/version detection on the live hosts from Phase 1.

    Uses python-nmap when available; otherwise degrades to a built-in socket
    connect-scan with light banner grabbing so the tool still produces useful
    output on a host with neither nmap nor root.
    """

    def __init__(
        self,
        nmap_args: str,
        workers: int,
        have_nmap: bool,
        connect_timeout: float = 0.6,
    ) -> None:
        self.nmap_args = nmap_args
        self.workers = max(1, workers)
        self.have_nmap = have_nmap
        self.connect_timeout = connect_timeout

    def run(self, live_ips: list[str], state: SharedState) -> None:
        """Enumerate all live hosts concurrently, updating ``state`` live."""
        state.set_enum_total(len(live_ips))
        pool = ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="nmap")
        try:
            futures = {
                pool.submit(self._enumerate_one, ip, state): ip for ip in live_ips
            }
            for future in as_completed(futures):
                if state.is_aborted():
                    break
                state.mark_enum_done()
                # Exceptions are handled inside ``_enumerate_one``; result() is
                # called only to surface programming errors during development.
                future.result()
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

    def _enumerate_one(self, ip: str, state: SharedState) -> None:
        """Scan a single host, never raising into the worker pool."""
        state.set_host_state(ip, "SCANNING")
        try:
            if self.have_nmap:
                record = self._nmap_scan(ip)
            else:
                record = self._socket_scan(ip, state.seed_ports_of(ip))
            state.update_host_record(record)
            state.push_log(f"{ip}: {record.open_count} open port(s) — {record.os}")
        except Exception as exc:  # noqa: BLE001 - convert any failure to a state
            state.set_host_state(ip, "ERROR", error=str(exc))
            state.push_log(f"{ip}: enumeration error ({type(exc).__name__})")

    # -- nmap-backed scan -------------------------------------------------- #
    def _nmap_scan(self, ip: str) -> HostRecord:
        scanner = nmap.PortScanner()  # type: ignore[union-attr]
        scanner.scan(hosts=ip, arguments=self.nmap_args)

        if ip not in scanner.all_hosts():
            return HostRecord(ip=ip, status="down", state="DONE", os="Unknown")

        node = scanner[ip]
        ports: list[PortRecord] = []
        for proto in node.all_protocols():
            for port in sorted(node[proto]):
                info = node[proto][port]
                if info.get("state") not in ("open", "open|filtered"):
                    continue
                version = " ".join(
                    part
                    for part in (info.get("version", ""), info.get("extrainfo", ""))
                    if part
                ).strip()
                ports.append(
                    PortRecord(
                        port=int(port),
                        protocol=proto,
                        state=info.get("state", "open"),
                        service=info.get("name") or COMMON_SERVICES.get(port, "unknown"),
                        product=info.get("product", ""),
                        version=version,
                    )
                )

        return HostRecord(
            ip=ip,
            hostname=node.hostname() or None,
            os=self._detect_os(node, ports),
            status="up",
            state="DONE",
            open_count=len(ports),
            ports=ports,
        )

    @staticmethod
    def _detect_os(node, ports: list[PortRecord]) -> str:
        """Best-effort OS label: nmap -O match, else CPE, else banner keyword."""
        osmatch = node.get("osmatch") or []
        if osmatch:
            return osmatch[0].get("name", "Unknown")

        # Look for an OS-type CPE produced by service detection (no root needed).
        for proto in node.all_protocols():
            for port in node[proto]:
                cpe = node[proto][port].get("cpe", "")
                values = cpe if isinstance(cpe, list) else [cpe]
                for value in values:
                    if isinstance(value, str) and value.startswith("cpe:/o:"):
                        seg = value.replace("cpe:/o:", "").split(":")
                        product = seg[1].replace("_", " ").title() if len(seg) > 1 else ""
                        ver = seg[2] if len(seg) > 2 else ""
                        return f"{product} {ver}".strip() or "Unknown"

        haystack = " ".join(f"{p.service} {p.product} {p.version}" for p in ports).lower()
        for needle, label in (
            ("ubuntu", "Linux (Ubuntu)"), ("debian", "Linux (Debian)"),
            ("centos", "Linux (CentOS)"), ("windows", "Windows"),
            ("freebsd", "FreeBSD"), ("mikrotik", "RouterOS"), ("cisco", "Cisco IOS"),
        ):
            if needle in haystack:
                return label
        return "Unknown"

    # -- built-in fallback scan (no nmap) ---------------------------------- #
    def _socket_scan(self, ip: str, seed_ports: list[int]) -> HostRecord:
        """A minimal connect-scan + banner grab used when nmap is absent."""
        targets = sorted(set(FALLBACK_PORTS) | set(seed_ports))
        ports: list[PortRecord] = []
        for port in targets:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.connect_timeout)
                    if sock.connect_ex((ip, port)) != 0:
                        continue
                    banner = self._grab_banner(sock)
                ports.append(
                    PortRecord(
                        port=port,
                        service=COMMON_SERVICES.get(port, "unknown"),
                        product=banner,
                    )
                )
            except OSError:
                continue
        return HostRecord(
            ip=ip,
            hostname=_reverse_dns(ip),
            os="Unknown",
            status="up",
            state="DONE",
            open_count=len(ports),
            ports=ports,
        )

    @staticmethod
    def _grab_banner(sock: socket.socket) -> str:
        """Read a short, printable, single-line banner without blocking long."""
        try:
            sock.settimeout(0.6)
            data = sock.recv(96)
        except OSError:
            return ""
        if not data:
            return ""
        # latin-1 maps every byte, so a non-empty buffer yields a non-empty
        # string and ``splitlines()[0]`` is always safe.
        first_line = data.decode("latin-1", "ignore").splitlines()[0]
        return "".join(ch for ch in first_line if ch.isprintable()).strip()


# --------------------------------------------------------------------------- #
# Orchestrator — drives the two phases and keeps the cockpit fed
# --------------------------------------------------------------------------- #
class Orchestrator:
    """Run Phase 1 then Phase 2, recording progress into shared state."""

    def __init__(
        self,
        state: SharedState,
        hosts: list[str],
        discovery: DiscoveryEngine,
        enumeration: EnumerationEngine,
        discover_only: bool = False,
    ) -> None:
        self.state = state
        self.hosts = hosts
        self.discovery = discovery
        self.enumeration = enumeration
        self.discover_only = discover_only

    def execute(self) -> None:
        """Background entry point; converts any failure into a clean state."""
        try:
            self.state.set_phase("PHASE 1 · HORIZONTAL SWEEP")
            self.state.push_log(f"Sweeping {len(self.hosts)} candidate host(s)")
            self.discovery.sweep(self.hosts, self.state)

            live = self.state.live_ips()
            self.state.push_log(f"Discovery complete — {len(live)} live host(s)")

            if self.state.is_aborted():
                self.state.set_phase("ABORTED")
                return

            # Discovery-only mode: resolve hostnames, then stop (no nmap).
            if self.discover_only:
                if live:
                    self.state.set_phase("RESOLVING HOSTNAMES")
                    resolve_hostnames(self.state)
                self.state.set_phase("COMPLETE")
                return

            self.state.set_phase("PHASE 2 · NMAP ENUMERATION")
            if live:
                self.enumeration.run(live, self.state)
            else:
                self.state.push_log("No live hosts — skipping deep-dive")

            self.state.set_phase("ABORTED" if self.state.is_aborted() else "COMPLETE")
        except Exception as exc:  # noqa: BLE001 - last-resort guard for the thread
            self.state.push_log(f"FATAL: {type(exc).__name__}: {exc}")
            self.state.set_phase("ERROR")
        finally:
            self.state.finish()


# --------------------------------------------------------------------------- #
# Cockpit renderer — builds the rich Layout from a state snapshot
# --------------------------------------------------------------------------- #
def _phase_style(phase: str) -> str:
    if phase.startswith(("PHASE 1", "PHASE 2", "INITIAL")):
        return f"bold {C_AMBER}"
    if phase == "COMPLETE":
        return f"bold {C_GREEN}"
    if phase in ("ERROR", "ABORTED"):
        return f"bold {C_CRIMSON}"
    return "bold white"


def _render_header(snap: SimpleNamespace) -> Panel:
    """Fixed status header: brand, operator, target, phase and live counters."""
    brand = Text()
    brand.append("⬢ PURPLE", style=f"bold {C_CRIMSON}")
    brand.append("RECON", style=f"bold {C_GREEN}")
    brand.append(f"  v{VERSION}\n", style="bold white")
    brand.append("Two-Tiered Purple-Team Asset Mapper\n", style="dim")
    brand.append("Operator: ", style="dim")
    brand.append(AUTHOR, style=C_AMBER)

    mode = "ROOT" if snap.privileged else "UNPRIVILEGED"
    mode_style = C_GREEN if snap.privileged else C_AMBER
    stats = Text()
    stats.append("TARGET    ", style="dim")
    stats.append(f"{snap.target}\n", style="white")
    stats.append("PHASE     ", style="dim")
    stats.append(f"{snap.phase}\n", style=_phase_style(snap.phase))
    stats.append("ENGINE    ", style="dim")
    stats.append(f"{snap.engine_label}   ", style="white")
    stats.append(f"[{mode}]\n", style=mode_style)
    stats.append("LIVE      ", style="dim")
    stats.append(f"{snap.live}", style=f"bold {C_GREEN}")
    stats.append(f" / {snap.sweep_total} candidates", style="white")
    stats.append("    ELAPSED ", style="dim")
    stats.append(f"{snap.elapsed:5.1f}s", style="white")

    grid = Table.grid(expand=True, padding=(0, 1))
    grid.add_column(justify="left", ratio=1)
    grid.add_column(justify="right", ratio=1)
    grid.add_row(brand, Align.right(stats))
    return Panel(grid, box=box.HEAVY, border_style=C_STEEL, padding=(0, 1))


def _render_body(snap: SimpleNamespace) -> Panel:
    """The live, central asset matrix (the primary focus of the cockpit)."""
    table = Table(
        box=box.SIMPLE_HEAVY,
        expand=True,
        header_style=f"bold {C_STEEL}",
        border_style="grey23",
        pad_edge=False,
    )
    table.add_column(" ", width=2, justify="center")
    table.add_column("IP ADDRESS", style="bold white", no_wrap=True)
    table.add_column("HOSTNAME", style="cyan", no_wrap=True)
    table.add_column("OS / DEVICE", no_wrap=True)
    table.add_column("OPEN", justify="right", width=5)
    table.add_column("SERVICES", overflow="ellipsis", no_wrap=True)
    table.add_column("STATE", justify="right", no_wrap=True)

    hosts = sorted(snap.hosts, key=lambda h: tuple(int(o) for o in h.ip.split(".")))
    for host in hosts:
        glyph, style = STATE_STYLE.get(host.state, ("?", "white"))
        services = _services_summary(host)
        open_style = C_AMBER if host.open_count else "dim"
        table.add_row(
            Text(glyph, style=style),
            host.ip,
            host.hostname or "—",
            _os_cell(host),
            Text(str(host.open_count), style=open_style),
            services,
            Text(f"{glyph} {host.state}", style=style),
        )

    if not hosts:
        hint = "Awaiting Phase 1 discovery…" if snap.phase.startswith("PHASE 1") \
            else "No live hosts discovered in scope."
        body: object = Align.center(Text(hint, style="dim"), vertical="middle")
    else:
        body = table

    return Panel(
        body,
        title=f"[bold]LIVE ASSET MATRIX[/]  ·  [{C_GREEN}]{len(hosts)}[/] host(s)",
        title_align="left",
        border_style=C_STEEL,
        box=box.HEAVY,
        padding=(0, 1),
    )


def _render_footer(snap: SimpleNamespace) -> Panel:
    """Progress bars for both phases, a rolling log, and the safety notice."""
    progress = Progress(
        TextColumn("[bold]{task.description}"),
        BarColumn(bar_width=None, complete_style=C_AMBER, finished_style=C_GREEN),
        MofNCompleteColumn(),
        TaskProgressColumn(),
        expand=True,
        auto_refresh=False,
    )
    progress.add_task(
        "PHASE 1 · SWEEP", total=max(snap.sweep_total, 1), completed=snap.sweep_done
    )
    progress.add_task(
        "PHASE 2 · NMAP ",
        total=max(snap.enum_total, 1),
        completed=snap.enum_done,
    )

    log_text = Text("\n".join(snap.log) or "Ready.", style="dim")
    notice = Text(
        "⚠  Authorized use only — scan assets you own or are explicitly permitted to test.",
        style=f"dim {C_AMBER}",
    )
    group = Group(progress, Rule(style="grey23"), log_text, notice)
    return Panel(group, box=box.HEAVY, border_style=C_STEEL, padding=(0, 1))


def render_dashboard(snap: SimpleNamespace) -> Layout:
    """Assemble the full cockpit layout for one frame."""
    layout = Layout(name="root")
    layout.split_column(
        Layout(_render_header(snap), name="header", size=7),
        Layout(_render_body(snap), name="body", ratio=1),
        Layout(_render_footer(snap), name="footer", size=10),
    )
    return layout


def _services_summary(host: HostRecord, limit: int = 5) -> Text:
    """Compact, coloured list of the host's services for the grid."""
    if host.state in ("DISCOVERED", "SCANNING") and not host.ports:
        seeds = ", ".join(COMMON_SERVICES.get(p, str(p)) for p in host.seed_ports[:limit])
        return Text(seeds or "probing…", style="dim")
    names = []
    for port in host.ports[:limit]:
        label = port.service if port.service != "unknown" else str(port.port)
        names.append(label)
    extra = len(host.ports) - len(names)
    text = Text(", ".join(names), style="white")
    if extra > 0:
        text.append(f"  +{extra}", style="dim")
    return text if names else Text("—", style="dim")


def _os_cell(host: HostRecord) -> Text:
    if host.error:
        return Text("scan error", style=C_CRIMSON)
    style = "white" if host.os and host.os != "Unknown" else "dim"
    return Text(host.os or "Unknown", style=style)


def render_device_list(snap: SimpleNamespace) -> Panel:
    """A clean, Angry-IP-style inventory of every device found on the network."""
    table = Table(
        box=box.SIMPLE_HEAVY,
        expand=True,
        header_style=f"bold {C_STEEL}",
        border_style="grey23",
        pad_edge=False,
    )
    table.add_column("#", width=3, justify="right", style="dim")
    table.add_column(" ", width=2, justify="center")
    table.add_column("IP ADDRESS", style="bold white", no_wrap=True)
    table.add_column("VENDOR", no_wrap=True)
    table.add_column("HOSTNAME", no_wrap=True)
    table.add_column("MAC ADDRESS", style="cyan", no_wrap=True)
    table.add_column("VIA", justify="right", no_wrap=True)

    hosts = sorted(snap.hosts, key=lambda h: _ip_key(h.ip))
    for index, host in enumerate(hosts, start=1):
        if not host.vendor:
            vendor = Text("—", style="dim")
        elif host.vendor == VENDOR_RANDOM:
            vendor = Text(host.vendor, style="dim italic")
        else:
            vendor = Text(host.vendor, style="white")
        # Wrap raw data in Text() so rich does NOT treat e.g. ':ab:' in a MAC as
        # an emoji shortcode (or any ':...:'/'[...]' as markup).
        table.add_row(
            str(index),
            Text("●", style=C_GREEN),
            Text(host.ip),
            vendor,
            Text(host.hostname or "—", style="white" if host.hostname else "dim"),
            Text(host.mac or "—"),
            Text(host.discovered_via or "—"),
        )

    body: object = table if hosts else Align.center(
        Text("No devices discovered on this network.", style="dim"), vertical="middle"
    )
    return Panel(
        body,
        title=f"[bold]NETWORK DEVICES[/]  ·  [{C_GREEN}]{len(hosts)}[/] online",
        title_align="left",
        border_style=C_GREEN,
        box=box.HEAVY,
        padding=(0, 1),
    )


# --------------------------------------------------------------------------- #
# Run modes: interactive cockpit (Live) and non-interactive fallback
# --------------------------------------------------------------------------- #
def run_cockpit(state: SharedState, orchestrator: Orchestrator, console: Console) -> None:
    """Drive the scan with a full-screen, real-time rich Live dashboard."""
    worker = threading.Thread(target=orchestrator.execute, name="orchestrator", daemon=True)
    try:
        with Live(
            render_dashboard(state.snapshot()),
            console=console,
            screen=True,
            refresh_per_second=8,
            transient=False,
        ) as live:
            worker.start()
            while worker.is_alive():
                live.update(render_dashboard(state.snapshot()))
                time.sleep(0.12)
            live.update(render_dashboard(state.snapshot()))  # final frame
    except KeyboardInterrupt:
        state.abort()
        console.print(f"[bold {C_AMBER}]Operator abort — exporting partial results…[/]")
    finally:
        worker.join(timeout=5)


def run_headless(state: SharedState, orchestrator: Orchestrator, console: Console) -> None:
    """Non-interactive fallback (pipes / CI / non-TTY): concise log + final grid."""
    worker = threading.Thread(target=orchestrator.execute, name="orchestrator", daemon=True)
    worker.start()
    last_phase = None
    last_tick = 0.0
    try:
        while worker.is_alive():
            snap = state.snapshot()
            if snap.phase != last_phase:
                console.print(f"[bold]{snap.phase}[/]", highlight=False)
                last_phase = snap.phase
            now = time.monotonic()
            if now - last_tick > 1.5:
                console.print(
                    f"  sweep {snap.sweep_done}/{snap.sweep_total} · "
                    f"live {snap.live} · enum {snap.enum_done}/{snap.enum_total}",
                    style="dim",
                    highlight=False,
                )
                last_tick = now
            time.sleep(0.3)
    except KeyboardInterrupt:
        state.abort()
        console.print(f"[bold {C_AMBER}]Operator abort — exporting partial results…[/]")
    finally:
        worker.join(timeout=5)


# --------------------------------------------------------------------------- #
# Reporting & export
# --------------------------------------------------------------------------- #
def build_report(
    state: SharedState,
    scope: SimpleNamespace,
    started: datetime,
    finished: datetime,
) -> dict:
    """Assemble the normalised, JSON-serialisable scan report (no I/O)."""
    hosts = sorted(state.hosts(), key=lambda h: _ip_key(h.ip))
    total_open = sum(h.open_count for h in hosts)
    return {
        "tool": APP_NAME,
        "version": VERSION,
        "author": AUTHOR,
        "target": state.target,
        "privileged": state.privileged,
        "engine": state.engine_label,
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "duration_seconds": round((finished - started).total_seconds(), 2),
        "summary": {
            "candidates": scope.n_hosts,
            "live_hosts": len(hosts),
            "total_open_ports": total_open,
            "blocked_entries": [{"entry": e, "reason": r} for e, r in scope.blocked],
        },
        "hosts": [asdict(h) for h in hosts],
    }


def write_report(report: dict, output_dir: str) -> str:
    """Atomically serialise ``report`` to a timestamped JSON file (mode 0600)."""
    os.makedirs(output_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe_target = _sanitize_filename(str(report.get("target", "scan")))
    path = os.path.join(output_dir, f"purplerecon_{safe_target}_{stamp}.json")

    # Atomic write: serialise to a temp file, fsync, then rename into place.
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp_path, path)
    try:
        os.chmod(path, 0o600)  # least-privilege: owner read/write only
    except OSError:
        pass  # best effort (e.g. unsupported filesystem)
    return path


# --------------------------------------------------------------------------- #
# Alternative export formats — CSV (spreadsheet) and self-contained HTML.
# Both are written atomically (temp → fsync → rename, mode 0600), like the JSON.
# --------------------------------------------------------------------------- #
def _timestamped_path(report: dict, output_dir: str, ext: str) -> str:
    """Build the standard ``purplerecon_<target>_<stamp>.<ext>`` output path."""
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe_target = _sanitize_filename(str(report.get("target", "scan")))
    return os.path.join(output_dir, f"purplerecon_{safe_target}_{stamp}.{ext}")


def _atomic_write_text(path: str, data: str, newline: str = "") -> None:
    """Atomically write ``data`` to ``path`` (temp → fsync → rename, mode 0600)."""
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8", newline=newline) as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp_path, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def csv_rows(report: dict) -> list[list[str]]:
    """Flatten a report into spreadsheet rows.

    One row per open port; a host with no open ports still gets one row (empty
    port columns) so *every* discovered device appears in the inventory.
    """
    header = [
        "ip", "hostname", "os", "mac", "vendor", "via",
        "port", "protocol", "state", "service", "version",
    ]
    rows: list[list[str]] = [header]
    for host in report.get("hosts", []):
        base = [
            host.get("ip", ""),
            host.get("hostname") or "",
            host.get("os", ""),
            host.get("mac") or "",
            host.get("vendor") or "",
            host.get("discovered_via", ""),
        ]
        ports = host.get("ports") or []
        if not ports:
            rows.append(base + ["", "", "", "", ""])
            continue
        for port in ports:
            version = " ".join(
                x for x in (port.get("product", ""), port.get("version", "")) if x
            ).strip()
            rows.append(
                base
                + [
                    str(port.get("port", "")),
                    port.get("protocol", "tcp"),
                    port.get("state", "open"),
                    port.get("service", ""),
                    version,
                ]
            )
    return rows


def write_csv_report(report: dict, output_dir: str) -> str:
    """Write the flat per-port CSV inventory; returns the path."""
    import io

    os.makedirs(output_dir, exist_ok=True)
    path = _timestamped_path(report, output_dir, "csv")
    buffer = io.StringIO()
    csv.writer(buffer).writerows(csv_rows(report))
    _atomic_write_text(path, buffer.getvalue(), newline="")
    return path


def render_html_report(report: dict) -> str:
    """Render a self-contained, dark-themed HTML report (no external assets).

    Pure function (returns the HTML string) so it can be unit-tested without
    touching the filesystem. Every user-controlled value is HTML-escaped.
    """
    esc = html.escape
    summary = report.get("summary", {}) or {}
    hosts = report.get("hosts", []) or []

    def card(label: str, value: object, accent: str) -> str:
        return (
            f'<div class="card"><div class="cval" style="color:{accent}">'
            f"{esc(str(value))}</div><div class=\"clbl\">{esc(label)}</div></div>"
        )

    cards = "".join(
        [
            card("Live hosts", summary.get("live_hosts", len(hosts)), "#00E676"),
            card("Candidates", summary.get("candidates", "—"), "#e7e9ee"),
            card("Open ports", summary.get("total_open_ports", 0), "#FFB300"),
            card("Duration", f"{report.get('duration_seconds', '?')}s", "#e7e9ee"),
        ]
    )

    # Device inventory rows.
    inv_rows: list[str] = []
    for index, host in enumerate(hosts, start=1):
        ports = host.get("ports") or []
        port_summary = ", ".join(
            f"{p.get('port')}/{p.get('service', '')}".rstrip("/") for p in ports
        ) or "—"
        inv_rows.append(
            "<tr>"
            f'<td class="dim">{index}</td>'
            f'<td class="mono">{esc(host.get("ip", ""))}</td>'
            f"<td>{esc(host.get('vendor') or '—')}</td>"
            f"<td>{esc(host.get('hostname') or '—')}</td>"
            f"<td>{esc(host.get('os') or 'Unknown')}</td>"
            f'<td class="mono dim">{esc(host.get("mac") or "—")}</td>'
            f'<td class="dim">{esc(host.get("discovered_via") or "—")}</td>'
            f'<td class="mono">{esc(port_summary)}</td>'
            "</tr>"
        )
    inventory = "\n".join(inv_rows) or (
        '<tr><td colspan="8" class="dim">No devices discovered.</td></tr>'
    )

    # Per-host service detail (only for hosts that actually exposed ports).
    detail_blocks: list[str] = []
    for host in hosts:
        ports = host.get("ports") or []
        if not ports:
            continue
        prows = "\n".join(
            "<tr>"
            f'<td class="mono">{esc(str(p.get("port", "")))}</td>'
            f"<td>{esc(p.get('protocol', 'tcp'))}</td>"
            f"<td>{esc(p.get('state', 'open'))}</td>"
            f"<td>{esc(p.get('service', ''))}</td>"
            f"<td>{esc(' '.join(x for x in (p.get('product', ''), p.get('version', '')) if x).strip() or '—')}</td>"
            "</tr>"
            for p in ports
        )
        detail_blocks.append(
            f'<h3 class="mono">{esc(host.get("ip", ""))}'
            f'<span class="dim"> — {esc(host.get("hostname") or host.get("os") or "")}</span></h3>'
            '<table class="grid"><thead><tr><th>Port</th><th>Proto</th>'
            "<th>State</th><th>Service</th><th>Version</th></tr></thead>"
            f"<tbody>{prows}</tbody></table>"
        )
    detail_section = (
        '<section><h2>Service detail</h2>' + "".join(detail_blocks) + "</section>"
        if detail_blocks
        else ""
    )

    blocked = summary.get("blocked_entries") or []
    blocked_note = (
        f'<p class="dim">Skipped {len(blocked)} protected/forbidden entr(y/ies) '
        "(loopback / multicast / broadcast / reserved).</p>"
        if blocked
        else ""
    )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PurpleRecon Report — {esc(report.get('target', ''))}</title>
<style>
  :root {{ --bg:#0b0f17; --panel:#121826; --line:#1e2738; --ink:#e7e9ee;
          --dim:#8b94a7; --amber:#FFB300; --green:#00E676; --crimson:#D32F2F; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--ink);
         font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; }}
  .mono {{ font-family:"Fira Code",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }}
  .dim {{ color:var(--dim); }}
  .wrap {{ max-width:1100px; margin:0 auto; padding:28px 20px 60px; }}
  header {{ border-bottom:1px solid var(--line); padding-bottom:16px; margin-bottom:22px; }}
  h1 {{ margin:0 0 4px; font-size:22px; letter-spacing:.5px; }}
  h1 .p {{ color:var(--crimson); }} h1 .r {{ color:var(--green); }}
  h2 {{ font-size:15px; text-transform:uppercase; letter-spacing:1px;
        color:var(--dim); margin:28px 0 10px; }}
  h3 {{ font-size:14px; margin:18px 0 6px; }}
  .meta {{ color:var(--dim); font-size:13px; }}
  .cards {{ display:flex; gap:12px; flex-wrap:wrap; margin:6px 0 4px; }}
  .card {{ background:var(--panel); border:1px solid var(--line); border-radius:10px;
          padding:14px 18px; min-width:130px; }}
  .cval {{ font-size:26px; font-weight:700; }}
  .clbl {{ color:var(--dim); font-size:12px; text-transform:uppercase; letter-spacing:1px; }}
  table.grid {{ width:100%; border-collapse:collapse; background:var(--panel);
               border:1px solid var(--line); border-radius:10px; overflow:hidden; }}
  .grid th,.grid td {{ text-align:left; padding:9px 12px; border-bottom:1px solid var(--line); }}
  .grid th {{ color:var(--dim); font-size:12px; text-transform:uppercase; letter-spacing:.6px; }}
  .grid tr:last-child td {{ border-bottom:0; }}
  .grid tbody tr:hover {{ background:#0e1422; }}
  footer {{ margin-top:30px; color:var(--dim); font-size:12px;
           border-top:1px solid var(--line); padding-top:14px; }}
</style></head>
<body><div class="wrap">
  <header>
    <h1><span class="p">⬢ PURPLE</span><span class="r">RECON</span> · Network Report</h1>
    <div class="meta">Target <span class="mono">{esc(report.get('target', ''))}</span>
      &nbsp;·&nbsp; Engine {esc(report.get('engine', '—'))}
      &nbsp;·&nbsp; Operator {esc(report.get('author', ''))}
      &nbsp;·&nbsp; {esc(report.get('finished_at', ''))}</div>
  </header>
  <section>
    <div class="cards">{cards}</div>
    {blocked_note}
  </section>
  <section>
    <h2>Device inventory</h2>
    <table class="grid"><thead><tr>
      <th>#</th><th>IP address</th><th>Vendor</th><th>Hostname</th>
      <th>OS / device</th><th>MAC</th><th>Via</th><th>Open ports</th>
    </tr></thead><tbody>
    {inventory}
    </tbody></table>
  </section>
  {detail_section}
  <footer>
    Generated by PurpleRecon v{esc(report.get('version', ''))} ·
    Authorized use only — scan assets you own or are explicitly permitted to test.
  </footer>
</div></body></html>"""


def write_html_report(report: dict, output_dir: str) -> str:
    """Write the self-contained HTML report; returns the path."""
    os.makedirs(output_dir, exist_ok=True)
    path = _timestamped_path(report, output_dir, "html")
    _atomic_write_text(path, render_html_report(report), newline="")
    return path


# --------------------------------------------------------------------------- #
# Differential analysis — compare a fresh scan against a previous JSON report
# --------------------------------------------------------------------------- #
def load_baseline(path: str) -> dict:
    """Load + sanity-check a previous report for diffing (raises on failure)."""
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict) or "hosts" not in data:
        raise ValueError("not a PurpleRecon report (missing 'hosts')")
    return data


def diff_reports(old: dict, new: dict) -> dict:
    """Structured delta between a baseline report and the current scan.

    Surfaces newly-appeared / disappeared hosts and, per surviving host, the
    ports that opened or closed and any service/version or OS changes — i.e.
    *configuration drift* and potential new exposure since the baseline.
    """
    old_hosts = {h["ip"]: h for h in old.get("hosts", [])}
    new_hosts = {h["ip"]: h for h in new.get("hosts", [])}

    appeared = sorted(set(new_hosts) - set(old_hosts), key=_ip_key)
    disappeared = sorted(set(old_hosts) - set(new_hosts), key=_ip_key)

    changed: list[dict] = []
    for ip in sorted(set(old_hosts) & set(new_hosts), key=_ip_key):
        old_host, new_host = old_hosts[ip], new_hosts[ip]
        old_ports = {p["port"]: p for p in old_host.get("ports", [])}
        new_ports = {p["port"]: p for p in new_host.get("ports", [])}

        opened = sorted(set(new_ports) - set(old_ports))
        closed = sorted(set(old_ports) - set(new_ports))
        service_changes = []
        for port in sorted(set(old_ports) & set(new_ports)):
            before = _service_sig(old_ports[port])
            after = _service_sig(new_ports[port])
            if before != after:
                service_changes.append({"port": port, "from": before, "to": after})

        os_changed = old_host.get("os") != new_host.get("os")
        if opened or closed or service_changes or os_changed:
            changed.append(
                {
                    "ip": ip,
                    "opened_ports": opened,
                    "closed_ports": closed,
                    "service_changes": service_changes,
                    "os_from": old_host.get("os") if os_changed else None,
                    "os_to": new_host.get("os") if os_changed else None,
                }
            )

    return {
        "baseline_finished_at": old.get("finished_at"),
        "appeared_hosts": appeared,
        "disappeared_hosts": disappeared,
        "changed_hosts": changed,
        "has_changes": bool(appeared or disappeared or changed),
    }


def _service_sig(port: dict) -> str:
    """A comparable 'service version' signature for one port record."""
    return f"{port.get('service', '')} {port.get('version', '')}".strip()


def render_diff_panel(diff: dict) -> Panel:
    """Render the configuration-drift delta as a coloured cockpit panel."""
    body = Text()
    if not diff["has_changes"]:
        body.append("No changes vs baseline — environment is stable.", style=C_GREEN)
    else:
        if diff["appeared_hosts"]:
            body.append("＋ NEW HOSTS    ", style=f"bold {C_AMBER}")
            body.append(", ".join(diff["appeared_hosts"]) + "\n", style="white")
        if diff["disappeared_hosts"]:
            body.append("－ GONE HOSTS   ", style=f"bold {C_GREEN}")
            body.append(", ".join(diff["disappeared_hosts"]) + "\n", style="white")
        for change in diff["changed_hosts"]:
            body.append(f"~ {change['ip']}\n", style=f"bold {C_AMBER}")
            if change["opened_ports"]:
                body.append("    ＋ ports  ", style=C_AMBER)
                body.append(", ".join(map(str, change["opened_ports"])) + "\n", style="white")
            if change["closed_ports"]:
                body.append("    － ports  ", style=C_GREEN)
                body.append(", ".join(map(str, change["closed_ports"])) + "\n", style="white")
            for svc in change["service_changes"]:
                body.append(f"    ~ :{svc['port']}  ", style=C_AMBER)
                body.append(f"{svc['from']} → {svc['to']}\n", style="white")
            if change["os_to"]:
                body.append(f"    ~ OS  {change['os_from']} → {change['os_to']}\n", style="white")

    baseline = diff.get("baseline_finished_at") or "unknown"
    return Panel(
        body,
        title=f"[bold]CONFIGURATION DRIFT[/]  ·  vs baseline {baseline}",
        title_align="left",
        border_style=C_AMBER,
        box=box.HEAVY,
        expand=False,
    )


def print_summary(
    console: Console,
    state: SharedState,
    scope: SimpleNamespace,
    started: datetime,
    finished: datetime,
) -> None:
    """Final, glance-able summary panel for the operator."""
    hosts = state.hosts()
    total_open = sum(h.open_count for h in hosts)
    weak = sum(1 for h in hosts if h.confidence == "weak")
    duration = (finished - started).total_seconds()

    grid = Table.grid(padding=(0, 2))
    grid.add_column(justify="right", style="dim")
    grid.add_column(style="bold white")
    grid.add_row("Target", state.target)
    grid.add_row("Candidates", str(scope.n_hosts))
    grid.add_row("Live hosts", f"[{C_GREEN}]{len(hosts)}[/]")
    if weak:
        grid.add_row("  unconfirmed", f"[{C_AMBER}]{weak} (RST-only)[/]")
    grid.add_row("Open ports", f"[{C_AMBER}]{total_open}[/]")
    grid.add_row("Duration", f"{duration:.1f}s")
    if scope.blocked:
        grid.add_row("Blocked", f"[{C_CRIMSON}]{len(scope.blocked)} entr(y/ies)[/]")

    console.print(
        Panel(
            grid,
            title="[bold]SCAN COMPLETE[/]",
            border_style=C_GREEN,
            box=box.HEAVY,
            expand=False,
        )
    )


# --------------------------------------------------------------------------- #
# Small helpers (privilege, ping portability, dns, sanitising)
# --------------------------------------------------------------------------- #
def is_privileged() -> bool:
    """True only when we have raw-socket capability (root on POSIX)."""
    if hasattr(os, "geteuid"):
        try:
            return os.geteuid() == 0
        except OSError:
            return False
    return False  # non-POSIX: assume unprivileged for safety


def _ping_available() -> bool:
    """Is a usable system ``ping`` binary present?"""
    from shutil import which

    return which("ping") is not None


def _ping_command(ip: str, timeout_s: float) -> list[str]:
    """Build a portable, single-echo ping command with a per-OS timeout.

    Home / Wi-Fi devices (phones, tablets, IoT in power-save) frequently answer
    ICMP only after 0.5–2 s, so the timeout must be generous or they are missed
    entirely — the cause of "Angry IP finds 13, we find 3".
    """
    secs = max(1, int(math.ceil(timeout_s)))
    system = platform.system().lower()
    if system == "darwin":
        return ["ping", "-c", "1", "-t", str(secs), ip]         # macOS: -t = total timeout (s)
    if system == "windows":
        return ["ping", "-n", "1", "-w", str(int(timeout_s * 1000)), ip]  # Windows: -w = wait (ms)
    return ["ping", "-c", "1", "-W", str(secs), ip]             # Linux/BSD: -W = reply wait (s)


# Matches "... (192.168.1.108) at a4:83:e7:.. on en0" from `arp -a`; the strict
# 6-octet MAC pattern naturally skips "(incomplete)" entries.
_ARP_RE = re.compile(
    r"\((\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})"
)
_NON_HOST_MACS = frozenset({"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"})


def _normalise_mac(mac: str) -> str:
    """Zero-pad each octet so macOS's '0:f:15:..' matches '00:0f:15:..'."""
    try:
        return ":".join(f"{int(part, 16):02x}" for part in mac.split(":"))
    except ValueError:
        return mac.lower()


def _is_host_mac(mac: str) -> bool:
    """True for a real unicast host MAC (not broadcast / multicast / empty)."""
    if mac in _NON_HOST_MACS or ":" not in mac:
        return False
    # IPv4 multicast (01:00:5e:..) and IPv6 (33:33:..) are not hosts.
    return not (mac.startswith("01:00:5e") or mac.startswith("33:33"))


def _proxy_macs(ip_to_mac: dict[str, str], threshold: int) -> set[str]:
    """MACs that answer for more than ``threshold`` IPs.

    A single MAC mapped to many addresses is a router doing *proxy ARP*, not
    that many distinct devices — counting them would flood the result with false
    positives (every IP in the subnet showing "up" with the gateway's MAC).
    """
    counts = Counter(ip_to_mac.values())
    return {mac for mac, count in counts.items() if count > threshold}


def _read_arp_table() -> dict[str, str]:
    """Read the OS ARP cache as ``{ip: mac}`` for resolved, real-host entries.

    Catches local-subnet devices that answer ARP but ignore ICMP (the classic
    Wi-Fi power-save phone). Best-effort + unprivileged; returns ``{}`` on any
    failure. ARP is L2-only, so this only contributes for same-subnet scans.
    """
    table: dict[str, str] = {}

    # Primary: `arp -an` (macOS / BSD / Linux). The `-n` is important: it skips
    # reverse-DNS on every entry, which otherwise makes `arp -a` take many
    # seconds and time out.
    try:
        out = subprocess.run(
            ["arp", "-an"], capture_output=True, text=True, timeout=6, check=False
        ).stdout
        for match in _ARP_RE.finditer(out):
            mac = _normalise_mac(match.group(2))
            if _is_host_mac(mac):
                table[match.group(1)] = mac
    except (OSError, subprocess.TimeoutExpired):
        pass

    # Linux fallback: parse /proc/net/arp directly (no arp binary required).
    if not table and os.path.exists("/proc/net/arp"):
        try:
            with open("/proc/net/arp", encoding="utf-8") as handle:
                next(handle, None)  # skip header row
                for line in handle:
                    cols = line.split()
                    if len(cols) >= 4 and _is_host_mac(cols[3].lower()):
                        table[cols[0]] = cols[3].lower()
        except OSError:
            pass

    return table


# Non-physical interfaces whose neighbours aren't real LAN devices (Apple
# AWDL/llw peer-to-peer, VPN tunnels, loopback, bridges).
_NDP_SKIP_IFACES = ("lo", "awdl", "llw", "utun", "gif", "stf", "bridge", "ap", "anpi", "tun", "tap")


def _read_ndp_table() -> dict[str, list[str]]:
    """Read the IPv6 neighbour cache as ``{mac: [ipv6, ...]}`` for LAN devices.

    The IPv6 analogue of the ARP cache: ``ndp -an`` (macOS / BSD) or
    ``ip -6 neigh`` (Linux). Incomplete entries and non-physical interfaces
    (AWDL, VPN ``utun``, loopback) are filtered out. Keyed by MAC so an IPv6
    address can be correlated to the same device discovered over IPv4.
    Best-effort + unprivileged; returns ``{}`` on any failure.
    """
    by_mac: dict[str, set[str]] = {}

    def _skip_iface(iface: str) -> bool:
        return any(iface.startswith(s) for s in _NDP_SKIP_IFACES)

    # macOS / BSD: `ndp -an`
    try:
        out = subprocess.run(
            ["ndp", "-an"], capture_output=True, text=True, timeout=6, check=False
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        out = ""
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 2 or "(incomplete)" in line:
            continue
        neigh, mac = parts[0], parts[1]
        if "%" in neigh:
            addr, iface = neigh.split("%", 1)
        else:
            addr, iface = neigh, (parts[2] if len(parts) > 2 else "")
        if _skip_iface(iface):
            continue
        mac = _normalise_mac(mac)
        if _is_host_mac(mac):
            by_mac.setdefault(mac, set()).add(addr)

    # Linux fallback: `ip -6 neigh`
    if not by_mac:
        try:
            out = subprocess.run(
                ["ip", "-6", "neigh"], capture_output=True, text=True, timeout=6, check=False
            ).stdout
        except (OSError, subprocess.TimeoutExpired):
            out = ""
        for line in out.splitlines():
            toks = line.split()
            if "lladdr" not in toks or "dev" not in toks:
                continue
            addr = toks[0]
            iface = toks[toks.index("dev") + 1] if toks.index("dev") + 1 < len(toks) else ""
            mac = _normalise_mac(toks[toks.index("lladdr") + 1])
            if not _skip_iface(iface) and _is_host_mac(mac) and toks[-1] not in ("FAILED", "INCOMPLETE"):
                by_mac.setdefault(mac, set()).add(addr)

    return {mac: sorted(addrs) for mac, addrs in by_mac.items()}


def _oui_key(six_hex: str) -> str:
    """'D84489' -> 'D8:44:89' (uppercase OUI key)."""
    s = six_hex.upper()
    return f"{s[0:2]}:{s[2:4]}:{s[4:6]}"


def _mac_vendor(mac: str | None, oui_table: dict[str, str]) -> str | None:
    """Resolve a MAC to a vendor name.

    A randomized / locally-administered MAC (the 0x02 bit of the first octet —
    a modern phone's "private Wi-Fi address") has no real vendor and is labelled
    as such. Otherwise the OUI is looked up in ``oui_table`` (full IEEE registry
    if loaded), then the built-in fallback.
    """
    if not mac or ":" not in mac:
        return None
    try:
        first_octet = int(mac.split(":")[0], 16)
    except ValueError:
        return None
    if first_octet & 0x02:  # locally administered => randomized / private
        return VENDOR_RANDOM
    oui = mac[:8].upper()
    return oui_table.get(oui) or _OUI_FALLBACK.get(oui)


def load_oui_table(path: str) -> dict[str, str]:
    """Parse an IEEE OUI registry (oui.csv or oui.txt) into ``{OUI: vendor}``.

    Returns ``{}`` on any error so the caller falls back to the built-in set.
    """
    table: dict[str, str] = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            sample = handle.read(4096)
            handle.seek(0)
            is_csv = path.lower().endswith(".csv") or "Assignment" in sample
            if is_csv:
                # IEEE CSV: Registry,Assignment,Organization Name,Address
                for row in csv.reader(handle):
                    if len(row) >= 3 and len(row[1]) == 6 and row[1].isalnum():
                        table[_oui_key(row[1])] = row[2].strip()[:22]
            else:
                # IEEE oui.txt: "AABBCC     (base 16)    Organization"
                for line in handle:
                    match = re.match(r"\s*([0-9A-Fa-f]{6})\s+\(base 16\)\s+(.+)", line)
                    if match:
                        table[_oui_key(match.group(1))] = match.group(2).strip()[:22]
    except OSError:
        return {}
    return table


def resolve_oui_path(explicit: str | None) -> str | None:
    """Locate an OUI registry file: explicit arg, beside the script, or cache."""
    here = os.path.dirname(os.path.abspath(__file__))
    cache = os.path.join(os.path.expanduser("~"), ".cache", "purple_recon", "oui.csv")
    for candidate in (explicit, os.path.join(here, "oui.csv"),
                      os.path.join(here, "oui.txt"), cache):
        if candidate and os.path.exists(candidate):
            return candidate
    return None


def download_oui_registry(console: Console) -> str | None:
    """Download the IEEE OUI registry to the user cache; return its path."""
    import urllib.request

    cache_dir = os.path.join(os.path.expanduser("~"), ".cache", "purple_recon")
    os.makedirs(cache_dir, exist_ok=True)
    dest = os.path.join(cache_dir, "oui.csv")
    console.print(f"[dim]» Downloading IEEE OUI registry → {dest} …[/]")
    try:
        url = "https://standards-oui.ieee.org/oui/oui.csv"
        # Defence-in-depth: refuse anything but HTTPS so urlopen can never be
        # steered to a file:// or other local scheme.
        if not url.startswith("https://"):
            raise ValueError("OUI registry source must be HTTPS")
        request = urllib.request.Request(
            url, headers={"User-Agent": f"{APP_NAME}/{VERSION}"}
        )
        # HTTPS scheme is enforced above, so urlopen cannot reach a local scheme.
        with urllib.request.urlopen(request, timeout=60) as resp:  # nosec B310
            data = resp.read()
        with open(dest, "wb") as out:
            out.write(data)
        console.print(f"[{C_GREEN}]» OUI registry saved ({len(data) // 1024} KB).[/]")
        return dest
    except Exception as exc:  # noqa: BLE001 - network/parse failures are non-fatal
        console.print(f"[{C_AMBER}]» OUI download failed ({exc}); using built-in table.[/]")
        return None


def _reverse_dns(ip: str) -> str | None:
    """Best-effort reverse DNS lookup with a bounded timeout.

    Saves and *restores* the previous global socket timeout (rather than
    clobbering it to ``None``), so a lookup here can't silently disable timeouts
    for unrelated sockets elsewhere in the process.
    """
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(1.0)
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror):
        return None
    finally:
        socket.setdefaulttimeout(previous)


def resolve_hostnames(state: SharedState, workers: int = 32) -> None:
    """Reverse-resolve hostnames for live hosts in parallel (mDNS / DNS).

    On macOS the system resolver answers via Bonjour/mDNS, which is how names
    like 'iPhone' or 'Nandhus-iPad' appear for devices with no DNS record.
    """
    targets = [host.ip for host in state.hosts() if not host.hostname]
    if not targets:
        return

    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(1.5)  # set once for the whole parallel pass

    def _lookup(ip: str) -> tuple[str, str | None]:
        try:
            return ip, socket.gethostbyaddr(ip)[0]
        except (OSError, socket.herror):
            return ip, None

    try:
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="dns") as pool:
            for ip, name in pool.map(_lookup, targets):
                if name:
                    state.set_host_hostname(ip, name)
    finally:
        socket.setdefaulttimeout(previous)


def _sanitize_filename(value: str) -> str:
    """Make a target string safe to embed in a filename."""
    keep = "".join(ch if ch.isalnum() else "-" for ch in value)
    return keep.strip("-")[:40] or "scan"


def _ip_key(ip: str) -> tuple[int, ...]:
    """Sort key that orders dotted-quad IPs numerically, not lexically."""
    try:
        return tuple(int(octet) for octet in ip.split("."))
    except (ValueError, AttributeError):
        return (0,)


def build_nmap_args(args: argparse.Namespace, privileged: bool) -> str:
    """Compose the nmap argument string from CLI options + privilege level."""
    parts = ["-sV", "-Pn", "-T4", "--host-timeout", args.host_timeout]
    if args.full:
        parts += ["-p-"]
    elif args.ports:
        parts += ["-p", args.ports]
    else:
        parts += ["--top-ports", str(args.top_ports)]
    if privileged:
        # OS fingerprinting needs raw sockets; only attempt it as root.
        parts += ["-O", "--osscan-guess"]
    return " ".join(parts)


def detect_nmap(console: Console) -> bool:
    """Return True if a usable nmap engine exists; warn (don't fail) otherwise."""
    if not _HAVE_PYNMAP:
        console.print(
            f"[{C_AMBER}]» python-nmap not installed — Phase 2 will use the "
            f"built-in socket scanner.[/]"
        )
        return False
    try:
        nmap.PortScanner()  # type: ignore[union-attr]
        return True
    except Exception:  # nmap.PortScannerError or anything else
        console.print(
            f"[{C_AMBER}]» nmap binary not found — Phase 2 will use the "
            f"built-in socket scanner. (Install nmap for full results.)[/]"
        )
        return False


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="purple_recon.py",
        description=f"{APP_NAME} v{VERSION} — two-tiered network enumeration "
        f"cockpit by {AUTHOR}.",
        epilog="Authorized use only. Example: purple_recon.py 192.168.1.0/24 -y",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("target", help="CIDR / IP / comma-list, e.g. 192.168.1.0/24")
    parser.add_argument("-p", "--ports", help="explicit nmap port spec (e.g. 1-1024)")
    parser.add_argument("--top-ports", type=int, default=100,
                        help="number of most-common ports to scan")
    parser.add_argument("--full", action="store_true", help="scan all 65535 ports")
    parser.add_argument("-D", "--discover", action="store_true",
                        help="DISCOVERY ONLY: fast device inventory (IP/MAC/hostname), "
                             "skipping the slower nmap deep-dive — best for 'list every device'")
    parser.add_argument("--host-timeout", default="120s",
                        help="per-host nmap timeout")
    parser.add_argument("--sweep-workers", type=int, default=128,
                        help="Phase 1 concurrency")
    parser.add_argument("--sweep-timeout", type=float, default=1.0,
                        help="Phase 1 per-port TCP connect timeout (seconds)")
    parser.add_argument("--ping-timeout", type=float, default=3.0,
                        help="Phase 1 ICMP echo timeout per attempt (seconds); "
                             "raise on high-latency Wi-Fi where slow devices are missed")
    parser.add_argument("--scan-workers", type=int, default=8,
                        help="Phase 2 concurrency (parallel nmap scans)")
    parser.add_argument("--no-ping", action="store_true",
                        help="disable the ICMP discovery fallback")
    parser.add_argument("--rst-up", action="store_true",
                        help="treat a bare TCP RST (connection refused) as 'host "
                             "up'. Off by default to avoid firewall false positives.")
    parser.add_argument("--no-arp", action="store_true",
                        help="disable ARP-cache discovery (local devices that ignore ICMP)")
    parser.add_argument("--oui-file", metavar="FILE",
                        help="IEEE OUI registry (oui.csv/oui.txt) for full MAC-vendor lookup")
    parser.add_argument("--download-oui", action="store_true",
                        help="download the IEEE OUI registry (~/.cache/purple_recon) and use it")
    parser.add_argument("--max-hosts", type=int, default=4096,
                        help="safety cap on the number of hosts to scan")
    parser.add_argument("-o", "--output-dir", default=".",
                        help="directory for the JSON report")
    parser.add_argument("--no-export", action="store_true",
                        help="do not write a JSON report")
    parser.add_argument("--html", action="store_true",
                        help="also write a self-contained HTML report (great for write-ups)")
    parser.add_argument("--csv", action="store_true",
                        help="also write a flat per-port CSV inventory (spreadsheet-friendly)")
    parser.add_argument("--diff", metavar="REPORT.json",
                        help="compare this scan against a previous JSON report")
    parser.add_argument("--no-ui", action="store_true",
                        help="force the non-interactive (headless) renderer")
    parser.add_argument("-y", "--yes", action="store_true",
                        help="skip the confirmation prompt for risky scopes")
    return parser


def print_banner(console: Console) -> None:
    """Pre-scan brand + authorization banner."""
    title = Text()
    title.append("⬢ PURPLE", style=f"bold {C_CRIMSON}")
    title.append("RECON ", style=f"bold {C_GREEN}")
    title.append(f"v{VERSION}", style="bold white")
    body = Text()
    body.append("Two-Tiered Purple-Team Network Enumeration Cockpit\n", style="white")
    body.append(f"Operator: {AUTHOR}\n\n", style="dim")
    body.append("Authorized use only. You are responsible for ensuring you have\n", style=C_AMBER)
    body.append("explicit permission to scan the specified targets.", style=C_AMBER)
    console.print(Panel(Group(title, body), border_style=C_STEEL, box=box.HEAVY))


def confirm_scope(scope: SimpleNamespace, args: argparse.Namespace, console: Console) -> bool:
    """Require explicit confirmation for public or unusually large scopes."""
    risky = scope.has_public or scope.n_hosts > 256
    if not risky or args.yes:
        return True
    detail = []
    if scope.has_public:
        detail.append("public/internet-routable addresses")
    if scope.n_hosts > 256:
        detail.append(f"{scope.n_hosts} hosts")
    reason = " and ".join(detail)
    if not console.is_terminal:
        console.print(
            f"[{C_CRIMSON}]Refusing a risky scope ({reason}) without -y/--yes "
            f"in a non-interactive session.[/]"
        )
        return False
    return Confirm.ask(
        f"[{C_AMBER}]This scope includes {reason}. Proceed?[/]", default=False
    )


def main(argv: list[str] | None = None) -> int:
    """Program entry point. Returns a POSIX-style exit code."""
    console = Console()
    args = build_parser().parse_args(argv)

    print_banner(console)

    # --- environment & dependency probing (graceful) ---------------------- #
    privileged = is_privileged()
    have_nmap = detect_nmap(console)
    engine_label = "nmap -sV" if have_nmap else "socket-scan"

    # --- guardrails: validate the scope BEFORE touching the network ------- #
    try:
        scope = ScopeValidator(max_hosts=args.max_hosts).validate(args.target)
    except ScopeError as exc:
        console.print(
            Panel(str(exc), title="[bold]SCOPE REJECTED[/]", border_style=C_CRIMSON,
                  box=box.HEAVY)
        )
        return 2

    if scope.blocked:
        reasons = ", ".join(sorted({r for _, r in scope.blocked}))
        console.print(
            f"[{C_AMBER}]» Skipped {len(scope.blocked)} protected address(es): "
            f"{reasons}.[/]"
        )

    if not confirm_scope(scope, args, console):
        console.print("[dim]Aborted before scanning.[/]")
        return 1

    # --- MAC-vendor (OUI) table: full IEEE registry if available, else the
    #     built-in fallback. ----------------------------------------------- #
    oui_path = download_oui_registry(console) if args.download_oui else resolve_oui_path(args.oui_file)
    oui_table = load_oui_table(oui_path) if oui_path else {}
    if oui_table:
        console.print(f"[dim]» MAC-vendor: {len(oui_table)} OUIs from {oui_path}[/]")

    # --- assemble the pipeline ------------------------------------------- #
    state = SharedState(target=args.target, privileged=privileged, engine_label=engine_label)
    discovery = DiscoveryEngine(
        timeout=args.sweep_timeout,
        workers=args.sweep_workers,
        use_ping=not args.no_ping,
        rst_up=args.rst_up,
        ping_timeout=args.ping_timeout,
        use_arp=not args.no_arp,
        oui_table=oui_table,
    )
    enumeration = EnumerationEngine(
        nmap_args=build_nmap_args(args, privileged),
        workers=args.scan_workers,
        have_nmap=have_nmap,
    )
    orchestrator = Orchestrator(
        state, scope.hosts, discovery, enumeration, discover_only=args.discover
    )

    # Optional differential baseline (loaded up-front so a bad path warns early
    # rather than after a full scan).
    baseline: dict | None = None
    if args.diff:
        try:
            baseline = load_baseline(args.diff)
            console.print(f"[dim]» Diff baseline loaded: {args.diff}[/]")
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            console.print(
                f"[{C_AMBER}]» Could not load diff baseline ({exc}); "
                f"continuing without diff.[/]"
            )

    started = datetime.now(timezone.utc)
    use_cockpit = console.is_terminal and not args.no_ui
    if use_cockpit:
        run_cockpit(state, orchestrator, console)
    else:
        run_headless(state, orchestrator, console)
    finished = datetime.now(timezone.utc)

    # The live cockpit is a fixed-height view that can clip a long host list (and
    # the alternate screen is torn down on exit), so always print the COMPLETE
    # results to the scrollback — the operator must see every device found.
    if args.discover:
        console.print(render_device_list(state.snapshot()))
    else:
        console.print(_render_body(state.snapshot()))

    # --- build report, optional diff, export & summary -------------------- #
    report = build_report(state, scope, started, finished)
    if baseline is not None:
        report["diff"] = diff_reports(baseline, report)

    if not args.no_export:
        try:
            path = write_report(report, args.output_dir)
            console.print(f"[{C_GREEN}]» Report written:[/] {path}")
        except OSError as exc:
            console.print(f"[{C_CRIMSON}]» Export failed:[/] {exc}")

    # Optional extra formats (independent of the JSON export).
    for enabled, writer, label in (
        (args.html, write_html_report, "HTML report"),
        (args.csv, write_csv_report, "CSV inventory"),
    ):
        if not enabled:
            continue
        try:
            path = writer(report, args.output_dir)
            console.print(f"[{C_GREEN}]» {label} written:[/] {path}")
        except OSError as exc:
            console.print(f"[{C_CRIMSON}]» {label} export failed:[/] {exc}")

    print_summary(console, state, scope, started, finished)
    if baseline is not None:
        console.print(render_diff_panel(report["diff"]))
    return 0


def cli() -> None:
    """Console-script entry point (``purplerecon`` once pip-installed).

    Wraps :func:`main` with the same last-resort guard the ``__main__`` block
    uses, so the installed command converts *any* unexpected failure or Ctrl-C
    into a clean, operator-friendly message and exit code — never a raw
    traceback.
    """
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        sys.stderr.write("\nInterrupted by operator.\n")
        raise SystemExit(130)
    except SystemExit:
        raise
    except Exception as _exc:  # noqa: BLE001 - intentional last-resort net
        try:
            Console(stderr=True).print(f"[bold {C_CRIMSON}]Fatal error:[/] {_exc}")
        except Exception:
            sys.stderr.write(f"Fatal error: {_exc}\n")
        raise SystemExit(1)


if __name__ == "__main__":
    cli()
