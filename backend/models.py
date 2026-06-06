"""
models.py — Pydantic models for the Two-Tiered Scan Pipeline.

These are the canonical server-side definitions. The frontend's
`src/lib/schema.js` mirrors them field-for-field, so a serialized `ScanState`
drops straight into the React reducer with no translation layer.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class ScanPhase(str, Enum):
    """Phases of the pipeline (Ping Sweep -> Nmap Service Scan)."""

    IDLE = "Idle"
    PING_SWEEP = "Ping Sweep"
    NMAP_ENUMERATION = "Nmap Enumeration"
    COMPLETE = "Complete"
    HALTED = "Halted"
    ERROR = "Error"


class HostStatus(str, Enum):
    UP = "up"
    DOWN = "down"
    UNKNOWN = "unknown"


class PortState(str, Enum):
    OPEN = "open"
    FILTERED = "filtered"
    CLOSED = "closed"
    OPEN_FILTERED = "open|filtered"


class Protocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Vuln(BaseModel):
    """A finding from an NSE vuln script (or the offline mock).

    `confidence` records *how* the finding was established, so the UI can be
    honest about false-positive risk:
      * "confirmed" — an NSE script actively tested the host and reported it
        VULNERABLE (high confidence);
      * "version"   — inferred from the detected product/version or CPE
        (vulners / offline reference / a referenced CVE). Accurate in general
        but can be a false positive when a vendor backported the fix without
        bumping the version — so it's flagged "verify".
    """

    id: str  # CVE id when available, else the script name
    title: str = ""
    severity: Severity = Severity.INFO
    cvss: float | None = None  # CVSS base score (from the `vulners` script)
    output: str = ""  # trimmed raw script output
    url: str = ""  # authoritative reference (NVD CVE page) — clickable in the UI
    confidence: str = ""  # "confirmed" | "version"  (basis of the finding)
    # Real-world prioritization signals (so "which of 40 CVEs matters first?"):
    kev: bool = False           # in CISA's Known Exploited Vulnerabilities catalog
    epss: float | None = None   # FIRST EPSS exploit-in-the-wild probability (0..1)


class Port(BaseModel):
    port: int
    protocol: Protocol = Protocol.TCP
    service: str = "unknown"
    version: str = ""
    state: PortState = PortState.OPEN
    critical: bool = False
    vulns: list[Vuln] = Field(default_factory=list)


class Host(BaseModel):
    ip: str
    hostname: str | None = None
    status: HostStatus = HostStatus.UNKNOWN
    os: str = "Unknown"
    mac: str | None = None          # L2 address (local subnet, from ARP)
    vendor: str | None = None       # OUI vendor or "(private/random)"
    ipv6: list[str] = Field(default_factory=list)  # IPv6 addrs (NDP cache, same MAC)
    device_type: str = ""           # heuristic type (Router/Phone/Printer/...) — not nmap -O
    discovered_via: str = ""        # "icmp" / "arp" / "tcp/<port>"
    scanning: bool = False
    ports: list[Port] = Field(default_factory=list)
    vulns: list[Vuln] = Field(default_factory=list)  # host-level NSE findings


class ScanState(BaseModel):
    """A single streamed snapshot of the whole scan — the SSE frame payload."""

    scan_id: str | None = None
    target: str = ""
    progress: int = 0  # 0..100
    phase: ScanPhase = ScanPhase.IDLE
    hosts: list[Host] = Field(default_factory=list)
    started_at: float | None = None
    finished_at: float | None = None
    message: str | None = None  # operator-readable note (e.g. why a scan was refused)
