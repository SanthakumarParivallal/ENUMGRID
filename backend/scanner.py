"""
scanner.py — the two-tiered Nmap pipeline.

Phase 1  Ping Sweep         (nmap -sn)      host discovery        progress 0..40
Phase 2  Nmap Enumeration   (nmap -sV)      service/version scan  progress 40..100

`run_pipeline()` is an async generator that yields `ScanState` snapshots as the
scan progresses. The blocking python-nmap calls run in a thread executor so the
event loop (and the SSE stream) stay responsive.

SECURITY
--------
* `validate_target()` strictly allowlists the target so a request can never
  inject extra flags into the nmap command line (python-nmap shells out).
* Only scan hosts/networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import asyncio
import functools
import os
import re
import time

import nmap
from fingerprint import guess_device_type
from models import (
    Host,
    HostStatus,
    Port,
    PortState,
    Protocol,
    ScanPhase,
    ScanState,
    Severity,
    Vuln,
)

# --- tunables (overridable via environment) -------------------------------- #
DISCOVERY_ARGS = os.environ.get("NMAP_DISCOVERY_ARGS", "-sn -T4")
TOP_PORTS = os.environ.get("NMAP_TOP_PORTS", "200")
SERVICE_ARGS = os.environ.get(
    "NMAP_SERVICE_ARGS", f"-sV -Pn -T4 --top-ports {TOP_PORTS} --host-timeout 90s"
)
# Deep scan adds NSE scripts. `vuln` = active checks; `vulners` = CVE lookup with
# CVSS scores (needs internet). Slower + noisier, so it's opt-in (Deep toggle /
# ?deep=1 / the per-host scan button).
VULN_ARGS = os.environ.get("NMAP_VULN_ARGS", "--script vuln,vulners --script-timeout 60s")

_CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.IGNORECASE)
# vulners emits lines like:  CVE-2018-15473  5.3  https://vulners.com/...
_VULNERS_RE = re.compile(r"(CVE-\d{4}-\d{3,7})\s+(\d{1,2}\.\d)", re.IGNORECASE)
_MAX_VULNERS = 8  # cap CVEs per port so the UI stays readable

# Open ports that count as a "critical finding" for the placeholder heuristic.
CRITICAL_PORTS = {21, 23, 135, 139, 445, 1433, 3389, 5985, 6379}
CRITICAL_SERVICES = {"telnet", "ftp", "microsoft-ds", "ms-wbt-server", "rdp", "vnc"}

# Strict target allowlist: IPv4 / CIDR / octet-range / hostname. Must start with
# an alphanumeric (blocks leading '-' flags) and contain no whitespace.
_TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-/]{0,62}$")

_NMAP_STATE_MAP = {
    "open": PortState.OPEN,
    "filtered": PortState.FILTERED,
    "closed": PortState.CLOSED,
    "open|filtered": PortState.OPEN_FILTERED,
    "unfiltered": PortState.OPEN,
}

_OS_HINTS = [
    ("ubuntu", "Linux (Ubuntu)"),
    ("debian", "Linux (Debian)"),
    ("centos", "Linux (CentOS)"),
    ("red hat", "Linux (RHEL)"),
    ("fedora", "Linux (Fedora)"),
    ("alpine", "Linux (Alpine)"),
    ("windows", "Windows"),
    ("freebsd", "FreeBSD"),
    ("openbsd", "OpenBSD"),
    ("mikrotik", "MikroTik RouterOS"),
    ("cisco", "Cisco IOS"),
    ("darwin", "macOS"),
    ("mac os", "macOS"),
]


def validate_target(target: str) -> bool:
    """True if `target` is a safe nmap target (no injectable flags/whitespace)."""
    return bool(target) and bool(_TARGET_RE.match(target))


def nmap_available() -> bool:
    """True if the nmap binary is installed and callable."""
    try:
        nmap.PortScanner()
        return True
    except nmap.PortScannerError:
        return False


def is_privileged() -> bool:
    """Root lets us add OS detection (-O) and raw-packet discovery."""
    return hasattr(os, "geteuid") and os.geteuid() == 0


# --------------------------------------------------------------------------- #
# Blocking nmap calls (run inside the executor)
# --------------------------------------------------------------------------- #


def _ping_sweep(target: str) -> list[dict]:
    """Phase 1: discover which hosts are up."""
    scanner = nmap.PortScanner()
    scanner.scan(hosts=target, arguments=DISCOVERY_ARGS)
    discovered: list[dict] = []
    for ip in scanner.all_hosts():
        node = scanner[ip]
        discovered.append(
            {
                "ip": ip,
                "status": node.state(),  # 'up' / 'down'
                "hostname": node.hostname() or None,
            }
        )
    # Stable ordering by numeric IP where possible.
    discovered.sort(key=lambda h: _ip_key(h["ip"]))
    return discovered


def _service_scan(ip: str, privileged: bool, deep: bool) -> dict:
    """Phase 2: enumerate services/versions on one host.

    `deep` adds NSE vuln scripts; `privileged` (root) adds OS detection (-O).
    """
    args = SERVICE_ARGS
    if privileged:
        args += " -O"
    if deep:
        args += " " + VULN_ARGS
    scanner = nmap.PortScanner()
    scanner.scan(hosts=ip, arguments=args)

    if ip not in scanner.all_hosts():
        return {"os": "Unknown", "hostname": None, "ports": [], "vulns": [], "device_type": ""}

    node = scanner[ip]
    ports: list[Port] = []
    for proto in node.all_protocols():  # 'tcp', 'udp'
        proto_enum = Protocol.UDP if proto == "udp" else Protocol.TCP
        for port_num in sorted(node[proto]):
            info = node[proto][port_num]
            state = _NMAP_STATE_MAP.get(info.get("state", ""), PortState.CLOSED)
            name = info.get("name") or "unknown"
            version = " ".join(
                part
                for part in (info.get("product", ""), info.get("version", ""), info.get("extrainfo", ""))
                if part
            ).strip()
            vulns = _parse_scripts(info.get("script", {}))
            critical = (
                state == PortState.OPEN
                and (port_num in CRITICAL_PORTS or name.lower() in CRITICAL_SERVICES)
            ) or any(v.severity in (Severity.HIGH, Severity.CRITICAL) for v in vulns)
            ports.append(
                Port(
                    port=port_num,
                    protocol=proto_enum,
                    service=name,
                    version=version,
                    state=state,
                    critical=critical,
                    vulns=vulns,
                )
            )

    hostname = node.hostname() or None
    open_ports = [p.port for p in ports if p.state in (PortState.OPEN, PortState.OPEN_FILTERED)]
    services = [p.service for p in ports]
    return {
        "os": _detect_os(node, ports),
        "hostname": hostname,
        "ports": ports,
        "vulns": _parse_hostscript(node.get("hostscript", [])),
        "device_type": guess_device_type(hostname=hostname, ports=open_ports, services=services),
    }


# ----------------------------------------------------- NSE script parsing -- #


_SEV_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def _severity_from_cvss(score: float) -> Severity:
    """Map a CVSS base score onto our severity bands."""
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


def _parse_vulners(output: str) -> list[Vuln]:
    """Parse `vulners` output (CVE + CVSS lines) into CVSS-scored Vulns."""
    best: dict[str, float] = {}
    for cve, score in _VULNERS_RE.findall(output or ""):
        cve = cve.upper()
        val = float(score)
        if cve not in best or val > best[cve]:
            best[cve] = val
    ranked = sorted(best.items(), key=lambda kv: kv[1], reverse=True)[:_MAX_VULNERS]
    return [
        Vuln(
            id=cve,
            title="",  # the CVE id + CVSS badge speak for themselves in the UI
            severity=_severity_from_cvss(score),
            cvss=score,
            output=f"{cve} — CVSS {score:.1f} (vulners)",
        )
        for cve, score in ranked
    ]


def _script_to_vuln(name: str, output: str) -> Vuln | None:
    """Turn one (non-vulners) NSE script result into a Vuln, or None."""
    text = (output or "").strip()
    low = text.lower()
    blob = f"{name} {text}".lower()  # name often carries the CVE/bug id
    cves = _CVE_RE.findall(text)
    vulnerable = "vulnerable" in low and "not vulnerable" not in low

    # Skip non-findings (scripts that ran but reported nothing actionable).
    if not vulnerable and not cves:
        return None

    if "likely vulnerable" in low:
        severity = Severity.MEDIUM
    elif vulnerable:
        # A couple of well-known wormable bugs get bumped to critical.
        severity = (
            Severity.CRITICAL
            if any(k in blob for k in ("ms17-010", "eternalblue", "bluekeep", "heartbleed"))
            else Severity.HIGH
        )
    else:  # CVE referenced but no explicit VULNERABLE state
        severity = Severity.MEDIUM

    return Vuln(
        id=cves[0].upper() if cves else name,
        title=name.replace("_", " ").replace("-", " "),
        severity=severity,
        output=text[:600],
    )


def _parse_one_script(name: str, output: str) -> list[Vuln]:
    if "vulners" in name.lower():
        return _parse_vulners(output)
    vuln = _script_to_vuln(name, output)
    return [vuln] if vuln else []


def _dedupe(vulns: list[Vuln]) -> list[Vuln]:
    """Collapse duplicate ids (keep worst severity) and sort critical → info."""
    by_id: dict[str, Vuln] = {}
    for v in vulns:
        cur = by_id.get(v.id)
        if cur is None or _SEV_RANK[v.severity] < _SEV_RANK[cur.severity]:
            by_id[v.id] = v
    return sorted(by_id.values(), key=lambda v: _SEV_RANK[v.severity])


def _parse_scripts(scripts) -> list[Vuln]:
    """Parse a per-port `script` dict ({name: output}) into Vulns."""
    out: list[Vuln] = []
    if isinstance(scripts, dict):
        for name, output in scripts.items():
            out.extend(_parse_one_script(name, output))
    return _dedupe(out)


def _parse_hostscript(hostscripts) -> list[Vuln]:
    """Parse host-level `hostscript` ([{id, output}, ...]) into Vulns."""
    out: list[Vuln] = []
    for entry in hostscripts or []:
        out.extend(_parse_one_script(entry.get("id", "script"), entry.get("output", "")))
    return _dedupe(out)


# ----------------------------------------------------------- OS detection -- #


def _friendly_os_cpe(cpe: str) -> str:
    """`cpe:/o:canonical:ubuntu_linux:22.04` -> `Ubuntu Linux 22.04`."""
    seg = cpe.replace("cpe:/o:", "").split(":")
    vendor = seg[0] if len(seg) > 0 else ""
    product = seg[1].replace("_", " ").title() if len(seg) > 1 and seg[1] else ""
    version = seg[2] if len(seg) > 2 else ""
    label = product or vendor.replace("_", " ").title()
    return f"{label} {version}".strip() or "Unknown"


def _detect_os(node, ports: list[Port]) -> str:
    """Prefer nmap's OS match (-O); otherwise infer from CPEs / banners (no root)."""
    osmatch = node.get("osmatch") or []
    if osmatch:
        return osmatch[0].get("name", "Unknown")

    # 1) An OS-type CPE (cpe:/o:...) reported by service detection is the
    #    strongest unprivileged signal.
    for proto in node.all_protocols():
        for port_num in node[proto]:
            cpe = node[proto][port_num].get("cpe", "")
            candidates = cpe if isinstance(cpe, list) else [cpe]
            for candidate in candidates:
                if isinstance(candidate, str) and candidate.startswith("cpe:/o:"):
                    return _friendly_os_cpe(candidate)

    # 2) Fall back to banner keywords (e.g. "Ubuntu" in an OpenSSH extrainfo).
    haystack = " ".join(f"{p.service} {p.version}" for p in ports).lower()
    for key, label in _OS_HINTS:
        if key in haystack:
            return label
    return "Unknown"


def _ip_key(ip: str) -> int:
    try:
        acc = 0
        for octet in ip.split("."):
            acc = acc * 256 + int(octet)
        return acc
    except (ValueError, AttributeError):
        return 0


# --------------------------------------------------------------------------- #
# Async pipeline (yields ScanState snapshots)
# --------------------------------------------------------------------------- #


async def run_pipeline(target: str, scan_id: str | None, deep: bool = False):
    """Drive the two-tiered scan, yielding a ScanState snapshot per step.

    `deep` enables the NSE vuln-script pass during Phase 2.
    """
    loop = asyncio.get_running_loop()
    started = time.time()
    state = ScanState(
        scan_id=scan_id,
        target=target,
        phase=ScanPhase.PING_SWEEP,
        progress=2,
        started_at=started,
        hosts=[],
    )
    yield state.model_copy(deep=True)

    if not nmap_available():
        state.phase = ScanPhase.ERROR
        state.finished_at = time.time()
        yield state.model_copy(deep=True)
        return

    # ---- Phase 1: Ping Sweep ---------------------------------------------- #
    try:
        discovered = await loop.run_in_executor(
            None, functools.partial(_ping_sweep, target)
        )
    except nmap.PortScannerError:
        state.phase = ScanPhase.ERROR
        state.finished_at = time.time()
        yield state.model_copy(deep=True)
        return

    total = len(discovered) or 1
    for i, d in enumerate(discovered):
        status = HostStatus.UP if d["status"] == "up" else HostStatus.DOWN
        state.hosts.append(
            Host(
                ip=d["ip"],
                status=status,
                hostname=d["hostname"],
                os="Fingerprinting…" if status == HostStatus.UP else "Unknown",
                scanning=False,
                ports=[],
            )
        )
        state.progress = min(40, round(5 + (i + 1) / total * 35))
        yield state.model_copy(deep=True)
        await asyncio.sleep(0.04)  # gentle stagger for live UX

    up_hosts = [h for h in state.hosts if h.status == HostStatus.UP]

    # ---- Phase 2: Nmap Enumeration ---------------------------------------- #
    state.phase = ScanPhase.NMAP_ENUMERATION
    privileged = is_privileged()
    count = len(up_hosts) or 1
    for i, host in enumerate(up_hosts):
        host.scanning = True
        state.progress = min(99, 40 + round(i / count * 60))
        yield state.model_copy(deep=True)

        try:
            result = await loop.run_in_executor(
                None, functools.partial(_service_scan, host.ip, privileged, deep)
            )
            host.os = result["os"]
            host.ports = result["ports"]
            host.vulns = result["vulns"]
            if result.get("device_type"):
                host.device_type = result["device_type"]
            if result["hostname"]:
                host.hostname = result["hostname"]
        except nmap.PortScannerError:
            host.os = "Unknown"
            host.ports = []

        host.scanning = False
        state.progress = min(99, 40 + round((i + 1) / count * 60))
        yield state.model_copy(deep=True)

    # ---- Complete --------------------------------------------------------- #
    state.phase = ScanPhase.COMPLETE
    state.progress = 100
    state.finished_at = time.time()
    yield state.model_copy(deep=True)


async def scan_single_host(ip: str, deep: bool = True) -> Host:
    """Deep-scan one already-discovered host (the per-row "Scan Vulns" action).

    Returns a fresh Host the client merges back into the grid in place.
    """
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None, functools.partial(_service_scan, ip, is_privileged(), deep)
    )
    return Host(
        ip=ip,
        hostname=result["hostname"],
        status=HostStatus.UP,  # the button only targets hosts already known up
        os=result["os"],
        device_type=result.get("device_type", ""),
        scanning=False,
        ports=result["ports"],
        vulns=result["vulns"],
    )
