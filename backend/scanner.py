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
from concurrent.futures import ThreadPoolExecutor

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
from vulndb import lookup_offline_cves

# A dedicated, bounded thread pool for the (blocking) nmap subprocess calls.
# Crucial: keeping nmap off asyncio's default executor means a slow scan can
# never starve the threads FastAPI uses to serve other requests (e.g. /health),
# which is what made the server appear to "hang" during long scans.
_SCAN_EXECUTOR = ThreadPoolExecutor(
    max_workers=int(os.environ.get("ENUMGRID_MAX_SCANS", "4")) + 2,
    thread_name_prefix="nmap-scan",
)
# A hard ceiling on any single host scan, so a pathological target can't pin a
# worker forever even past nmap's own --host-timeout.
HOST_SCAN_DEADLINE = int(os.environ.get("ENUMGRID_HOST_DEADLINE", "360"))

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

# --------------------------------------------------------------------------- #
# Nmap scan profiles (Zenmap-style). The args are SERVER-DEFINED constants — a
# client only ever sends a profile *name*, an optional validated port spec, and
# optional validated NSE script names. This is what keeps "full nmap power"
# injection-safe: no user string is ever spliced into the nmap command line.
# --------------------------------------------------------------------------- #
# Curated, non-intrusive enumeration scripts for the "recon" profile — rich
# service intel (titles, headers, certs, host keys, SMB/DNS facts) with zero
# brute/exploit/DoS risk. Server-defined, so they're trusted by construction.
_RECON_SCRIPTS = (
    "banner,http-title,http-headers,http-server-header,http-methods,"
    "ssl-cert,ssh-hostkey,smb-os-discovery,smb-security-mode,"
    "dns-service-discovery,nbstat,rpcinfo"
)

SCAN_PROFILES: dict[str, dict] = {
    "quick":         {"args": "-sV -Pn -T4 -F",                           "timeout": "120s", "scripts": ""},
    "default":       {"args": f"-sV -Pn -T4 --top-ports {TOP_PORTS}",     "timeout": "120s", "scripts": ""},
    "intense":       {"args": "-sV -sC -Pn -T4 --top-ports 1000",         "timeout": "240s", "scripts": ""},
    "recon":         {"args": "-sV -Pn -T4 --top-ports 1000",             "timeout": "300s", "scripts": _RECON_SCRIPTS},
    "aggressive":    {"args": "-A -Pn -T4",                               "timeout": "300s", "scripts": ""},
    "stealth":       {"args": "-sS -Pn -T2 --top-ports 200",              "timeout": "400s", "scripts": ""},
    "vuln":          {"args": f"-sV -Pn -T4 --top-ports {TOP_PORTS}",     "timeout": "300s", "scripts": "vuln,vulners"},
    "safe":          {"args": "-sV -sC -Pn -T4 --top-ports 500",          "timeout": "300s", "scripts": "safe"},
    "fullports":     {"args": "-sV -Pn -T4 -p-",                          "timeout": "600s", "scripts": ""},
    "comprehensive": {"args": "-A -Pn -T4 -p-",                           "timeout": "900s", "scripts": "default,vuln"},
    "udp":           {"args": "-sU -sV -Pn -T4 --top-ports 50",          "timeout": "300s", "scripts": ""},
}
DEFAULT_PROFILE = "default"

# Human-facing metadata for the UI (served via /api/profiles).
PROFILE_META: dict[str, dict] = {
    "quick":         {"label": "Quick",            "desc": "Fast -sV on the top 100 ports", "needs_root": False},
    "default":       {"label": "Default",          "desc": f"-sV on the top {TOP_PORTS} ports (balanced)", "needs_root": False},
    "intense":       {"label": "Intense",          "desc": "-sV + default NSE scripts (-sC), top 1000", "needs_root": False},
    "recon":         {"label": "Recon (rich)",     "desc": "-sV + safe enum scripts: titles, certs, host keys, SMB/DNS", "needs_root": False},
    "aggressive":    {"label": "Aggressive (OS)",  "desc": "-A: version, scripts, traceroute + OS detect", "needs_root": True},
    "stealth":       {"label": "Stealth SYN",      "desc": "-sS -T2 quiet half-open scan, top 200 (low-noise)", "needs_root": True},
    "vuln":          {"label": "Vulnerability",    "desc": "-sV + NSE vuln/vulners (CVE + CVSS)", "needs_root": False},
    "safe":          {"label": "Safe scripts",     "desc": "-sV -sC + the 'safe' NSE category, top 500", "needs_root": False},
    "fullports":     {"label": "All 65535 ports",  "desc": "-sV -p- (thorough, slow)", "needs_root": False},
    "comprehensive": {"label": "Comprehensive",    "desc": "-A -p- + default & vuln scripts — the works (very slow)", "needs_root": True},
    "udp":           {"label": "UDP (top 50)",     "desc": "-sU UDP scan of the top 50 ports", "needs_root": True},
}

# Validate user-supplied NSE scripts (names or categories) and port specs so
# they can never break out of their nmap argument.
_SCRIPT_RE = re.compile(r"^[a-z0-9][a-z0-9_\-*]{0,40}$", re.IGNORECASE)
_PORTSPEC_RE = re.compile(r"^[0-9]{1,5}([,\-][0-9]{1,5}){0,256}$")
# Scripts that could be intrusive/dangerous are refused even though they're valid
# NSE — an enumeration tool should not brute-force or exploit by accident.
_BLOCKED_SCRIPT_CATEGORIES = {"brute", "exploit", "dos", "malware"}


def _safe_scripts(scripts: str | None) -> list[str]:
    """Validated, deduped NSE script names/categories (intrusive ones removed)."""
    if not scripts:
        return []
    out: list[str] = []
    for raw in scripts.split(","):
        name = raw.strip()
        if name and _SCRIPT_RE.match(name) and name.lower() not in _BLOCKED_SCRIPT_CATEGORIES:
            if name not in out:
                out.append(name)
    return out


def build_host_scan_args(
    profile: str | None,
    scripts: str | None,
    ports: str | None,
    privileged: bool,
    deep: bool,
    auto_cve: bool = False,
) -> str:
    """Compose the nmap argument string for a per-host scan from a vetted profile.

    Only server-defined profile args + validated script/port tokens are used, so
    this is injection-safe by construction. `auto_cve` adds the version-based
    `vulners` CVE lookup even when `deep` is off, so a per-host scan always
    answers "is this version vulnerable?" automatically.
    """
    prof = SCAN_PROFILES.get(profile or DEFAULT_PROFILE, SCAN_PROFILES[DEFAULT_PROFILE])
    args = prof["args"]

    # Explicit port override — only when the profile hasn't already fixed ports.
    if ports and _PORTSPEC_RE.match(ports) and "-p-" not in args and "-F" not in args:
        args += f" -p {ports}"

    # Assemble NSE scripts: profile's own + deep (vuln) + the user's vetted list.
    script_list: list[str] = []
    if prof["scripts"]:
        script_list += prof["scripts"].split(",")
    if deep:
        script_list += ["vuln", "vulners"]
    if auto_cve and "vulners" not in script_list:
        script_list.append("vulners")  # always do the fast version→CVE lookup
    for name in _safe_scripts(scripts):
        if name not in script_list:
            script_list.append(name)
    if script_list:
        args += f" --script {','.join(script_list)} --script-timeout 60s"

    # OS detection: -A already includes -O. For other profiles, add -O only when
    # we actually have raw-socket privilege (root) — otherwise nmap just warns.
    if privileged and "-A" not in args.split():
        args += " -O --osscan-guess"

    args += f" --host-timeout {prof['timeout']}"
    return args

def _confirm_filtered(ip: str, ports: list[int], privileged: bool) -> dict[int, "PortState"]:
    """Re-probe specific ports with a *different* technique to confirm a
    'filtered' verdict.

    A single scan pass can wrongly report `filtered` when a rate-limiting home
    router or stateless firewall drops the first probes. We retry just those
    ports, slower and more persistently, with an evasion-flavoured method:

      * unprivileged → patient TCP connect scan (`-sT -T2 --max-retries 5`);
      * privileged   → SYN scan from a DNS source port (`-sS --source-port 53`),
                       which slips past naive "allow DNS replies" firewall rules.

    The port list comes from our own prior scan (integers only), so the `-p`
    argument is injection-safe. Returns ``{port: PortState}`` for any port whose
    state we could re-determine; the caller merges these over the original.
    """
    targets = sorted({p for p in ports if 0 < p < 65536})[:50]
    if not targets:
        return {}
    portspec = ",".join(str(p) for p in targets)
    if privileged:
        args = f"-sS -Pn -T2 --max-retries 5 --source-port 53 -p {portspec} --host-timeout 120s"
    else:
        args = f"-sT -Pn -T2 --max-retries 5 -p {portspec} --host-timeout 120s"
    if ":" in ip:
        args += " -6"
    scanner = nmap.PortScanner()
    try:
        scanner.scan(hosts=ip, arguments=args)
    except nmap.PortScannerError:
        return {}
    if ip not in scanner.all_hosts():
        return {}
    node = scanner[ip]
    out: dict[int, PortState] = {}
    for proto in node.all_protocols():
        for pn in node[proto]:
            state = _NMAP_STATE_MAP.get(node[proto][pn].get("state", ""), PortState.CLOSED)
            out[int(pn)] = state
    return out


_CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.IGNORECASE)
# vulners emits lines like:  CVE-2018-15473  5.3  https://vulners.com/...
_VULNERS_RE = re.compile(r"(CVE-\d{4}-\d{3,7})\s+(\d{1,2}\.\d)", re.IGNORECASE)
_MAX_VULNERS = 8  # cap CVEs per port so the UI stays readable


def _cve_url(vuln_id: str) -> str:
    """Authoritative reference link for a finding id.

    For a real CVE we link to NVD (always valid, no API call needed) — this is
    what powers the dashboard's clickable "is this version vulnerable?" links.
    Non-CVE script ids link to nmap's NSE script documentation instead.
    """
    if _CVE_RE.fullmatch(vuln_id or ""):
        return f"https://nvd.nist.gov/vuln/detail/{vuln_id.upper()}"
    return ""

# Open ports that count as a "critical finding" for the placeholder heuristic.
CRITICAL_PORTS = {21, 23, 135, 139, 445, 1433, 3389, 5985, 6379}
CRITICAL_SERVICES = {"telnet", "ftp", "microsoft-ds", "ms-wbt-server", "rdp", "vnc"}

# Strict target allowlist: IPv4 / IPv6 / CIDR / octet-range / hostname. Must
# start with an alphanumeric or ':' (IPv6 "::"), block a leading '-' (flags),
# and contain no whitespace — so no extra nmap args can ever be injected. Colon
# and '%' (IPv6 + link-local scope) are allowed; they can't split an argument.
_TARGET_RE = re.compile(r"^[A-Za-z0-9:][A-Za-z0-9._:\-/%]{0,90}$")

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


def _service_scan(
    ip: str,
    privileged: bool,
    deep: bool,
    profile: str | None = None,
    scripts: str | None = None,
    ports: str | None = None,
    auto_cve: bool = False,
) -> dict:
    """Phase 2: enumerate one host using a chosen nmap profile.

    `profile` selects an allowlisted nmap scan type (quick/intense/aggressive/
    vuln/fullports/udp); `scripts`/`ports` are validated add-ons; `deep` forces
    the NSE vuln pass; `auto_cve` adds the fast version→CVE `vulners` lookup;
    `privileged` (root) enables real OS detection (-O). Detected service versions
    are also matched against the curated offline CVE reference.
    """
    args = build_host_scan_args(profile, scripts, ports, privileged, deep, auto_cve)
    if ":" in ip:  # IPv6 target — nmap needs -6
        args += " -6"
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
            # CVEs from NSE scripts (online) + the curated offline version map.
            vulns = _dedupe(_parse_scripts(info.get("script", {})) + lookup_offline_cves(version))
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
            url=_cve_url(cve),
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

    vuln_id = cves[0].upper() if cves else name
    return Vuln(
        id=vuln_id,
        title=name.replace("_", " ").replace("-", " "),
        severity=severity,
        output=text[:600],
        url=_cve_url(vuln_id),
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
            _SCAN_EXECUTOR, functools.partial(_ping_sweep, target)
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
                _SCAN_EXECUTOR, functools.partial(_service_scan, host.ip, privileged, deep)
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


async def scan_single_host(
    ip: str,
    deep: bool = True,
    profile: str | None = None,
    scripts: str | None = None,
    ports: str | None = None,
    confirm: bool = True,
) -> Host:
    """Scan one already-discovered host with a chosen nmap profile.

    Powers the per-row "Nmap Scan" + "Scan All" actions. Returns a fresh Host the
    client merges back into the grid in place. When `confirm` is set and the scan
    leaves ports in the ambiguous `filtered` state, a second pass re-probes just
    those ports with a different technique to resolve them (see
    :func:`_confirm_filtered`).
    """
    loop = asyncio.get_running_loop()
    privileged = is_privileged()
    result = await asyncio.wait_for(
        loop.run_in_executor(
            _SCAN_EXECUTOR,
            # auto_cve=True → every on-demand host scan checks versions for CVEs.
            functools.partial(
                _service_scan, ip, privileged, deep, profile, scripts, ports, True
            ),
        ),
        timeout=HOST_SCAN_DEADLINE,
    )

    port_objs: list[Port] = result["ports"]
    # Second-chance confirmation for ports stuck in 'filtered'.
    filtered = [p.port for p in port_objs if p.state == PortState.FILTERED]
    if confirm and filtered:
        try:
            confirmed = await asyncio.wait_for(
                loop.run_in_executor(
                    _SCAN_EXECUTOR,
                    functools.partial(_confirm_filtered, ip, filtered, privileged),
                ),
                timeout=HOST_SCAN_DEADLINE,
            )
        except (TimeoutError, asyncio.TimeoutError, nmap.PortScannerError):
            confirmed = {}
        for p in port_objs:
            new_state = confirmed.get(p.port)
            if new_state and new_state != PortState.FILTERED:
                p.state = new_state
                if p.state == PortState.OPEN and (
                    p.port in CRITICAL_PORTS or p.service.lower() in CRITICAL_SERVICES
                ):
                    p.critical = True

    return Host(
        ip=ip,
        hostname=result["hostname"],
        status=HostStatus.UP,  # the button only targets hosts already known up
        os=result["os"],
        device_type=result.get("device_type", ""),
        scanning=False,
        ports=port_objs,
        vulns=result["vulns"],
    )
