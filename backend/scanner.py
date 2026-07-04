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
import shlex
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

import cve as cvedb
import nmap
import threatintel
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
# Default service scan covers the top 1000 ports (nmap's default breadth) so the
# out-of-the-box result is thorough — virtually every real-world listening service
# is in this set. The adaptive pass (see scan_single_host) then sweeps ALL 65535
# ports on just the hosts that already showed an open port.
TOP_PORTS = os.environ.get("NMAP_TOP_PORTS", "1000")
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
    # _run_scan elevates via sudo when available and otherwise rewrites the SYN
    # re-probe to a connect scan, so confirmation works at any privilege level.
    try:
        scanner, _ = _run_scan(ip, args)
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


# --------------------------------------------------------------------------- #
# Privilege auto-adaptation
# --------------------------------------------------------------------------- #
# Several nmap scan types need raw sockets (root): -sS (SYN), -sU (UDP), -O (OS
# detection). Run unprivileged they HARD-FAIL ("requires root privileges.
# QUITTING!"), so picking Stealth/UDP in the dashboard used to error out. We fix
# that by detecting — once — how much privilege we can get WITHOUT ever blocking
# on a password prompt, then either elevating transparently or rewriting the
# command so it still runs. Three tiers:
#
#   "root"         — the backend itself runs as root (e.g. ./start.sh --accurate-os)
#   "sudo"         — not root, but `sudo -n nmap` works (NOPASSWD or a cached
#                    credential): we run the scan under sudo and parse its XML
#   "unprivileged" — neither: root-only flags are auto-rewritten to equivalent
#                    unprivileged techniques (SYN→connect, UDP→connect, drop -O),
#                    so the scan always completes — with an honest note about it.
#
# The net effect: every profile runs without error, however the server started.
_AUTO_SUDO = os.environ.get("ENUMGRID_AUTO_SUDO", "1").lower() not in ("0", "false", "no")
_CAPABILITY: str | None = None

# In-memory sudo credential primed at runtime from the dashboard ("Elevate").
# ---------------------------------------------------------------------------
# When the backend starts unprivileged, the operator can elevate to real
# raw-socket scans (-sS/-sU/-O) *without restarting* by entering their sudo
# password once. We hold it ONLY in this process's memory for the session:
#   • never written to disk, never logged, never echoed back to any response;
#   • cleared by drop_privileges() and lost when the process exits;
#   • only settable over the local-only / admin-gated /api/privilege/elevate.
# This mirrors how a desktop GUI prompts for privilege — the password primes
# elevation, then every nmap call runs under `sudo -S` (see _sudo_scan).
_SUDO_PASSWORD: str | None = None


def sudo_available() -> bool:
    """True when a `sudo` binary exists (so elevation is even possible)."""
    return bool(shutil.which("sudo"))


def can_elevate() -> bool:
    """True when the dashboard could elevate us: not already root, sudo present.

    (Auto-sudo can be disabled with ENUMGRID_AUTO_SUDO=0, which also disables
    interactive elevation — the operator opted the process out of sudo entirely.)
    """
    return _AUTO_SUDO and not is_privileged() and sudo_available()


def _probe_sudo() -> bool:
    """True iff `sudo -n nmap --version` runs without prompting (NOPASSWD/cached).

    Uses `-n` (non-interactive), so this can never hang on or trigger a password
    prompt — it returns immediately if a password would be required.
    """
    if not _AUTO_SUDO:
        return False
    if not shutil.which("sudo"):
        return False
    nmap_bin = shutil.which("nmap") or "nmap"
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["sudo", "-n", nmap_bin, "--version"],
            capture_output=True,
            timeout=5,
            check=False,
        )
        return proc.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def scan_capability() -> str:
    """How much scan privilege we can obtain *without* prompting — cached.

    One of ``"root"`` / ``"sudo"`` / ``"unprivileged"``.
    """
    global _CAPABILITY
    if _CAPABILITY is None:
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            _CAPABILITY = "root"
        # A password primed at runtime (dashboard "Elevate") counts as sudo even
        # if the OS timestamp cache wouldn't answer `sudo -n` — _sudo_scan feeds
        # the password on stdin, so raw-socket scans genuinely run.
        elif _SUDO_PASSWORD is not None or _probe_sudo():
            _CAPABILITY = "sudo"
        else:
            _CAPABILITY = "unprivileged"
    return _CAPABILITY


def _reset_capability_cache() -> None:
    """Clear the cached capability (used by tests)."""
    global _CAPABILITY
    _CAPABILITY = None


def is_privileged() -> bool:
    """True only when the process runs AS root (direct raw-socket access)."""
    return hasattr(os, "geteuid") and os.geteuid() == 0


def can_raw_scan() -> bool:
    """True when we can run raw-socket scans (-sS/-sU/-O) — via root *or* sudo."""
    return scan_capability() in ("root", "sudo")


def elevate_sudo(password: str) -> tuple[bool, str]:
    """Validate a sudo password and, on success, elevate this session.

    Runs ``sudo -k -S -p '' nmap --version`` feeding the password on stdin:
    ``-k`` forces a real re-authentication (so a stale timestamp can't mask a
    wrong password) and confirms this user may actually run nmap under sudo. On
    success the password is held in memory (see _SUDO_PASSWORD) and the cached
    capability is reset so every subsequent scan runs with real raw sockets.

    Returns ``(ok, message)``; the password is never logged or returned.
    """
    global _SUDO_PASSWORD
    if is_privileged():
        return True, "already running as root"
    if not _AUTO_SUDO:
        return False, "sudo elevation is disabled (ENUMGRID_AUTO_SUDO=0)"
    if not sudo_available():
        return False, "sudo is not installed on this host"
    if not password:
        return False, "no password provided"
    nmap_bin = shutil.which("nmap") or "nmap"
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, password via stdin, no shell
            ["sudo", "-k", "-S", "-p", "", nmap_bin, "--version"],
            input=(password + "\n").encode(),
            capture_output=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False, "could not invoke sudo"
    if proc.returncode != 0:
        # Wrong password, or this user isn't allowed to sudo nmap.
        return False, "sudo rejected the password (or nmap is not permitted for this user)"
    _SUDO_PASSWORD = password
    _reset_capability_cache()
    return True, "elevated — raw-socket scans (SYN/UDP/OS detection) are now available"


def drop_privileges() -> None:
    """Forget any primed sudo credential and invalidate the OS timestamp cache."""
    global _SUDO_PASSWORD
    _SUDO_PASSWORD = None
    _reset_capability_cache()
    if sudo_available():
        try:
            subprocess.run(  # noqa: S603 - fixed argv, no shell
                ["sudo", "-k"], capture_output=True, timeout=5, check=False
            )
        except (OSError, subprocess.SubprocessError):
            pass


def privilege_status() -> dict:
    """Machine-readable privilege state for the dashboard's elevation control."""
    cap = scan_capability()
    return {
        "capability": cap,            # "root" | "sudo" | "unprivileged"
        "can_raw": cap in ("root", "sudo"),
        "is_root": is_privileged(),
        "elevated": _SUDO_PASSWORD is not None,  # elevated at runtime via password
        "sudo_available": sudo_available(),
        "can_elevate": can_elevate(),  # a password prompt could raise us to sudo
    }


# Root-only scan-type flags → their best unprivileged equivalent.
_RAW_SCAN_DOWNGRADE = {
    "-sS": "-sT",  # SYN half-open      → TCP connect
    "-sA": "-sT",  # ACK               → TCP connect
    "-sW": "-sT",  # Window            → TCP connect
    "-sM": "-sT",  # Maimon            → TCP connect
    "-sN": "-sT",  # Null              → TCP connect
    "-sF": "-sT",  # FIN               → TCP connect
    "-sX": "-sT",  # Xmas              → TCP connect
    "-sU": "-sT",  # UDP (needs root)  → TCP connect (best unprivileged effort)
}
# Root-only flags with no unprivileged equivalent — dropped entirely.
_RAW_ONLY_DROP = {"-O", "--osscan-guess", "-sO", "-PR"}


def _adapt_args(args: str) -> tuple[str, str]:
    """Rewrite root-only nmap flags into unprivileged-safe equivalents.

    Guarantees the resulting command can run without root, so a scan never aborts
    with "requires root privileges" — it trades a little fidelity (SYN→connect,
    no OS detection) for the guarantee that *every* profile completes. Returns
    ``(adapted_args, note)`` where ``note`` is a short human explanation of what
    changed ("" when nothing did).
    """
    out: list[str] = []
    notes: list[str] = []
    skip_value = False
    for tok in args.split():
        if skip_value:  # consume the value that followed a dropped option
            skip_value = False
            continue
        if tok == "--source-port":
            skip_value = True  # also drop its value; connect scan can't set it
            notes.append("custom source-port needs root — dropped")
            continue
        if tok in _RAW_ONLY_DROP:
            notes.append(
                "OS detection (-O) needs root — skipped"
                if tok in ("-O", "--osscan-guess")
                else f"{tok} needs root — skipped"
            )
            continue
        if tok == "-A":
            # -A bundles OS detect + traceroute (root-only) with -sV + -sC; keep
            # the parts that work unprivileged and say so.
            out.extend(["-sV", "-sC"])
            notes.append("-A: OS detect/traceroute need root — kept -sV -sC")
            continue
        if tok in _RAW_SCAN_DOWNGRADE:
            repl = _RAW_SCAN_DOWNGRADE[tok]
            notes.append(
                "UDP scan needs root — ran TCP connect instead"
                if tok == "-sU"
                else f"{tok} needs root — used {repl} (connect) instead"
            )
            out.append(repl)
            continue
        out.append(tok)

    # De-dup tokens (a downgrade can introduce a second -sT/-sV) and guarantee a
    # scan type survives.
    deduped: list[str] = []
    for tok in out:
        if tok.startswith("-s") and tok in deduped:
            continue
        deduped.append(tok)
    if not any(t in ("-sT", "-sV", "-sn", "-sL") for t in deduped):
        deduped.insert(0, "-sT")
    note = "; ".join(dict.fromkeys(notes))  # de-dup notes, keep order
    return " ".join(deduped), note


def _sudo_scan(hosts: str, args: str) -> "nmap.PortScanner | None":
    """Run ``sudo -n nmap -oX - <args> <hosts>`` and parse the XML, or None.

    `args` is built from server-defined profile constants + already-validated
    script/port tokens (and `hosts` from the strict target allowlist), so the
    argv is safe; nothing is passed through a shell. Returns None on any failure
    (e.g. the cached sudo credential expired mid-session), letting the caller
    fall back to the unprivileged path.
    """
    nmap_bin = shutil.which("nmap") or "nmap"
    # With a password primed at runtime, authenticate via stdin (`sudo -S`); this
    # works even where `sudo -n` (timestamp cache) wouldn't. Otherwise stay
    # strictly non-interactive (`sudo -n`) so we can never block on a prompt.
    if _SUDO_PASSWORD is not None:
        argv = ["sudo", "-S", "-p", "", nmap_bin, "-oX", "-", *shlex.split(args), hosts]
        stdin_data: bytes | None = (_SUDO_PASSWORD + "\n").encode()
    else:
        argv = ["sudo", "-n", nmap_bin, "-oX", "-", *shlex.split(args), hosts]
        stdin_data = None
    try:
        proc = subprocess.run(  # noqa: S603 - argv built from validated tokens, no shell
            argv, input=stdin_data, capture_output=True, timeout=HOST_SCAN_DEADLINE, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0 or not proc.stdout:
        return None
    try:
        scanner = nmap.PortScanner()
        scanner.analyse_nmap_xml_scan(
            nmap_xml_output=proc.stdout.decode("utf-8", "replace"),
            nmap_err=proc.stderr.decode("utf-8", "replace"),
        )
        return scanner
    except nmap.PortScannerError:
        return None


def _run_scan(hosts: str, args: str) -> "tuple[nmap.PortScanner, str]":
    """Execute one nmap scan, adapting to whatever privilege we actually have.

    Returns ``(scanner, note)``. ``note`` describes any unprivileged downgrade
    that was applied (empty otherwise). This is the single choke-point every
    blocking nmap call funnels through, so the privilege policy lives in one place.
    """
    cap = scan_capability()
    if cap == "sudo":
        scanner = _sudo_scan(hosts, args)
        if scanner is not None:
            return scanner, ""
        # Cached sudo credential expired since startup → degrade gracefully.
    elif cap == "root":
        scanner = nmap.PortScanner()
        scanner.scan(hosts=hosts, arguments=args)
        return scanner, ""
    # Unprivileged (or a sudo run that just failed): rewrite root-only flags.
    safe_args, note = _adapt_args(args)
    scanner = nmap.PortScanner()
    scanner.scan(hosts=hosts, arguments=safe_args)
    return scanner, note


# --------------------------------------------------------------------------- #
# Blocking nmap calls (run inside the executor)
# --------------------------------------------------------------------------- #


def _ping_sweep(target: str) -> list[dict]:
    """Phase 1: discover which hosts are up."""
    scanner, _ = _run_scan(target, DISCOVERY_ARGS)
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


def _app_cpe(info: dict) -> str:
    """The application CPE (`cpe:/a:...`) nmap reported for a port, or "".

    This is what drives the live NVD lookup — an exact product/version key, so
    the CVE match is version-scoped rather than a fuzzy keyword search.
    """
    cpe = info.get("cpe", "")
    candidates = cpe if isinstance(cpe, list) else [cpe]
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.startswith("cpe:/a:"):
            return candidate
    return ""


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
    # Single adaptive choke-point: runs under sudo when available, otherwise
    # rewrites root-only flags so the scan always completes (never QUITTING!).
    scanner, scan_note = _run_scan(ip, args)

    if ip not in scanner.all_hosts():
        return {
            "os": "Unknown", "hostname": None, "ports": [], "vulns": [],
            "device_type": "", "note": scan_note,
        }

    node = scanner[ip]
    ports: list[Port] = []
    cpe_by_port: dict[int, str] = {}
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
            cpe_by_port[port_num] = _app_cpe(info)
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

    # Live NVD enrichment (on-demand per-host path only): match each service's
    # CPE against the authoritative, always-current NVD feed (cached locally), so
    # coverage isn't limited to the curated table — and new CVEs appear by
    # themselves. Best-effort: any failure leaves the vulners/offline results.
    if auto_cve:
        try:
            extra = cvedb.enrich(cpe_by_port)
        except Exception:  # noqa: BLE001 - enrichment must never break a scan
            extra = {}
        for p in ports:
            add = extra.get(p.port)
            if add:
                p.vulns = _dedupe(list(p.vulns) + add)
                if any(v.severity in (Severity.HIGH, Severity.CRITICAL) for v in p.vulns):
                    p.critical = True

    host_vulns = _parse_hostscript(node.get("hostscript", []))

    # Prioritize: annotate every CVE with CISA KEV (actively exploited) + FIRST
    # EPSS (exploit probability), then risk-rank — so the worst, real-world-
    # exploited issues float to the top instead of just sorting by CVSS.
    if auto_cve:
        _apply_threatintel(ports, host_vulns)

    hostname = node.hostname() or None
    open_ports = [p.port for p in ports if p.state in (PortState.OPEN, PortState.OPEN_FILTERED)]
    services = [p.service for p in ports]
    return {
        "os": _detect_os(node, ports),
        "hostname": hostname,
        "ports": ports,
        "vulns": host_vulns,
        "device_type": guess_device_type(hostname=hostname, ports=open_ports, services=services),
        "note": scan_note,
    }


def _apply_threatintel(ports: list[Port], host_vulns: list[Vuln]) -> None:
    """Batch-annotate all CVE findings with KEV + EPSS and risk-rank them.

    One KEV-set check + one EPSS batch call covers the whole host. Best-effort:
    any feed failure leaves the findings untouched.
    """
    all_vulns = [v for p in ports for v in p.vulns] + list(host_vulns)
    cve_ids = [v.id for v in all_vulns if v.id.upper().startswith("CVE-")]
    if not cve_ids:
        return
    try:
        kev = threatintel.kev_set()
        scores = threatintel.epss_for(cve_ids)
    except Exception:  # noqa: BLE001 - enrichment must never break a scan
        return
    for v in all_vulns:
        cid = v.id.upper()
        if cid in kev:
            v.kev = True
        if cid in scores:
            v.epss = round(scores[cid], 4)
    for p in ports:
        p.vulns = sorted(p.vulns, key=threatintel.risk_key)
    host_vulns.sort(key=threatintel.risk_key)


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
            output=f"{cve} — CVSS {score:.1f} (vulners, version-matched)",
            url=_cve_url(cve),
            confidence="version",  # matched by version/CPE — verify against vendor
        )
        for cve, score in ranked
    ]


# Phrases that mean "the script ran but found nothing" — guard against the
# heuristic turning an informational/!error result into a false finding.
_NON_FINDING_MARKERS = (
    "not vulnerable",
    "no vulnerabilit",        # "no vulnerabilities found"
    "couldn't",
    "could not",
    "unable to",
    "false positive",
    "error:",
    "no reply",
)


def _script_to_vuln(name: str, output: str) -> Vuln | None:
    """Turn one (non-vulners) NSE script result into a Vuln, or None.

    Confidence is "confirmed" only when the script's own state machine reported
    VULNERABLE (it actively tested the host); a bare CVE reference with no state
    is downgraded to "version" confidence (lower — could be a mention/backport).
    """
    text = (output or "").strip()
    low = text.lower()
    blob = f"{name} {text}".lower()  # name often carries the CVE/bug id
    cves = _CVE_RE.findall(text)

    # A real "VULNERABLE" verdict, not negated by a non-finding phrase.
    vulnerable = "vulnerable" in low and not any(m in low for m in _NON_FINDING_MARKERS)

    # Skip non-findings: nothing actionable, or an explicit "not vulnerable"/error.
    if any(m in low for m in _NON_FINDING_MARKERS) and not vulnerable:
        return None
    if not vulnerable and not cves:
        return None

    if "likely vulnerable" in low:
        severity, confidence = Severity.MEDIUM, "confirmed"
    elif vulnerable:
        # A couple of well-known wormable bugs get bumped to critical.
        severity = (
            Severity.CRITICAL
            if any(k in blob for k in ("ms17-010", "eternalblue", "bluekeep", "heartbleed"))
            else Severity.HIGH
        )
        confidence = "confirmed"
    else:  # CVE referenced but no explicit VULNERABLE state — weaker evidence.
        severity, confidence = Severity.MEDIUM, "version"

    vuln_id = cves[0].upper() if cves else name
    return Vuln(
        id=vuln_id,
        title=name.replace("_", " ").replace("-", " "),
        severity=severity,
        output=text[:600],
        url=_cve_url(vuln_id),
        confidence=confidence,
    )


def _parse_one_script(name: str, output: str) -> list[Vuln]:
    if "vulners" in name.lower():
        return _parse_vulners(output)
    vuln = _script_to_vuln(name, output)
    return [vuln] if vuln else []


def _dedupe(vulns: list[Vuln]) -> list[Vuln]:
    """Collapse duplicate ids and sort critical → info.

    When the same id appears more than once (e.g. a `vulners` version match *and*
    an NSE script that actively confirmed it), keep the worst severity and the
    strongest confidence ("confirmed" beats "version"), so a finding is never
    silently downgraded to a lower-confidence duplicate.
    """
    by_id: dict[str, Vuln] = {}
    for v in vulns:
        cur = by_id.get(v.id)
        if cur is None:
            by_id[v.id] = v
            continue
        # Merge: take the worse severity and the better confidence/score.
        worse = v if _SEV_RANK[v.severity] < _SEV_RANK[cur.severity] else cur
        confirmed = v.confidence == "confirmed" or cur.confidence == "confirmed"
        merged = worse.model_copy()
        if confirmed:
            merged.confidence = "confirmed"
        if merged.cvss is None:
            merged.cvss = cur.cvss if cur.cvss is not None else v.cvss
        if not merged.url:
            merged.url = cur.url or v.url
        by_id[v.id] = merged
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
    privileged = can_raw_scan()  # root OR passwordless sudo → real raw-socket scans
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
            host.scan_note = result.get("note", "")
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


def _merge_scan_results(quick: dict, deep: dict) -> dict:
    """Union the ports of a quick (top-1000) and a deep (all-ports) scan result.

    On a port collision the deep entry wins (it carries the full ``-sV`` version +
    CVE data); ports only the quick pass observed are preserved. Host-level fields
    prefer the deep result when it's more specific. Used by the adaptive scan so
    the merged Host reflects the most thorough evidence from both passes.
    """
    by_key: dict[tuple[int, str], Port] = {}
    for p in quick.get("ports", []):
        by_key[(p.port, p.protocol.value)] = p
    for p in deep.get("ports", []):
        by_key[(p.port, p.protocol.value)] = p  # deep is authoritative on conflict
    merged_ports = sorted(by_key.values(), key=lambda p: (p.port, p.protocol.value))

    def _pick(primary: str, fallback: str) -> str:
        return primary if primary and primary != "Unknown" else fallback

    note = "; ".join(
        dict.fromkeys(n for n in (quick.get("note", ""), deep.get("note", "")) if n)
    )
    return {
        "os": _pick(deep.get("os", ""), quick.get("os", "")),
        "hostname": deep.get("hostname") or quick.get("hostname"),
        "ports": merged_ports,
        "vulns": _dedupe(list(quick.get("vulns", [])) + list(deep.get("vulns", []))),
        "device_type": deep.get("device_type") or quick.get("device_type", ""),
        "note": note,
    }


async def scan_single_host(
    ip: str,
    deep: bool = True,
    profile: str | None = None,
    scripts: str | None = None,
    ports: str | None = None,
    confirm: bool = True,
    adaptive: bool = False,
) -> Host:
    """Scan one already-discovered host with a chosen nmap profile.

    Powers the per-row "Nmap Scan" + "Scan All" actions. Returns a fresh Host the
    client merges back into the grid in place. When `confirm` is set and the scan
    leaves ports in the ambiguous `filtered` state, a second pass re-probes just
    those ports with a different technique to resolve them (see
    :func:`_confirm_filtered`).

    `adaptive` (used by the default auto-scan) implements the thorough-where-it-pays
    strategy: do the fast top-1000 `-sV` scan first, and **only if** that finds an
    open port, sweep ALL 65535 ports on this one host to catch services outside the
    top-1000. Hosts with nothing open (the common case for firewalled clients) cost
    just the quick pass — no wasted full-port scan, and nothing is ever fabricated.
    """
    loop = asyncio.get_running_loop()
    privileged = can_raw_scan()  # root OR passwordless sudo → real raw-socket scans
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

    # Adaptive all-ports deep pass — only when the quick scan actually found an
    # open port and the caller didn't pin a profile/port set. This is what makes
    # "default" both fast (skips dead/firewalled hosts) and thorough (full sweep of
    # live ones). Best-effort: a timeout/error just keeps the quick-scan result.
    quick_open = [p for p in result["ports"] if p.state in (PortState.OPEN, PortState.OPEN_FILTERED)]
    if adaptive and quick_open and not profile and not ports:
        try:
            deep_res = await asyncio.wait_for(
                loop.run_in_executor(
                    _SCAN_EXECUTOR,
                    functools.partial(
                        _service_scan, ip, privileged, deep, "fullports", None, None, True
                    ),
                ),
                timeout=HOST_SCAN_DEADLINE,
            )
            result = _merge_scan_results(result, deep_res)
        except (TimeoutError, asyncio.TimeoutError, nmap.PortScannerError):
            pass  # keep the thorough-enough top-1000 result

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
        scan_note=result.get("note", ""),
    )
