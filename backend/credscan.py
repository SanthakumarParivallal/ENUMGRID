"""
credscan.py — authenticated (credentialed) host facts over SSH.

Network-only scanning infers the OS/software from banners, which is approximate
and prone to false positives (backported fixes). A *credentialed* check logs in
and reads the truth: the exact distro (`/etc/os-release`), kernel (`uname`), and
installed-package inventory (`dpkg`/`rpm`). That's how authoritative vulnerability
assessment is done — exact installed versions instead of guesses.

SSH is via `paramiko` (optional dependency). The pure parsers are always
available and fully tested; the live login is best-effort and never raises into
the caller. Credentials are used in-memory only — never logged or persisted.
Authorized use only: run this only against hosts you administer.
"""

from __future__ import annotations

import os

try:
    import paramiko

    _HAVE_PARAMIKO = True
except Exception:  # pragma: no cover - import environment dependent
    _HAVE_PARAMIKO = False

# Trust unknown SSH host keys automatically? Off by default → unknown keys are
# REJECTED (MITM-safe). Opt in for first-use convenience on a LAN you control.
_SSH_AUTOADD = os.environ.get("ENUMGRID_SSH_AUTOADD", "").strip().lower() in ("1", "true", "yes", "on")


def parse_os_release(text: str) -> str:
    """Best human-readable OS name from `/etc/os-release` contents ("" if none)."""
    fields: dict[str, str] = {}
    for line in (text or "").splitlines():
        if "=" in line:
            key, _, val = line.partition("=")
            fields[key.strip()] = val.strip().strip('"').strip("'")
    if fields.get("PRETTY_NAME"):
        return fields["PRETTY_NAME"]
    name = fields.get("NAME", "")
    version = fields.get("VERSION", "") or fields.get("VERSION_ID", "")
    return (f"{name} {version}".strip()) if name else ""


def parse_uname(text: str) -> dict:
    """Parse `uname -srm` → {kernel_name, kernel_release, arch}."""
    parts = (text or "").split()
    return {
        "kernel_name": parts[0] if len(parts) > 0 else "",
        "kernel_release": parts[1] if len(parts) > 1 else "",
        "arch": parts[2] if len(parts) > 2 else "",
    }


def count_packages(text: str) -> int:
    """Count installed packages from `dpkg -l` (ii lines) or `rpm -qa` output."""
    lines = [ln for ln in (text or "").splitlines() if ln.strip()]
    ii = [ln for ln in lines if ln.startswith("ii ")]
    if ii:
        return len(ii)  # dpkg -l
    # rpm -qa: one package per line (filter the dpkg header rows if present)
    return sum(1 for ln in lines if ln and not ln.startswith(("Desired=", "|", "+++", "||")))


def available() -> bool:
    """True if SSH (paramiko) is installed and credentialed scans are possible."""
    return _HAVE_PARAMIKO


def ssh_facts(
    ip: str,
    username: str,
    password: str | None = None,
    key_filename: str | None = None,
    port: int = 22,
    timeout: float = 8.0,
) -> dict:
    """Log into `ip` over SSH and return authoritative host facts.

    Returns ``{"ok": bool, "error"?: str, "os", "kernel", "arch", "packages"}``.
    Never raises — connection/auth problems come back as ``{"ok": False, ...}``.
    """
    if not _HAVE_PARAMIKO:
        return {"ok": False, "error": "paramiko not installed (pip install paramiko)"}
    client = paramiko.SSHClient()
    # Verify against the system's known_hosts first (secure path).
    try:
        client.load_system_host_keys()
    except Exception:  # noqa: BLE001 - missing known_hosts is fine
        pass
    if _SSH_AUTOADD:
        # Opt-in only (ENUMGRID_SSH_AUTOADD=1): trust unknown keys — convenient
        # for first-use on a LAN you control, at the cost of MITM detection.
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # nosec B507 - gated, off by default
    else:
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(
            ip, port=port, username=username, password=password,
            key_filename=key_filename, timeout=timeout, allow_agent=bool(key_filename),
            look_for_keys=bool(key_filename),
        )
    except Exception as exc:  # noqa: BLE001 - surface a clean reason
        return {"ok": False, "error": f"ssh connect failed ({type(exc).__name__})"}

    def _run(cmd: str) -> str:
        try:
            _in, out, _err = client.exec_command(cmd, timeout=timeout)  # nosec B601 - fixed, no user input
            return out.read().decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            return ""

    try:
        os_release = _run("cat /etc/os-release 2>/dev/null")
        uname = _run("uname -srm 2>/dev/null")
        pkgs = _run("dpkg -l 2>/dev/null || rpm -qa 2>/dev/null")
    finally:
        client.close()

    info = parse_uname(uname)
    return {
        "ok": True,
        "os": parse_os_release(os_release) or "Unknown",
        "kernel": f"{info['kernel_name']} {info['kernel_release']}".strip(),
        "arch": info["arch"],
        "packages": count_packages(pkgs),
        "method": "ssh-credentialed",
    }
