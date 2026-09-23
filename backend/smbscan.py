"""
smbscan.py: authenticated SMB enumeration (real, credential-gated).

On a Windows or file-server estate the share layout is a core internal-recon
fact: which shares exist, their type, and whether the supplied account can
actually read them. ENUMGRID already discovers shares *unauthenticated* through
nmap's ``smb-enum-shares`` script; this module adds the *credentialed* half:
given an account, it connects over SMB2/3 (`smbprotocol`, an optional
dependency) and verifies, read-only, which shares that account can reach and
what is at their root.

No writes, no file exfiltration, no password guessing: a single authenticated
session and read-only directory listings. Credentials are used in memory only,
never logged or persisted. Authorized use only: hosts you administer or are
explicitly permitted to test.

The share-shaping, type-classification, credential-splitting and nmap-output
parsing are pure and fully unit-tested; the live connect/list runs only when
`smbprotocol` and credentials are provided, mirroring `adscan.py` (LDAP) and
`credscan.py` (SSH).
"""

from __future__ import annotations

import os
import re

# The import guard is environment-dependent (smbprotocol may or may not be
# installed), so both branches are excluded from coverage; the live code below
# is exercised in tests by injecting a fake `smbclient`, exactly as adscan's
# LDAP path is tested with a fake ldap3.
try:  # pragma: no cover - optional dependency
    import smbclient  # part of the `smbprotocol` package

    _HAVE_SMB = True
except Exception:  # pragma: no cover - optional dependency
    smbclient = None
    _HAVE_SMB = False

# Seconds to wait for the SMB TCP accept and each operation. A wrong host or a
# firewalled 445 should surface as a clean error in a few seconds, not after the
# OS's multi-minute TCP retry schedule.
SMB_TIMEOUT = max(1, int(os.environ.get("ENUMGRID_SMB_TIMEOUT", "8")))

# Windows SRVSVC share-type constants (the low byte is the base type; the high
# bits are flags). Used to label a share without depending on the SMB library.
_STYPE_MASK = 0x000000FF
_STYPE_BASE = {0: "disk", 1: "print", 2: "device", 3: "ipc"}
_STYPE_SPECIAL = 0x80000000   # administrative share (C$, ADMIN$, IPC$)
_STYPE_TEMPORARY = 0x40000000

# The default administrative shares to probe when the caller supplies no list
# and none were discovered. Reaching these with an account is the classic
# "this account is a local admin here" signal.
DEFAULT_SHARES = ("C$", "ADMIN$", "IPC$")


def available() -> bool:
    """True if smbprotocol is installed (authenticated SMB is possible)."""
    return _HAVE_SMB


def is_admin_share(name: str) -> bool:
    """A ``$``-suffixed share (C$, ADMIN$, IPC$) is administrative/hidden."""
    return bool(name) and name.endswith("$")


def share_type_label(flags: int) -> str:
    """Human label for an SRVSVC share-type bitmask (e.g. 0x80000000 -> 'disk (admin)')."""
    try:
        value = int(flags)
    except (TypeError, ValueError):
        return "unknown"
    base = _STYPE_BASE.get(value & _STYPE_MASK, "unknown")
    tags = []
    if value & _STYPE_SPECIAL:
        tags.append("admin")
    if value & _STYPE_TEMPORARY:
        tags.append("temporary")
    return f"{base} ({', '.join(tags)})" if tags else base


def split_credential(username: str, domain: str = "") -> tuple[str, str]:
    """Normalise ``DOMAIN\\user`` / ``user@domain`` / bare user -> (domain, user).

    An explicit ``domain`` argument wins only when the username carries none, so
    a fully-qualified ``CORP\\alice`` is never silently re-homed.
    """
    user = (username or "").strip()
    dom = (domain or "").strip()
    if "\\" in user:
        d, _, u = user.partition("\\")
        return d.strip(), u.strip()
    if "@" in user:
        u, _, d = user.partition("@")
        return d.strip(), u.strip()
    return dom, user


def shape_shares(raw: list[dict]) -> list[dict]:
    """Normalise raw share entries into stable rows for the report/UI.

    Each input may carry ``name``, ``type`` (int bitmask) and ``comment``. The
    output adds ``admin``/``type_label`` and drops nothing, so the caller sees
    every share the account was told about.
    """
    out: list[dict] = []
    for entry in raw or []:
        name = str((entry or {}).get("name", "") or "").strip()
        if not name:
            continue
        row = {
            "name": name,
            "comment": str(entry.get("comment", "") or ""),
            "admin": is_admin_share(name),
        }
        if "type" in entry:
            row["type_label"] = share_type_label(entry.get("type"))
        # Access, when known ("READ"/"WRITE"/"DENIED"), is passed through as-is.
        if entry.get("access"):
            row["access"] = str(entry["access"])
        out.append(row)
    return out


# nmap `smb-enum-shares` prints one indented "\\HOST\SHARE:" block per share,
# followed by "Anonymous access:" / "Current user access:" lines. This lifts the
# share names and the current-user access out of that text (unauthenticated
# discovery), which the authenticated pass below then confirms.
_NMAP_SHARE_RE = re.compile(r"\\\\[^\\]+\\([^\s:]+)\s*:?\s*$")
_NMAP_ACCESS_RE = re.compile(r"current user access:\s*([A-Za-z/<> ]+)", re.IGNORECASE)


def parse_nmap_smb_shares(script_text: str) -> list[dict]:
    """Parse nmap ``smb-enum-shares`` script output into ``[{name, access?}]``.

    Best-effort and forgiving: unrecognised lines are ignored, so a change in
    nmap's phrasing degrades to fewer fields, never an exception.
    """
    shares: list[dict] = []
    current: dict | None = None
    for line in (script_text or "").splitlines():
        m = _NMAP_SHARE_RE.search(line.strip())
        if m:
            current = {"name": m.group(1).strip()}
            shares.append(current)
            continue
        if current is not None:
            a = _NMAP_ACCESS_RE.search(line)
            if a:
                current["access"] = a.group(1).strip()
    return shape_shares(shares)


def enumerate_shares(
    host: str,
    username: str,
    password: str,
    domain: str = "",
    shares: list[str] | None = None,
    port: int = 445,
) -> dict:
    """Authenticated SMB: connect and verify read access to ``shares`` (read-only).

    Returns ``{"ok": bool, "error"?: str, "host", "shares": [...] }``. Never
    raises: a bad host, refused credentials or a blocked port come back as
    ``{"ok": False, "error": ...}`` with a clean reason, so a false negative is
    an honest "could not connect", never a fabricated share list.

    For each candidate share it attempts a read-only directory listing of the
    share root and records ``access`` as ``READ`` (listing succeeded), ``DENIED``
    (access refused) or ``ERROR`` (share missing / other). No writes are ever
    attempted.
    """
    if not _HAVE_SMB:
        return {"ok": False, "error": "smbprotocol not installed (pip install smbprotocol)"}
    dom, user = split_credential(username, domain)
    candidates = [s for s in (shares or list(DEFAULT_SHARES)) if str(s).strip()]
    account = f"{dom}\\{user}" if dom else user
    try:
        # A single registered session, reused across every share probe.
        smbclient.register_session(
            host, username=account, password=password, port=port,
            connection_timeout=SMB_TIMEOUT,
        )
    except Exception as exc:  # noqa: BLE001 - clean reason (creds / network / port)
        return {"ok": False, "error": f"SMB session failed ({type(exc).__name__})"}

    results: list[dict] = []
    try:
        for name in candidates:
            unc = f"\\\\{host}\\{name}"
            entry: dict = {"name": name, "admin": is_admin_share(name)}
            try:
                # Read-only listing of the share root: proves authenticated read
                # access without touching any file.
                items = smbclient.listdir(unc)
                entry["access"] = "READ"
                entry["entries"] = len(items)
            except Exception as exc:  # noqa: BLE001
                # PermissionError -> DENIED; anything else -> ERROR (missing, etc.)
                entry["access"] = "DENIED" if isinstance(exc, PermissionError) else "ERROR"
            results.append(entry)
    finally:
        try:
            smbclient.delete_session(host, port=port)
        except Exception:  # noqa: BLE001
            pass

    return {
        "ok": True,
        "host": host,
        "account": account,  # domain\user, never the password
        "shares": results,
        "method": "smb-credentialed",
    }
