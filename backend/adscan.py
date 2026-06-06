"""
adscan.py — Active Directory / LDAP enumeration (real, credential-gated).

In a Windows environment the domain controller is the map of the whole estate.
Given domain credentials, this enumerates computers and users from AD over LDAP
(`ldap3`, optional dependency) — the foundation of internal AD recon: hostnames,
operating systems, last-logon, and accounts. Read-only searches only.

The DN / base-DN helpers and the entry-shaping are fully unit-tested; the live
bind/search runs only when ldap3 + credentials are provided. Authorized use
only — your own domain.
"""

from __future__ import annotations

try:
    import ldap3

    _HAVE_LDAP3 = True
except Exception:  # pragma: no cover - optional dependency
    _HAVE_LDAP3 = False


def available() -> bool:
    """True if ldap3 is installed (AD enumeration is possible)."""
    return _HAVE_LDAP3


def base_dn_from_domain(domain: str) -> str:
    """'corp.example.com' → 'DC=corp,DC=example,DC=com'."""
    parts = [p for p in (domain or "").split(".") if p]
    return ",".join(f"DC={p}" for p in parts)


def shape_computers(entries: list[dict]) -> list[dict]:
    """LDAP computer entries (with an 'attributes' dict) → asset rows."""
    out: list[dict] = []
    for e in entries or []:
        a = e.get("attributes", {}) or {}
        name = a.get("dNSHostName") or a.get("name") or a.get("cn") or ""
        out.append({
            "type": "ad-computer",
            "name": str(name),
            "os": str(a.get("operatingSystem", "") or ""),
            "os_version": str(a.get("operatingSystemVersion", "") or ""),
            "last_logon": str(a.get("lastLogonTimestamp", "") or ""),
        })
    return out


def shape_users(entries: list[dict]) -> list[dict]:
    """LDAP user entries → account rows (sAMAccountName + flags)."""
    out: list[dict] = []
    for e in entries or []:
        a = e.get("attributes", {}) or {}
        out.append({
            "type": "ad-user",
            "sam": str(a.get("sAMAccountName", "") or ""),
            "name": str(a.get("displayName") or a.get("cn") or ""),
            "enabled": _is_enabled(a.get("userAccountControl")),
        })
    return out


def _is_enabled(uac) -> bool:
    """AD userAccountControl: bit 0x2 (ACCOUNTDISABLE) clear == enabled."""
    try:
        return not (int(uac) & 0x2)
    except (TypeError, ValueError):
        return True


def enumerate_domain(
    dc_host: str, domain: str, username: str, password: str,
    use_ssl: bool = True, limit: int = 500,
) -> dict:
    """Bind to a DC and enumerate computers + users (read-only). Best-effort."""
    if not _HAVE_LDAP3:
        return {"ok": False, "error": "ldap3 not installed (pip install ldap3)"}
    base = base_dn_from_domain(domain)
    if not base:
        return {"ok": False, "error": "invalid domain"}
    try:
        server = ldap3.Server(dc_host, use_ssl=use_ssl, get_info=ldap3.NONE)
        user = username if "\\" in username or "@" in username else f"{domain}\\{username}"
        conn = ldap3.Connection(server, user=user, password=password, auto_bind=True)
    except Exception as exc:  # noqa: BLE001 - clean reason (bind/creds/network)
        return {"ok": False, "error": f"LDAP bind failed ({type(exc).__name__})"}
    try:
        conn.search(base, "(objectClass=computer)", attributes=ldap3.ALL_ATTRIBUTES, size_limit=limit)
        computers = shape_computers([e for e in conn.response if e.get("type") == "searchResEntry"])
        conn.search(base, "(&(objectClass=user)(objectCategory=person))",
                    attributes=["sAMAccountName", "displayName", "cn", "userAccountControl"],
                    size_limit=limit)
        users = shape_users([e for e in conn.response if e.get("type") == "searchResEntry"])
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"LDAP search failed ({type(exc).__name__})"}
    finally:
        try:
            conn.unbind()
        except Exception:  # noqa: BLE001
            pass
    return {"ok": True, "base_dn": base, "computers": computers, "users": users}
