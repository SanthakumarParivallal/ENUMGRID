"""
osv.py — backport-aware vulnerability matching via OSV.dev.

Matching a *banner version* to NVD over-reports: distros backport security fixes
without bumping the upstream version, so "OpenSSH 8.9" looks vulnerable even when
Ubuntu already patched it. OSV.dev solves this — its Debian/Ubuntu/Alpine feeds
encode the *distro-fixed* versions, so querying an installed package + version in
its distro ecosystem returns only the CVEs that **actually still affect it**.

Paired with the credentialed scan's real package list, this is authoritative,
backport-aware assessment instead of guesswork. Cached in SQLite, batched,
best-effort (offline / error → no findings, never a crash). Free, no API key.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import time
import urllib.error
import urllib.request

from models import Severity, Vuln

_DIR = os.path.dirname(os.path.abspath(__file__))
OSV_QUERY = "https://api.osv.dev/v1/query"
CACHE_DB = os.environ.get("ENUMGRID_OSV_CACHE", os.path.join(_DIR, "enumgrid_osv_cache.db"))
CACHE_TTL = max(1, int(os.environ.get("ENUMGRID_OSV_TTL_HOURS", "24"))) * 3600
DISABLED = os.environ.get("ENUMGRID_OSV_DISABLE", "").strip().lower() in ("1", "true", "yes", "on")
MAX_PACKAGES = max(1, int(os.environ.get("ENUMGRID_OSV_MAX_PKGS", "400")))
_HTTP_TIMEOUT = 10
_CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.IGNORECASE)


def ecosystem_from_os(os_name: str) -> str:
    """Map an `/etc/os-release` name to an OSV ecosystem ("" if unsupported).

    e.g. "Ubuntu 22.04.4 LTS" → "Ubuntu:22.04", "Debian GNU/Linux 11" →
    "Debian:11", "Alpine Linux v3.19" → "Alpine:v3.19".
    """
    low = (os_name or "").lower()
    ver = re.search(r"(\d+(?:\.\d+)?)", os_name or "")
    if "ubuntu" in low and ver:
        return f"Ubuntu:{ver.group(1)}"
    if "debian" in low and ver:
        return f"Debian:{ver.group(1).split('.')[0]}"
    if "alpine" in low and ver:
        mm = ".".join(ver.group(1).split(".")[:2])
        return f"Alpine:v{mm}"
    return ""


# --------------------------------------------------------------------------- #
# Cache
# --------------------------------------------------------------------------- #
def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(CACHE_DB, timeout=5)
    conn.execute("CREATE TABLE IF NOT EXISTS osv (key TEXT PRIMARY KEY, payload TEXT, fetched_at REAL)")
    return conn


def _cache_get(key: str) -> list[Vuln] | None:
    try:
        with _conn() as conn:
            row = conn.execute("SELECT payload, fetched_at FROM osv WHERE key = ?", (key,)).fetchone()
    except sqlite3.Error:
        return None
    if not row or time.time() - row[1] > CACHE_TTL:
        return None
    try:
        return [Vuln(**v) for v in json.loads(row[0])]
    except (TypeError, ValueError):
        return None


def _cache_put(key: str, vulns: list[Vuln]) -> None:
    try:
        with _conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO osv (key, payload, fetched_at) VALUES (?, ?, ?)",
                (key, json.dumps([v.model_dump() for v in vulns]), time.time()),
            )
    except sqlite3.Error:
        pass


# --------------------------------------------------------------------------- #
# Query + parse
# --------------------------------------------------------------------------- #
def _sev_text(text: str) -> Severity:
    t = (text or "").upper()
    if "CRITICAL" in t:
        return Severity.CRITICAL
    if "HIGH" in t:
        return Severity.HIGH
    if "MEDIUM" in t or "MODERATE" in t:
        return Severity.MEDIUM
    if "LOW" in t:
        return Severity.LOW
    return Severity.INFO


def parse_osv(data: dict) -> list[Vuln]:
    """Turn an OSV `/v1/query` response into Vulns (CVE-linked where possible)."""
    out: list[Vuln] = []
    for v in (data or {}).get("vulns", []):
        osv_id = v.get("id", "")
        aliases = v.get("aliases", []) or []
        cve = next((a.upper() for a in aliases if _CVE_RE.fullmatch(a)), "")
        if not cve:  # distro ids like "UBUNTU-CVE-2019-1543" embed the CVE
            m = _CVE_RE.search(osv_id)
            if m:
                cve = m.group(0).upper()
        vid = cve or osv_id
        if not vid:
            continue
        # OSV severity vectors carry no clean base score, so band by the distro's
        # text severity (KEV/EPSS + NVD/vulners supply the precise CVSS later).
        dbs = (v.get("database_specific") or {}).get("severity")
        sev = _sev_text(dbs) if dbs else Severity.MEDIUM
        url = f"https://nvd.nist.gov/vuln/detail/{vid}" if cve else f"https://osv.dev/vulnerability/{osv_id}"
        out.append(
            Vuln(
                id=vid,
                title=(v.get("summary") or "")[:140],
                severity=sev,
                cvss=None,
                output=f"{vid} — distro-confirmed affecting installed version (OSV)",
                url=url,
                confidence="version",  # version-scoped, but distro/backport-aware
            )
        )
    return out


def _query(name: str, version: str, ecosystem: str) -> dict:
    body = json.dumps({"version": version, "package": {"name": name, "ecosystem": ecosystem}}).encode()
    req = urllib.request.Request(
        OSV_QUERY, data=body, headers={"Content-Type": "application/json", "User-Agent": "EnumGrid/1.0"}
    )
    with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:  # nosec B310 - fixed HTTPS OSV endpoint
        return json.loads(resp.read().decode("utf-8", "replace"))


def lookup(name: str, version: str, ecosystem: str) -> list[Vuln]:
    """Backport-aware CVEs for one installed package (cache-first)."""
    if DISABLED or not (name and version and ecosystem):
        return []
    key = f"{ecosystem}|{name}|{version}"
    cached = _cache_get(key)
    if cached is not None:
        return cached
    try:
        vulns = parse_osv(_query(name, version, ecosystem))
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return []
    _cache_put(key, vulns)
    return vulns


def scan_packages(packages: list[tuple[str, str]], ecosystem: str) -> list[Vuln]:
    """Backport-aware findings across an installed-package list (deduped)."""
    if not ecosystem or not packages:
        return []
    by_id: dict[str, Vuln] = {}
    for name, version in packages[:MAX_PACKAGES]:
        for v in lookup(name, version, ecosystem):
            by_id.setdefault(v.id, v)
    return list(by_id.values())
