"""
cve.py — live, cached CVE enrichment from the authoritative NVD feed.

A hardcoded table can't keep up with real-world scanning, which hits thousands of
distinct product/versions. This module closes that gap by querying the **NVD API
2.0** (the US-government National Vulnerability Database — the canonical, complete
CVE corpus) using the **CPE** that nmap's service/version detection emits. So any
service nmap fingerprints gets matched against *every* published CVE, and
newly-published CVEs appear automatically — no code change, ever.

Design for real use:
  * **CPE-precise** — we query by the exact `cpe:2.3:a:vendor:product:version`,
    so results are version-scoped (few false positives), not keyword soup.
  * **Cached + growing** — every result is stored in a local SQLite cache, so
    repeat scans are instant and the tool keeps working **offline** once a
    service has been seen. The cache becomes a real, environment-specific DB.
  * **Rate-limit aware** — honours NVD's published limits (5 req/30s anonymous,
    50/30s with `ENUMGRID_NVD_API_KEY`) via a rolling window, plus a per-scan
    time budget so a scan never stalls. Anything not fetched in budget is still
    covered by the in-scan `vulners` script and filled into the cache next time.
  * **Best-effort** — any network/parse error degrades silently to cache +
    vulners + the curated offline set; a scan never fails because NVD is slow.

Env:
  ENUMGRID_NVD_API_KEY    raise the rate limit (recommended for heavy use)
  ENUMGRID_NVD_DISABLE=1  turn live NVD lookups off (cache/offline still used)
  ENUMGRID_CVE_CACHE      cache DB path (default beside this file)
  ENUMGRID_CVE_TTL_DAYS   cache freshness window (default 30)
  ENUMGRID_NVD_BUDGET     max seconds of live lookups per host scan (default 20)
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager

from models import Severity, Vuln

_DIR = os.path.dirname(os.path.abspath(__file__))

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# Where a dashboard-entered key is persisted so it survives a restart. Owner-only
# (0600) and gitignored — the key is still never logged. Overridable for tests.
KEY_FILE = os.environ.get("ENUMGRID_NVD_KEY_FILE", os.path.join(_DIR, ".enumgrid_nvd_key"))


def _load_persisted_key() -> str | None:
    """Read a previously-saved NVD key from the local key file, or None."""
    try:
        with open(KEY_FILE, encoding="utf-8") as fh:
            return fh.read().strip() or None
    except OSError:
        return None


# Precedence: the explicit env var (e.g. from .env) wins; otherwise fall back to a
# key persisted from the dashboard so it survives restarts. `_KEY_FROM_ENV` lets
# us avoid stomping an env-provided key with the on-disk file.
_KEY_FROM_ENV = bool(os.environ.get("ENUMGRID_NVD_API_KEY"))
API_KEY = os.environ.get("ENUMGRID_NVD_API_KEY") or _load_persisted_key() or None
DISABLED = os.environ.get("ENUMGRID_NVD_DISABLE", "").strip().lower() in ("1", "true", "yes", "on")
CACHE_DB = os.environ.get("ENUMGRID_CVE_CACHE", os.path.join(_DIR, "enumgrid_cve_cache.db"))
CACHE_TTL = max(1, int(os.environ.get("ENUMGRID_CVE_TTL_DAYS", "30"))) * 86400
MAX_PER_SERVICE = max(1, int(os.environ.get("ENUMGRID_CVE_MAX", "12")))
DEFAULT_BUDGET = max(0, int(os.environ.get("ENUMGRID_NVD_BUDGET", "20")))
_HTTP_TIMEOUT = 12

# Rolling-window rate limiter (shared across threads / concurrent host scans).
# The cap depends on whether an API key is set, which can change at runtime
# (see set_api_key), so it's computed on demand rather than frozen at import.
_RATE_WINDOW = 30.0
_lock = threading.Lock()
_calls: list[float] = []


def _rate_max() -> int:
    """Live NVD calls allowed per window — higher with an API key."""
    return 45 if API_KEY else 5


def key_active() -> bool:
    """True when an NVD API key is configured (env or set at runtime)."""
    return bool(API_KEY)


def _persist_key(key: str | None) -> None:
    """Save (0600) or remove the NVD key file so it survives a restart.

    Best-effort: any filesystem error is swallowed (the key still works for this
    process). The file is owner-read/write only and gitignored; the key value is
    never logged.
    """
    try:
        if key:
            # O_CREAT with 0600 so the secret is owner-only even on first write.
            fd = os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(key)
            os.chmod(KEY_FILE, 0o600)  # tighten perms even if the file pre-existed
        elif os.path.exists(KEY_FILE):
            os.remove(KEY_FILE)
    except OSError:
        pass


def set_api_key(key: str | None) -> bool:
    """Set (or clear) the NVD API key at runtime, and persist it across restarts.

    Returns True if a non-empty key is now active. The key is saved to a local,
    owner-only (0600), gitignored file so a key entered in the dashboard survives
    a restart — it is still never logged. A blank/None value clears it (removes
    the file and drops back to the anonymous rate limit). An ``ENUMGRID_NVD_API_KEY``
    env var still takes precedence on the next startup.
    """
    global API_KEY
    cleaned = (key or "").strip()
    API_KEY = cleaned or None
    _persist_key(API_KEY)
    return bool(API_KEY)


# --------------------------------------------------------------------------- #
# Local cache (SQLite) — makes repeat scans instant and the tool offline-capable.
# --------------------------------------------------------------------------- #
@contextmanager
def _conn():
    """Cache connection that commits, rolls back on error, and always closes."""
    conn = sqlite3.connect(CACHE_DB, timeout=5)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS cve_cache "
        "(key TEXT PRIMARY KEY, fetched_at REAL, payload TEXT)"
    )
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def cache_count() -> int:
    """Number of cached (service → CVEs) entries — the local DB's size."""
    try:
        with _conn() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM cve_cache").fetchone()[0])
    except sqlite3.Error:
        return 0


def _cache_get(key: str) -> list[Vuln] | None:
    try:
        with _conn() as conn:
            row = conn.execute(
                "SELECT fetched_at, payload FROM cve_cache WHERE key = ?", (key,)
            ).fetchone()
    except sqlite3.Error:
        return None
    if not row:
        return None
    fetched_at, payload = row
    if time.time() - fetched_at > CACHE_TTL:
        return None
    try:
        return [Vuln(**v) for v in json.loads(payload)]
    except (TypeError, ValueError):
        return None


def _cache_put(key: str, vulns: list[Vuln]) -> None:
    try:
        with _conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO cve_cache (key, fetched_at, payload) VALUES (?, ?, ?)",
                (key, time.time(), json.dumps([v.model_dump() for v in vulns])),
            )
    except sqlite3.Error:
        pass


# --------------------------------------------------------------------------- #
# CPE handling + NVD query/parse
# --------------------------------------------------------------------------- #
def cpe_to_23(cpe: str | None) -> str:
    """Normalize an nmap CPE (2.2 `cpe:/a:...`) to a 2.3 match string ("" if n/a)."""
    if not cpe:
        return ""
    cpe = cpe.strip()
    if cpe.startswith("cpe:2.3:"):
        return cpe
    if cpe.startswith("cpe:/"):
        return "cpe:2.3:" + cpe[len("cpe:/"):]
    return ""


def _sev_from_score(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


def _query_nvd(cpe23: str) -> dict:
    """One live NVD API call for a CPE match string. Raises on network error."""
    qs = urllib.parse.urlencode({"virtualMatchString": cpe23, "resultsPerPage": 50})
    req = urllib.request.Request(f"{NVD_URL}?{qs}", headers={"User-Agent": "EnumGrid/1.0"})
    if API_KEY:
        req.add_header("apiKey", API_KEY)
    # Fixed HTTPS NVD endpoint; scheme cannot be attacker-controlled.
    with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:  # nosec B310
        return json.loads(resp.read().decode("utf-8", "replace"))


def parse_nvd(data: dict) -> list[Vuln]:
    """Turn an NVD API 2.0 response into ranked, NVD-linked Vulns."""
    out: list[Vuln] = []
    for item in (data or {}).get("vulnerabilities", []):
        cve = item.get("cve", {})
        cid = cve.get("id", "")
        if not cid:
            continue
        score: float | None = None
        severity = Severity.INFO
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            arr = metrics.get(key)
            if arr:
                cdata = arr[0].get("cvssData", {})
                score = cdata.get("baseScore")
                severity = _sev_from_score(score or 0)
                break
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        out.append(
            Vuln(
                id=cid,
                title=desc[:140],
                severity=severity,
                cvss=score,
                output=f"{cid}{f' — CVSS {score:.1f}' if score else ''} (NVD, version-matched)",
                url=f"https://nvd.nist.gov/vuln/detail/{cid}",
                confidence="version",
            )
        )
    out.sort(key=lambda v: (v.cvss or 0.0), reverse=True)
    return out[:MAX_PER_SERVICE]


def _acquire_slot(deadline: float | None) -> bool:
    """Rolling-window rate gate. False if waiting would blow the budget."""
    with _lock:
        now = time.time()
        while _calls and now - _calls[0] > _RATE_WINDOW:
            _calls.pop(0)
        if len(_calls) >= _rate_max():
            wait = _RATE_WINDOW - (now - _calls[0]) + 0.2
            if deadline is not None and now + wait > deadline:
                return False
            time.sleep(wait)
            now = time.time()
            while _calls and now - _calls[0] > _RATE_WINDOW:
                _calls.pop(0)
        _calls.append(time.time())
        return True


def lookup(cpe: str | None, deadline: float | None = None) -> list[Vuln]:
    """CVEs for one CPE: cache-first, then a budgeted, rate-limited live NVD call."""
    cpe23 = cpe_to_23(cpe)
    if not cpe23:
        return []
    cached = _cache_get(cpe23)
    if cached is not None:
        return cached
    if DISABLED:
        return []
    if deadline is not None and time.time() >= deadline:
        return []  # out of per-scan budget — vulners covers it; cache next time
    if not _acquire_slot(deadline):
        return []
    try:
        data = _query_nvd(cpe23)
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return []  # best-effort: degrade to vulners / offline
    vulns = parse_nvd(data)
    _cache_put(cpe23, vulns)  # grow the local DB
    return vulns


def enrich(cpe_by_port: dict[int, str], budget_s: int | None = None) -> dict[int, list[Vuln]]:
    """Map {port: cpe} → {port: [Vuln]}, cache-first with a shared time budget.

    The same CPE seen on multiple ports/hosts is fetched once, so a /24 of
    identical services costs a single NVD call (then it's cached).
    """
    budget = DEFAULT_BUDGET if budget_s is None else budget_s
    deadline = (time.time() + budget) if budget else None
    results: dict[int, list[Vuln]] = {}
    seen: dict[str, list[Vuln]] = {}
    for port, cpe in cpe_by_port.items():
        cpe23 = cpe_to_23(cpe)
        if not cpe23:
            continue
        if cpe23 in seen:
            results[port] = seen[cpe23]
            continue
        found = lookup(cpe, deadline)
        seen[cpe23] = found
        if found:
            results[port] = found
    return results
