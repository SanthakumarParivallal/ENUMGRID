"""
threatintel.py — CVE prioritization with CISA KEV + FIRST EPSS.

CVSS tells you how bad a CVE *could* be; it doesn't tell you what's actually
being attacked. This module adds the two signals practitioners use to triage:

  * **CISA KEV** — the U.S. Known Exploited Vulnerabilities catalog: CVEs with
    confirmed in-the-wild exploitation. A KEV hit means "patch this now".
  * **FIRST EPSS** — a daily-updated probability (0..1) that a CVE will be
    exploited in the next 30 days.

Both feeds are free and need no key. KEV is cached as a local JSON file; EPSS
scores are cached in SQLite. Everything is best-effort: offline or on error we
simply skip enrichment (the CVE list is still shown, just without the extra
signals). This turns "here are 40 CVEs" into "these 3 are actively exploited —
fix them first".
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

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
DISABLED = os.environ.get("ENUMGRID_THREATINTEL_DISABLE", "").strip().lower() in ("1", "true", "yes", "on")
KEV_CACHE = os.environ.get("ENUMGRID_KEV_CACHE", os.path.join(_DIR, "enumgrid_kev.json"))
EPSS_CACHE = os.environ.get("ENUMGRID_EPSS_CACHE", os.path.join(_DIR, "enumgrid_epss_cache.db"))
KEV_TTL = max(1, int(os.environ.get("ENUMGRID_KEV_TTL_HOURS", "24"))) * 3600
EPSS_TTL = max(1, int(os.environ.get("ENUMGRID_EPSS_TTL_HOURS", "24"))) * 3600
_HTTP_TIMEOUT = 12

_lock = threading.Lock()
_kev_mem: set[str] | None = None
_kev_mem_at = 0.0


# --------------------------------------------------------------------------- #
# CISA KEV (cached JSON file -> in-memory set)
# --------------------------------------------------------------------------- #
def _download_kev() -> set[str]:
    req = urllib.request.Request(KEV_URL, headers={"User-Agent": "EnumGrid/1.0"})
    with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:  # nosec B310 - fixed HTTPS CISA feed
        data = json.loads(resp.read().decode("utf-8", "replace"))
    ids = {
        v.get("cveID", "").upper()
        for v in data.get("vulnerabilities", [])
        if v.get("cveID")
    }
    try:
        with open(KEV_CACHE, "w", encoding="utf-8") as fh:
            json.dump(sorted(ids), fh)
    except OSError:
        pass
    return ids


def kev_set() -> set[str]:
    """Return the set of KEV CVE ids (memory → file cache → live download)."""
    global _kev_mem, _kev_mem_at
    if DISABLED:
        return set()
    now = time.time()
    if _kev_mem is not None and now - _kev_mem_at < KEV_TTL:
        return _kev_mem
    # File cache, if fresh.
    try:
        if os.path.exists(KEV_CACHE) and now - os.path.getmtime(KEV_CACHE) < KEV_TTL:
            with open(KEV_CACHE, encoding="utf-8") as fh:
                _kev_mem = {c.upper() for c in json.load(fh)}
                _kev_mem_at = now
                return _kev_mem
    except (OSError, ValueError):
        pass
    # Live download (fall back to any stale file cache on failure).
    try:
        _kev_mem = _download_kev()
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        try:
            with open(KEV_CACHE, encoding="utf-8") as fh:
                _kev_mem = {c.upper() for c in json.load(fh)}
        except (OSError, ValueError):
            _kev_mem = set()
    _kev_mem_at = now
    return _kev_mem


# --------------------------------------------------------------------------- #
# FIRST EPSS (SQLite cache + batched API)
# --------------------------------------------------------------------------- #
@contextmanager
def _epss_conn():
    """EPSS cache connection that commits, rolls back on error, and always closes."""
    conn = sqlite3.connect(EPSS_CACHE, timeout=5)
    conn.execute("CREATE TABLE IF NOT EXISTS epss (cve TEXT PRIMARY KEY, score REAL, fetched_at REAL)")
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def _epss_cached(cves: list[str]) -> tuple[dict[str, float], list[str]]:
    """Return ({cve: score} fresh hits, [misses])."""
    hits: dict[str, float] = {}
    misses: list[str] = []
    now = time.time()
    try:
        with _epss_conn() as conn:
            for cve in cves:
                row = conn.execute(
                    "SELECT score, fetched_at FROM epss WHERE cve = ?", (cve,)
                ).fetchone()
                if row and now - row[1] < EPSS_TTL:
                    hits[cve] = row[0]
                else:
                    misses.append(cve)
    except sqlite3.Error:
        return {}, list(cves)
    return hits, misses


def _epss_store(scores: dict[str, float]) -> None:
    if not scores:
        return
    now = time.time()
    try:
        with _epss_conn() as conn:
            conn.executemany(
                "INSERT OR REPLACE INTO epss (cve, score, fetched_at) VALUES (?, ?, ?)",
                [(c, s, now) for c, s in scores.items()],
            )
    except sqlite3.Error:
        pass


def _query_epss(cves: list[str]) -> dict[str, float]:
    qs = urllib.parse.urlencode({"cve": ",".join(cves)})
    req = urllib.request.Request(f"{EPSS_URL}?{qs}", headers={"User-Agent": "EnumGrid/1.0"})
    with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:  # nosec B310 - fixed HTTPS FIRST EPSS API
        data = json.loads(resp.read().decode("utf-8", "replace"))
    out: dict[str, float] = {}
    for row in data.get("data", []):
        cve = (row.get("cve") or "").upper()
        try:
            out[cve] = float(row.get("epss"))
        except (TypeError, ValueError):
            continue
    return out


def epss_for(cve_ids: list[str]) -> dict[str, float]:
    """EPSS scores for the given CVE ids (cache-first, batched live query)."""
    cves = sorted({c.upper() for c in cve_ids if c and c.upper().startswith("CVE-")})
    if not cves:
        return {}
    hits, misses = _epss_cached(cves)
    if misses and not DISABLED:
        # FIRST allows large batches; chunk to keep URLs sane.
        fetched: dict[str, float] = {}
        for i in range(0, len(misses), 100):
            chunk = misses[i:i + 100]
            try:
                fetched.update(_query_epss(chunk))
            except (urllib.error.URLError, OSError, ValueError, TimeoutError):
                break  # best-effort; cache what we got
        # Record explicit 0.0 for CVEs EPSS doesn't know, so we don't re-query.
        _epss_store({c: fetched.get(c, 0.0) for c in misses})
        hits.update({c: fetched.get(c, 0.0) for c in misses})
    return hits


# --------------------------------------------------------------------------- #
# Enrichment + risk ranking
# --------------------------------------------------------------------------- #
_SEV_RANK = {
    Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
    Severity.LOW: 3, Severity.INFO: 4,
}


def risk_key(v: Vuln) -> tuple:
    """Sort key: KEV first, then EPSS desc, then CVSS desc, then severity."""
    return (
        0 if v.kev else 1,
        -(v.epss or 0.0),
        -(v.cvss or 0.0),
        _SEV_RANK.get(v.severity, 9),
    )


def enrich(vulns: list[Vuln]) -> list[Vuln]:
    """Annotate CVE findings with KEV + EPSS, then return them risk-ranked.

    Non-CVE findings (script names) pass through unchanged. Best-effort: any
    feed failure leaves the findings intact, just without the extra signals.
    """
    if not vulns:
        return vulns
    cve_ids = [v.id.upper() for v in vulns if v.id.upper().startswith("CVE-")]
    if cve_ids and not DISABLED:
        kev = kev_set()
        scores = epss_for(cve_ids)
        for v in vulns:
            cid = v.id.upper()
            if cid.startswith("CVE-"):
                if cid in kev:
                    v.kev = True
                if cid in scores:
                    v.epss = round(scores[cid], 4)
    return sorted(vulns, key=risk_key)
