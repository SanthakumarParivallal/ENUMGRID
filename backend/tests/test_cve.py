"""
test_cve.py — live NVD enrichment: parsing, CPE handling, caching, dedupe.

The network is never touched: `_query_nvd` is monkeypatched and the cache points
at a tmp DB. These pin the contract that makes real-world CVE coverage work —
authoritative parsing, version-scoped CPE keys, a cache that avoids re-fetching,
and graceful no-ops when disabled or given no CPE.
"""

from __future__ import annotations

import cve
import pytest
from models import Severity

_SAMPLE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2016-6210",
                "descriptions": [{"lang": "en", "value": "OpenSSH user enumeration"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.9}}]},
            }
        },
        {
            "cve": {
                "id": "CVE-2016-10009",
                "descriptions": [{"lang": "en", "value": "ssh-agent code execution"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.3}}]},
            }
        },
    ]
}


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(cve, "CACHE_DB", str(tmp_path / "cve_cache.db"))
    monkeypatch.setattr(cve, "DISABLED", False)
    monkeypatch.setattr(cve, "_calls", [])
    yield


def test_cpe_to_23():
    assert cve.cpe_to_23("cpe:/a:openbsd:openssh:7.2p2") == "cpe:2.3:a:openbsd:openssh:7.2p2"
    assert cve.cpe_to_23("cpe:2.3:a:already:23") == "cpe:2.3:a:already:23"
    assert cve.cpe_to_23("") == ""
    assert cve.cpe_to_23(None) == ""
    assert cve.cpe_to_23("not-a-cpe") == ""


def test_parse_nvd_ranks_and_links():
    vulns = cve.parse_nvd(_SAMPLE)
    assert [v.id for v in vulns] == ["CVE-2016-10009", "CVE-2016-6210"]  # by score desc
    top = vulns[0]
    assert top.cvss == 7.3 and top.severity == Severity.HIGH
    assert top.url == "https://nvd.nist.gov/vuln/detail/CVE-2016-10009"
    assert top.confidence == "version"
    assert all(v.url.startswith("https://nvd.nist.gov/vuln/detail/CVE-") for v in vulns)


def test_parse_nvd_empty_is_empty():
    assert cve.parse_nvd({}) == []
    assert cve.parse_nvd({"vulnerabilities": []}) == []


def test_lookup_caches_and_avoids_refetch(monkeypatch):
    calls = {"n": 0}

    def fake_query(cpe23):
        calls["n"] += 1
        return _SAMPLE

    monkeypatch.setattr(cve, "_query_nvd", fake_query)
    first = cve.lookup("cpe:/a:openbsd:openssh:7.2p2")
    assert len(first) == 2 and calls["n"] == 1
    # Second call is served from cache — no extra network hit.
    second = cve.lookup("cpe:/a:openbsd:openssh:7.2p2")
    assert [v.id for v in second] == [v.id for v in first]
    assert calls["n"] == 1
    assert cve.cache_count() == 1


def test_lookup_no_cpe_or_disabled_is_noop(monkeypatch):
    def boom(_):
        raise AssertionError("must not query NVD")

    monkeypatch.setattr(cve, "_query_nvd", boom)
    assert cve.lookup("") == []
    assert cve.lookup(None) == []
    monkeypatch.setattr(cve, "DISABLED", True)
    assert cve.lookup("cpe:/a:vendor:prod:1.0") == []


def test_lookup_network_error_degrades_gracefully(monkeypatch):
    def fail(_):
        raise OSError("network down")

    monkeypatch.setattr(cve, "_query_nvd", fail)
    assert cve.lookup("cpe:/a:vendor:prod:1.0") == []  # no crash, no findings


def test_enrich_fetches_each_cpe_once(monkeypatch):
    calls = {"n": 0}

    def fake_query(cpe23):
        calls["n"] += 1
        return _SAMPLE

    monkeypatch.setattr(cve, "_query_nvd", fake_query)
    # Same CPE on two ports → a single NVD call, both ports enriched.
    out = cve.enrich({80: "cpe:/a:vendor:web:1.0", 443: "cpe:/a:vendor:web:1.0"})
    assert calls["n"] == 1
    assert len(out[80]) == 2 and len(out[443]) == 2


def test_enrich_skips_ports_without_cpe(monkeypatch):
    monkeypatch.setattr(cve, "_query_nvd", lambda c: _SAMPLE)
    out = cve.enrich({22: "", 80: "cpe:/a:vendor:web:1.0"})
    assert 22 not in out and 80 in out


# --- API-key persistence (survives a restart) ------------------------------- #
def test_api_key_persists_to_owner_only_file(tmp_path, monkeypatch):
    import os
    import stat

    kf = tmp_path / "nvd_key"
    monkeypatch.setattr(cve, "KEY_FILE", str(kf))
    monkeypatch.setattr(cve, "API_KEY", None)

    assert cve.set_api_key("SECRET-123") is True
    assert kf.exists()
    # Secret must be owner read/write only (0600).
    assert stat.S_IMODE(os.stat(kf).st_mode) == 0o600
    # What a fresh process would read on the next startup.
    assert cve._load_persisted_key() == "SECRET-123"


def test_clearing_api_key_removes_persisted_file(tmp_path, monkeypatch):
    kf = tmp_path / "nvd_key"
    monkeypatch.setattr(cve, "KEY_FILE", str(kf))
    monkeypatch.setattr(cve, "API_KEY", None)

    cve.set_api_key("x")
    assert kf.exists()
    assert cve.set_api_key("") is False
    assert not kf.exists()
    assert cve._load_persisted_key() is None


def test_load_persisted_key_missing_file_is_none(tmp_path, monkeypatch):
    monkeypatch.setattr(cve, "KEY_FILE", str(tmp_path / "does-not-exist"))
    assert cve._load_persisted_key() is None


# --- severity mapping + richer NVD parsing --------------------------------- #
def test_sev_from_score_bands():
    assert cve._sev_from_score(9.0) == Severity.CRITICAL
    assert cve._sev_from_score(7.0) == Severity.HIGH
    assert cve._sev_from_score(4.0) == Severity.MEDIUM
    assert cve._sev_from_score(0.1) == Severity.LOW
    assert cve._sev_from_score(0.0) == Severity.INFO


def test_parse_nvd_skips_entry_without_id():
    data = {"vulnerabilities": [{"cve": {"descriptions": []}}, {"cve": {"id": "CVE-2020-0001"}}]}
    assert [v.id for v in cve.parse_nvd(data)] == ["CVE-2020-0001"]


def test_parse_nvd_uses_cvss_v2_and_handles_missing_metrics():
    data = {"vulnerabilities": [
        {"cve": {"id": "CVE-A", "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 4.0}}]}}},
        {"cve": {"id": "CVE-B", "metrics": {}, "descriptions": [{"lang": "en", "value": "x"}]}},
    ]}
    by = {v.id: v for v in cve.parse_nvd(data)}
    assert by["CVE-A"].severity == Severity.MEDIUM and by["CVE-A"].cvss == 4.0
    assert by["CVE-B"].cvss is None and by["CVE-B"].severity == Severity.INFO  # no metrics → INFO


def test_parse_nvd_truncates_long_description():
    long_desc = "x" * 500
    data = {"vulnerabilities": [{"cve": {"id": "CVE-C",
             "descriptions": [{"lang": "en", "value": long_desc}]}}]}
    assert len(cve.parse_nvd(data)[0].title) == 140  # capped for a tidy UI/report


# --- live query path (mocked urlopen — still no network) -------------------- #
def test_query_nvd_builds_request_and_sends_api_key(monkeypatch):
    import json as _json

    captured = {}

    class _FakeResp:
        def __init__(self, body): self._body = body
        def read(self): return self._body
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["apikey"] = req.get_header("Apikey")  # urllib title-cases header names
        return _FakeResp(_json.dumps(_SAMPLE).encode())

    monkeypatch.setattr(cve, "API_KEY", "SECRET-KEY")
    monkeypatch.setattr(cve.urllib.request, "urlopen", fake_urlopen)
    data = cve._query_nvd("cpe:2.3:a:openbsd:openssh:7.2p2")
    assert data == _SAMPLE
    assert "virtualMatchString=" in captured["url"] and "resultsPerPage=50" in captured["url"]
    assert captured["apikey"] == "SECRET-KEY"       # key is sent, never logged


def test_key_active_and_rate_max_track_the_key(monkeypatch):
    monkeypatch.setattr(cve, "API_KEY", None)
    assert cve.key_active() is False and cve._rate_max() == 5     # anonymous limit
    monkeypatch.setattr(cve, "API_KEY", "K")
    assert cve.key_active() is True and cve._rate_max() == 45     # keyed limit


# --- cache expiry / corruption / DB-error resilience ------------------------ #
def test_cache_get_expired_entry_is_a_miss(monkeypatch):
    monkeypatch.setattr(cve, "CACHE_TTL", 10)
    with cve._conn() as conn:
        conn.execute("INSERT OR REPLACE INTO cve_cache VALUES (?, ?, ?)",
                     ("stale", cve.time.time() - 1000, "[]"))
    assert cve._cache_get("stale") is None           # older than TTL → refetch


def test_cache_get_corrupt_payload_is_a_miss():
    with cve._conn() as conn:
        conn.execute("INSERT OR REPLACE INTO cve_cache VALUES (?, ?, ?)",
                     ("bad", cve.time.time(), "{not-json"))
    assert cve._cache_get("bad") is None             # unparseable → miss, no crash


def test_cache_ops_survive_db_errors(monkeypatch, tmp_path):
    # Point the cache at a directory so sqlite can't open it: every cache op must
    # degrade quietly (best-effort contract), never raise into a scan.
    monkeypatch.setattr(cve, "CACHE_DB", str(tmp_path))
    assert cve.cache_count() == 0
    assert cve._cache_get("k") is None
    cve._cache_put("k", [])                           # no raise


def test_persist_key_survives_filesystem_error(monkeypatch, tmp_path):
    monkeypatch.setattr(cve, "KEY_FILE", str(tmp_path / "missing-dir" / "key"))
    cve._persist_key("x")                             # os.open fails → swallowed


# --- rate limiter (rolling window) ----------------------------------------- #
def test_acquire_slot_evicts_old_calls_and_allows(monkeypatch):
    monkeypatch.setattr(cve, "_calls", [cve.time.time() - 100])   # outside the window
    assert cve._acquire_slot(None) is True
    assert len(cve._calls) == 1                        # old evicted, new recorded


def test_acquire_slot_refuses_when_waiting_would_blow_budget(monkeypatch):
    now = cve.time.time()
    monkeypatch.setattr(cve, "API_KEY", None)          # cap = 5
    monkeypatch.setattr(cve, "_calls", [now] * 5)      # at the cap, all fresh
    assert cve._acquire_slot(deadline=now) is False    # would wait ~30s past deadline


def test_acquire_slot_waits_then_allows_without_deadline(monkeypatch):
    now = cve.time.time()
    monkeypatch.setattr(cve, "API_KEY", None)
    monkeypatch.setattr(cve, "_calls", [now - 29.9] * 5)   # at cap, oldest nearly aged out
    slept = {}
    monkeypatch.setattr(cve.time, "sleep", lambda s: slept.__setitem__("s", s))
    assert cve._acquire_slot(None) is True             # no deadline → waits, then allows
    assert slept["s"] > 0


def test_lookup_over_budget_returns_empty(monkeypatch):
    monkeypatch.setattr(cve, "_query_nvd", lambda c: pytest.fail("must not query over budget"))
    assert cve.lookup("cpe:/a:v:p:1", deadline=cve.time.time() - 1) == []


def test_lookup_rate_limited_returns_empty(monkeypatch):
    monkeypatch.setattr(cve, "_acquire_slot", lambda d: False)
    monkeypatch.setattr(cve, "_query_nvd", lambda c: pytest.fail("must not query when throttled"))
    assert cve.lookup("cpe:/a:v:p:1", deadline=cve.time.time() + 100) == []
