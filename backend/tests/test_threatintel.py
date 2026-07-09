"""
test_threatintel.py — KEV + EPSS prioritization (feeds mocked, caches isolated).

Pins the contract that makes triage trustworthy: KEV marks actively-exploited
CVEs, EPSS attaches exploit probability, results are risk-ranked (KEV first), and
everything caches + degrades gracefully offline.
"""

from __future__ import annotations

import json
import os
import time

import threatintel as ti
from models import Severity, Vuln


def _v(cid, sev=Severity.MEDIUM, cvss=5.0):
    return Vuln(id=cid, severity=sev, cvss=cvss)


class _FakeResp:
    """Minimal context-manager stand-in for an ``urlopen`` response."""

    def __init__(self, payload: bytes):
        self._payload = payload

    def read(self, *a):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _mock_urlopen(monkeypatch, payload: dict):
    data = json.dumps(payload).encode()
    monkeypatch.setattr(ti.urllib.request, "urlopen", lambda *a, **k: _FakeResp(data))


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(ti, "KEV_CACHE", str(tmp_path / "kev.json"))
    monkeypatch.setattr(ti, "EPSS_CACHE", str(tmp_path / "epss.db"))
    monkeypatch.setattr(ti, "DISABLED", False)
    monkeypatch.setattr(ti, "_kev_mem", None)
    monkeypatch.setattr(ti, "_kev_mem_at", 0.0)


def test_kev_set_downloads_and_caches(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    calls = {"n": 0}

    def fake_dl():
        calls["n"] += 1
        return {"CVE-2021-44228", "CVE-2017-0144"}

    monkeypatch.setattr(ti, "_download_kev", fake_dl)
    assert "CVE-2021-44228" in ti.kev_set()
    # second call served from the in-memory/file cache — no second download
    ti.kev_set()
    assert calls["n"] == 1


def test_epss_caches_and_batches(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    calls = {"n": 0}

    def fake_query(cves):
        calls["n"] += 1
        return {c.upper(): 0.5 for c in cves}

    monkeypatch.setattr(ti, "_query_epss", fake_query)
    s1 = ti.epss_for(["CVE-2021-44228", "CVE-2017-0144"])
    assert s1["CVE-2021-44228"] == 0.5 and calls["n"] == 1
    # cached now → no further network
    ti.epss_for(["CVE-2021-44228"])
    assert calls["n"] == 1


def test_enrich_marks_kev_and_sorts_exploited_first(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(ti, "_download_kev", lambda: {"CVE-2021-44228"})
    monkeypatch.setattr(ti, "_query_epss", lambda cves: {
        "CVE-2021-44228": 0.97, "CVE-2016-0001": 0.02,
    })
    out = ti.enrich([
        _v("CVE-2016-0001", Severity.CRITICAL, 9.8),  # high CVSS but not exploited
        _v("CVE-2021-44228", Severity.HIGH, 7.5),     # KEV — must rank first
    ])
    assert out[0].id == "CVE-2021-44228"
    assert out[0].kev is True and out[0].epss == 0.97
    assert out[1].kev is False


def test_non_cve_findings_pass_through(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(ti, "_download_kev", lambda: set())
    monkeypatch.setattr(ti, "_query_epss", lambda cves: {})
    out = ti.enrich([_v("ssl-heartbleed", Severity.HIGH)])
    assert out[0].id == "ssl-heartbleed" and out[0].kev is False


def test_disabled_is_noop(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(ti, "DISABLED", True)

    def boom(*a):
        raise AssertionError("must not hit the network when disabled")

    monkeypatch.setattr(ti, "_download_kev", boom)
    monkeypatch.setattr(ti, "_query_epss", boom)
    out = ti.enrich([_v("CVE-2021-44228")])
    assert out[0].kev is False and out[0].epss is None


def test_risk_key_orders_kev_then_epss_then_cvss():
    kev = Vuln(id="CVE-A", kev=True, cvss=4.0)
    hi_epss = Vuln(id="CVE-B", epss=0.9, cvss=4.0)
    hi_cvss = Vuln(id="CVE-C", cvss=9.9)
    ranked = sorted([hi_cvss, hi_epss, kev], key=ti.risk_key)
    assert [v.id for v in ranked] == ["CVE-A", "CVE-B", "CVE-C"]


# --- the real feed/cache code paths (network mocked at urlopen) ------------- #
def test_download_kev_parses_upper_cases_and_caches(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _mock_urlopen(monkeypatch, {"vulnerabilities": [
        {"cveID": "CVE-2021-44228"}, {"cveID": "cve-2017-0144"}, {"nope": 1},
    ]})
    ids = ti._download_kev()
    assert ids == {"CVE-2021-44228", "CVE-2017-0144"}          # upper-cased, blanks skipped
    assert set(json.loads(open(ti.KEV_CACHE, encoding="utf-8").read())) == ids   # written to disk


def test_kev_set_disabled_returns_empty(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(ti, "DISABLED", True)
    assert ti.kev_set() == set()


def test_kev_set_reads_fresh_file_cache(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    with open(ti.KEV_CACHE, "w", encoding="utf-8") as fh:
        json.dump(["cve-2020-0001"], fh)

    def _no_download():
        raise AssertionError("must not download while the file cache is fresh")

    monkeypatch.setattr(ti, "_download_kev", _no_download)
    assert ti.kev_set() == {"CVE-2020-0001"}                   # served (upper-cased) from disk


def test_kev_set_falls_back_to_stale_cache_on_download_error(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    with open(ti.KEV_CACHE, "w", encoding="utf-8") as fh:
        json.dump(["CVE-2019-0001"], fh)
    old = time.time() - ti.KEV_TTL - 10
    os.utime(ti.KEV_CACHE, (old, old))                         # age the file cache out

    def _boom():
        raise OSError("network down")

    monkeypatch.setattr(ti, "_download_kev", _boom)
    assert ti.kev_set() == {"CVE-2019-0001"}                   # stale cache used as last resort


def test_query_epss_parses_and_skips_bad_values(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _mock_urlopen(monkeypatch, {"data": [
        {"cve": "CVE-2021-44228", "epss": "0.97"},
        {"cve": "CVE-2016-0001", "epss": "not-a-number"},      # unparseable → skipped
    ]})
    assert ti._query_epss(["CVE-2021-44228", "CVE-2016-0001"]) == {"CVE-2021-44228": 0.97}


def test_epss_for_no_cve_ids_is_empty(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    assert ti.epss_for(["not-a-cve", ""]) == {}


def test_epss_for_records_zero_when_query_fails(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)

    def _boom(chunk):
        raise OSError("down")

    monkeypatch.setattr(ti, "_query_epss", _boom)
    assert ti.epss_for(["CVE-2021-44228"]) == {"CVE-2021-44228": 0.0}   # miss recorded, not dropped


def test_epss_cache_read_and_write_errors_degrade(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(ti, "EPSS_CACHE", str(tmp_path))       # a directory → sqlite can't open a DB
    hits, misses = ti._epss_cached(["CVE-2021-44228"])
    assert hits == {} and misses == ["CVE-2021-44228"]         # read error → treat all as misses
    ti._epss_store({"CVE-2021-44228": 0.5})                    # write error is swallowed (no raise)


def test_epss_store_empty_is_noop(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    ti._epss_store({})                                         # early return, nothing written


def test_download_kev_cache_write_error_is_swallowed(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(ti, "KEV_CACHE", str(tmp_path))       # a directory → the cache write fails
    _mock_urlopen(monkeypatch, {"vulnerabilities": [{"cveID": "CVE-2021-44228"}]})
    assert ti._download_kev() == {"CVE-2021-44228"}           # ids returned despite the write error


def test_kev_set_ignores_corrupt_fresh_cache_then_downloads(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    with open(ti.KEV_CACHE, "w", encoding="utf-8") as fh:
        fh.write("{ not json")                               # fresh mtime, but unparseable
    monkeypatch.setattr(ti, "_download_kev", lambda: {"CVE-2020-0002"})
    assert ti.kev_set() == {"CVE-2020-0002"}                 # corrupt read skipped → live download


def test_kev_set_empty_when_download_and_cache_both_fail(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)                          # no cache file exists

    def _boom():
        raise OSError("network down")

    monkeypatch.setattr(ti, "_download_kev", _boom)
    assert ti.kev_set() == set()                             # nothing to fall back to → empty


def test_enrich_empty_list_passes_through():
    assert ti.enrich([]) == []
