"""
test_threatintel.py — KEV + EPSS prioritization (feeds mocked, caches isolated).

Pins the contract that makes triage trustworthy: KEV marks actively-exploited
CVEs, EPSS attaches exploit probability, results are risk-ranked (KEV first), and
everything caches + degrades gracefully offline.
"""

from __future__ import annotations

import threatintel as ti
from models import Severity, Vuln


def _v(cid, sev=Severity.MEDIUM, cvss=5.0):
    return Vuln(id=cid, severity=sev, cvss=cvss)


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
