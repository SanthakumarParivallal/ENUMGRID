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
