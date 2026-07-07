"""test_osv.py — backport-aware OSV matching (network mocked, cache isolated)."""

from __future__ import annotations

import osv
import pytest
from models import Severity


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(osv, "CACHE_DB", str(tmp_path / "osv.db"))
    monkeypatch.setattr(osv, "DISABLED", False)


@pytest.mark.parametrize(
    "os_name,eco",
    [
        ("Ubuntu 22.04.4 LTS", "Ubuntu:22.04"),
        ("Debian GNU/Linux 11 (bullseye)", "Debian:11"),
        ("Alpine Linux v3.19", "Alpine:v3.19"),
        ("Fedora Linux 39", ""),     # unsupported ecosystem → skip
        ("", ""),
    ],
)
def test_ecosystem_from_os(os_name, eco):
    assert osv.ecosystem_from_os(os_name) == eco


_SAMPLE = {
    "vulns": [
        {
            "id": "USN-1234-1",
            "aliases": ["CVE-2023-1234"],
            "summary": "OpenSSL flaw",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/...  9.8"}],
            "database_specific": {"severity": "CRITICAL"},
        },
        {"id": "OSV-2020-1", "summary": "no alias", "database_specific": {"severity": "LOW"}},
    ]
}


def test_parse_prefers_cve_alias_and_links_nvd():
    vulns = osv.parse_osv(_SAMPLE)
    by_id = {v.id: v for v in vulns}
    assert "CVE-2023-1234" in by_id
    c = by_id["CVE-2023-1234"]
    assert c.severity == Severity.CRITICAL  # from distro database_specific severity
    assert c.url == "https://nvd.nist.gov/vuln/detail/CVE-2023-1234"
    # no-CVE entry keeps the OSV id and links to osv.dev
    assert "OSV-2020-1" in by_id
    assert by_id["OSV-2020-1"].url == "https://osv.dev/vulnerability/OSV-2020-1"


def test_lookup_caches(monkeypatch):
    calls = {"n": 0}

    def fake_q(name, version, eco):
        calls["n"] += 1
        return _SAMPLE

    monkeypatch.setattr(osv, "_query", fake_q)
    a = osv.lookup("openssl", "1.1.1n-0ubuntu1", "Ubuntu:22.04")
    assert len(a) == 2 and calls["n"] == 1
    osv.lookup("openssl", "1.1.1n-0ubuntu1", "Ubuntu:22.04")  # cached
    assert calls["n"] == 1


def test_lookup_skips_without_ecosystem(monkeypatch):
    monkeypatch.setattr(osv, "_query", lambda *a: (_ for _ in ()).throw(AssertionError("no query")))
    assert osv.lookup("openssl", "1.0", "") == []


def test_backport_aware_empty_means_not_vulnerable(monkeypatch):
    # OSV returning {} for a patched version => no findings (the suppression).
    monkeypatch.setattr(osv, "_query", lambda *a: {"vulns": []})
    assert osv.lookup("bash", "5.1-6ubuntu1.1", "Ubuntu:22.04") == []


def test_scan_packages_dedupes(monkeypatch):
    monkeypatch.setattr(osv, "_query", lambda *a: _SAMPLE)
    out = osv.scan_packages([("openssl", "1.0"), ("libssl", "1.0")], "Ubuntu:22.04")
    ids = sorted(v.id for v in out)
    assert ids == ["CVE-2023-1234", "OSV-2020-1"]  # deduped across packages
