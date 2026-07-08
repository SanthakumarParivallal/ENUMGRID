"""
test_vulndb.py — the curated offline version→CVE reference.

Confirms well-known vulnerable builds are flagged (with NVD links + CVSS) while
patched/unrelated versions are not — the offline supplement must never guess.
"""

from __future__ import annotations

import pytest
from models import Severity
from vulndb import _ver, lookup_offline_cves


@pytest.mark.parametrize(
    "banner,cve",
    [
        ("vsftpd 2.3.4", "CVE-2011-2523"),
        ("ProFTPD 1.3.5", "CVE-2015-3306"),
        ("OpenSSH 7.2p2 Ubuntu", "CVE-2018-15473"),
        ("OpenSSH 8.9p1 Ubuntu", "CVE-2024-6387"),       # regreSSHion
        ("Apache httpd 2.4.49", "CVE-2021-41773"),
        ("Apache httpd 2.4.50 ((Unix))", "CVE-2021-42013"),
        ("lighttpd 1.4.63", "CVE-2022-41556"),           # the router's build
        ("Microsoft-IIS/6.0", "CVE-2017-7269"),
        ("Apache Tomcat/9.0.30", "CVE-2020-1938"),       # Ghostcat
        ("Webmin httpd 1.900", "CVE-2019-15107"),
        ("Exim smtpd 4.89", "CVE-2019-10149"),
        ("dnsmasq 2.87", "CVE-2023-50387"),
    ],
)
def test_known_vulnerable_versions_are_flagged(banner, cve):
    vulns = lookup_offline_cves(banner)
    ids = {v.id for v in vulns}
    assert cve in ids
    hit = next(v for v in vulns if v.id == cve)
    assert hit.url == f"https://nvd.nist.gov/vuln/detail/{cve}"
    assert hit.cvss is not None and hit.cvss > 0
    # Offline matches are version-based — flagged for verification, never "confirmed".
    assert hit.confidence == "version"


@pytest.mark.parametrize(
    "banner",
    [
        "OpenSSH 9.9p1",          # past both the enum and regreSSHion ranges
        "Apache httpd 2.4.62",    # patched
        "vsftpd 3.0.5",           # not the backdoored build
        "dnsmasq 2.90",           # fixed
        "nginx 1.25.3",           # modern
        "lighttpd 1.4.76",        # past the mod_wstunnel range
        "Apache Tomcat/9.0.40",   # Ghostcat fixed (>= 9.0.31)
        "Microsoft-IIS/10.0",     # not 6.0
        "",                       # no banner
        "some-random-service",    # no version
    ],
)
def test_safe_or_unknown_versions_are_not_flagged(banner):
    assert lookup_offline_cves(banner) == []


def test_database_has_grown_and_links_all_findings():
    # The curated DB is meaningfully sized and every entry links to NVD.
    import vulndb
    assert len(vulndb._DB) >= 14
    # Spot-check that a representative match always carries an NVD link.
    for banner in ("vsftpd 2.3.4", "OpenSSH 8.9p1", "Apache Tomcat/9.0.30"):
        for v in lookup_offline_cves(banner):
            assert v.url.startswith("https://nvd.nist.gov/vuln/detail/CVE-")


def test_severity_bands_from_cvss():
    crit = lookup_offline_cves("vsftpd 2.3.4")[0]
    assert crit.severity == Severity.CRITICAL  # 9.8
    med = lookup_offline_cves("OpenSSH 7.2")[0]
    assert med.severity == Severity.MEDIUM     # 5.3


def test_version_parser():
    assert _ver("OpenSSH 7.2p2") == (7, 2)
    assert _ver("2.4.49") == (2, 4, 49)
    assert _ver("no-version-here") == ()


def test_product_keyword_matches_whole_token_not_substring():
    """'httpd' must match "Apache httpd" but NOT inside "lighttpd".

    Regression guard for a real false positive: naive substring matching flagged
    a patched lighttpd with Apache's path-traversal CVE-2021-41773 because
    "httpd" is a substring of "lighttpd". Keyword matching is now token-bounded.
    """
    # the collision: a lighttpd build whose version happens to equal Apache's
    # vulnerable build must NOT inherit the Apache CVE.
    assert lookup_offline_cves("lighttpd 2.4.49") == []
    # the genuine Apache build is still detected.
    assert "CVE-2021-41773" in {v.id for v in lookup_offline_cves("Apache httpd 2.4.49")}
    # a version digit immediately after the product name still matches.
    assert "CVE-2021-41773" in {v.id for v in lookup_offline_cves("Apache/2.4.49")}


def test_kw_hit_helper_is_token_bounded():
    from vulndb import _kw_hit
    assert _kw_hit("apache httpd 2.4.49", ("httpd",)) is True
    assert _kw_hit("lighttpd 2.4.49", ("httpd",)) is False
    assert _kw_hit("microsoft-iis/6.0", ("iis",)) is True      # hyphen is a boundary
    assert _kw_hit("apache/2.4.49", ("apache",)) is True       # slash/digit boundary


def test_severity_bands_cover_all_thresholds():
    from vulndb import _sev

    assert _sev(9.8) == Severity.CRITICAL
    assert _sev(7.5) == Severity.HIGH
    assert _sev(5.3) == Severity.MEDIUM
    assert _sev(3.1) == Severity.LOW
