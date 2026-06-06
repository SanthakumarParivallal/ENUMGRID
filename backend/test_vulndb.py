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
        ("OpenSSH 7.2p2 Ubuntu", "CVE-2018-15473"),
        ("Apache httpd 2.4.49", "CVE-2021-41773"),
        ("Apache httpd 2.4.50 ((Unix))", "CVE-2021-42013"),
        ("ProFTPD 1.3.5", "CVE-2015-3306"),
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


@pytest.mark.parametrize(
    "banner",
    [
        "OpenSSH 9.6p1",          # patched
        "Apache httpd 2.4.62",    # patched
        "vsftpd 3.0.5",           # not the backdoored build
        "dnsmasq 2.90",           # fixed
        "nginx 1.25.3",           # modern
        "lighttpd 1.4.63",        # not in the offline table (vulners covers it)
        "",                       # no banner
        "some-random-service",    # no version
    ],
)
def test_safe_or_unknown_versions_are_not_flagged(banner):
    assert lookup_offline_cves(banner) == []


def test_severity_bands_from_cvss():
    crit = lookup_offline_cves("vsftpd 2.3.4")[0]
    assert crit.severity == Severity.CRITICAL  # 9.8
    med = lookup_offline_cves("OpenSSH 7.2")[0]
    assert med.severity == Severity.MEDIUM     # 5.3


def test_version_parser():
    assert _ver("OpenSSH 7.2p2") == (7, 2)
    assert _ver("2.4.49") == (2, 4, 49)
    assert _ver("no-version-here") == ()
