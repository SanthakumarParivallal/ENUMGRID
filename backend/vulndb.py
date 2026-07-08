"""
vulndb.py — a small, curated OFFLINE version→CVE reference.

The live nmap `vulners` script is authoritative but needs internet. This module
supplements it with a hand-checked table of well-known "this exact version is
vulnerable" cases so the dashboard still flags the classics (and works air-gapped).

Every entry is a documented, high-confidence fact (textbook vulnerable builds),
matched against the product name + version that service detection reports. When
nothing matches we return nothing — we never guess. The list is deliberately
small and conservative; `vulners` provides the long tail when online.
"""

from __future__ import annotations

import re

from models import Severity, Vuln

_VER_RE = re.compile(r"(\d+(?:\.\d+){0,3})")


def _kw_hit(low: str, keywords: tuple[str, ...]) -> bool:
    """True if any product keyword appears as a whole token in ``low``.

    Whole-token (letter-boundary) matching, not a bare substring: nmap's product
    string is space/slash/digit-delimited, so ``"httpd"`` must match "Apache
    httpd 2.4.49" but NOT "lighttpd 2.4.49" — otherwise lighttpd would inherit
    Apache's path-traversal CVE (a real false positive this guards against; see
    evaluation/cve_corpus.json). Boundaries are alphabetic only, so a version
    digit right after the name (e.g. "Apache/2.4.49") still matches.
    """
    return any(
        re.search(rf"(?<![a-z]){re.escape(k)}(?![a-z])", low) is not None
        for k in keywords
    )


def _ver(text: str | None) -> tuple[int, ...]:
    """Extract the leading dotted version from a banner → tuple of ints."""
    m = _VER_RE.search(text or "")
    if not m:
        return ()
    try:
        return tuple(int(x) for x in m.group(1).split("."))
    except ValueError:  # pragma: no cover - regex guarantees ints
        return ()


def _sev(cvss: float) -> Severity:
    if cvss >= 9.0:
        return Severity.CRITICAL
    if cvss >= 7.0:
        return Severity.HIGH
    if cvss >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


# Each row: (product keywords [match ANY on the banner], predicate(version)->bool,
#            CVE id, CVSS, short title). All facts verifiable on NVD. The live
# `vulners` scan is the authoritative, always-current source for ANY service/
# version online; this hand-checked table is the offline fallback for the
# best-known "this exact build is vulnerable" cases.
_DB: list[tuple[tuple[str, ...], object, str, float, str]] = [
    # --- FTP ---------------------------------------------------------------- #
    (("vsftpd",), lambda v: v == (2, 3, 4), "CVE-2011-2523", 9.8,
     "vsftpd 2.3.4 backdoor command execution"),
    (("proftpd",), lambda v: v == (1, 3, 5), "CVE-2015-3306", 9.8,
     "ProFTPD 1.3.5 mod_copy remote command execution"),
    # --- SSH ---------------------------------------------------------------- #
    (("openssh", "opensshd"), lambda v: (1, 0) <= v < (7, 7), "CVE-2018-15473", 5.3,
     "OpenSSH < 7.7 username enumeration"),
    (("openssh", "opensshd"), lambda v: (8, 5) <= v < (9, 8), "CVE-2024-6387", 8.1,
     "OpenSSH 8.5p1–9.7p1 regreSSHion signal-handler RCE"),
    # --- Web servers -------------------------------------------------------- #
    (("apache", "httpd"), lambda v: v == (2, 4, 49), "CVE-2021-41773", 7.5,
     "Apache httpd 2.4.49 path traversal / RCE"),
    (("apache", "httpd"), lambda v: v == (2, 4, 50), "CVE-2021-42013", 9.8,
     "Apache httpd 2.4.50 path traversal / RCE"),
    (("nginx",), lambda v: (0, 5, 6) <= v <= (1, 3, 9), "CVE-2013-2028", 7.5,
     "nginx 0.5.6–1.3.9 chunked-encoding stack overflow"),
    (("lighttpd",), lambda v: (1, 4, 46) <= v <= (1, 4, 66), "CVE-2022-41556", 7.5,
     "lighttpd 1.4.46–1.4.66 mod_wstunnel use-after-free"),
    (("microsoft-iis", "iis"), lambda v: v == (6, 0), "CVE-2017-7269", 7.5,
     "Microsoft IIS 6.0 WebDAV ScStoragePathFromUrl buffer overflow"),
    # --- App / management servers ------------------------------------------ #
    (("tomcat", "coyote"),
     lambda v: (9, 0) <= v < (9, 0, 31) or (8, 5) <= v < (8, 5, 51)
     or (7, 0) <= v < (7, 0, 100) or (6, 0) <= v < (7, 0),
     "CVE-2020-1938", 9.8, "Apache Tomcat AJP 'Ghostcat' file read / RCE"),
    (("webmin",), lambda v: (1, 890) <= v <= (1, 920), "CVE-2019-15107", 9.8,
     "Webmin 1.890–1.920 unauthenticated RCE (password_change.cgi)"),
    # --- Mail / DNS / file sharing / IRC ------------------------------------ #
    (("exim",), lambda v: (4, 87) <= v <= (4, 91), "CVE-2019-10149", 9.8,
     "Exim 4.87–4.91 remote command execution"),
    (("samba", "smbd"), lambda v: (3, 5, 0) <= v < (4, 6, 4), "CVE-2017-7494", 9.8,
     "Samba 3.5.0–4.6.x is_known_pipename() RCE (SambaCry)"),
    (("dnsmasq",), lambda v: (1, 0) <= v < (2, 90), "CVE-2023-50387", 7.5,
     "dnsmasq < 2.90 DNSSEC validation CPU exhaustion (KeyTrap)"),
    (("unrealircd",), lambda v: v == (3, 2, 8, 1), "CVE-2010-2075", 10.0,
     "UnrealIRCd 3.2.8.1 backdoor"),
]


def lookup_offline_cves(banner: str | None) -> list[Vuln]:
    """Return curated CVEs whose product + version match `banner` ("" → none).

    `banner` is the product/version string from service detection, e.g.
    "OpenSSH 7.2p2 Ubuntu" or "vsftpd 2.3.4".
    """
    low = (banner or "").lower()
    if not low:
        return []
    version = _ver(banner)
    if not version:
        return []
    out: list[Vuln] = []
    for keywords, predicate, cve, cvss, title in _DB:
        if _kw_hit(low, keywords) and predicate(version):
            out.append(
                Vuln(
                    id=cve,
                    title=title,
                    severity=_sev(cvss),
                    cvss=cvss,
                    output=(
                        f"{title} — CVSS {cvss:.1f} (offline reference, version-matched; "
                        "verify — distros may backport the fix)"
                    ),
                    url=f"https://nvd.nist.gov/vuln/detail/{cve}",
                    confidence="version",  # version-matched, not actively confirmed
                )
            )
    return out
