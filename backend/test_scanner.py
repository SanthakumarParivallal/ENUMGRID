"""
test_scanner.py — deterministic unit tests for the NSE / OS parsing layer.

None of these touch the network or the nmap binary: they exercise the pure
functions that turn raw nmap script output into normalized, CVSS-scored
findings — the part most likely to regress when the parsing is tweaked.
"""

from __future__ import annotations

import pytest
import scanner
from models import Severity


# --- validate_target (anti flag-injection) --------------------------------- #
@pytest.mark.parametrize("good", ["192.168.1.1", "10.0.0.0/24", "host.local", "a-b_c.d"])
def test_validate_target_accepts_safe(good):
    assert scanner.validate_target(good) is True


@pytest.mark.parametrize("bad", ["", "-oG", " 1.2.3.4", "1.2.3.4 -p-", "a;b", "--script"])
def test_validate_target_rejects_unsafe(bad):
    assert scanner.validate_target(bad) is False


# --- CVSS -> severity banding ---------------------------------------------- #
@pytest.mark.parametrize(
    "score,expected",
    [
        (9.8, Severity.CRITICAL),
        (9.0, Severity.CRITICAL),
        (7.5, Severity.HIGH),
        (7.0, Severity.HIGH),
        (5.0, Severity.MEDIUM),
        (4.0, Severity.MEDIUM),
        (3.9, Severity.LOW),
        (0.1, Severity.LOW),
        (0.0, Severity.INFO),
    ],
)
def test_severity_from_cvss(score, expected):
    assert scanner._severity_from_cvss(score) == expected


# --- vulners output parsing ------------------------------------------------ #
def test_parse_vulners_extracts_scored_cves():
    output = (
        "\t  CVE-2018-15473   5.3   https://vulners.com/cve/CVE-2018-15473\n"
        "\t  CVE-2020-9999    9.8   https://vulners.com/cve/CVE-2020-9999\n"
    )
    vulns = scanner._parse_vulners(output)
    by_id = {v.id: v for v in vulns}
    assert by_id["CVE-2020-9999"].cvss == 9.8
    assert by_id["CVE-2020-9999"].severity == Severity.CRITICAL
    assert by_id["CVE-2018-15473"].severity == Severity.MEDIUM
    # Highest score sorts first.
    assert vulns[0].id == "CVE-2020-9999"


def test_parse_vulners_keeps_worst_score_per_cve():
    output = "CVE-2021-101 4.0 x\nCVE-2021-101 9.1 y\n"
    vulns = scanner._parse_vulners(output)
    assert len(vulns) == 1
    assert vulns[0].cvss == 9.1


def test_parse_vulners_caps_results():
    lines = "".join(f"CVE-2020-{i:04d} 5.0 x\n" for i in range(50))
    assert len(scanner._parse_vulners(lines)) == scanner._MAX_VULNERS


# --- single NSE script -> Vuln -------------------------------------------- #
def test_script_vulnerable_is_high():
    v = scanner._script_to_vuln("http-something", "State: VULNERABLE\nfoo")
    assert v is not None
    assert v.severity == Severity.HIGH


def test_script_wormable_is_critical():
    v = scanner._script_to_vuln("smb-vuln-ms17-010", "VULNERABLE: Remote Code Execution")
    assert v is not None
    assert v.severity == Severity.CRITICAL


def test_script_not_vulnerable_is_skipped():
    assert scanner._script_to_vuln("ssl-heartbleed", "NOT VULNERABLE") is None


def test_script_no_finding_is_skipped():
    assert scanner._script_to_vuln("banner", "just a banner, nothing here") is None


def test_script_cve_without_state_is_medium():
    v = scanner._script_to_vuln("some-check", "references CVE-2019-1234 in changelog")
    assert v is not None
    assert v.id == "CVE-2019-1234"
    assert v.severity == Severity.MEDIUM


# --- dedupe keeps the worst severity --------------------------------------- #
def test_dedupe_keeps_worst_and_sorts():
    from models import Vuln

    vulns = [
        Vuln(id="CVE-1", severity=Severity.MEDIUM),
        Vuln(id="CVE-1", severity=Severity.CRITICAL),  # worse → wins
        Vuln(id="CVE-2", severity=Severity.LOW),
    ]
    out = scanner._dedupe(vulns)
    by_id = {v.id: v for v in out}
    assert by_id["CVE-1"].severity == Severity.CRITICAL
    assert out[0].id == "CVE-1"  # critical sorts before low


# --- OS detection (fake nmap node, no binary) ------------------------------ #
class _FakeNode:
    """Minimal stand-in for python-nmap's PortScannerHostDict."""

    def __init__(self, data, osmatch=None):
        self._data = data
        self._osmatch = osmatch or []

    def get(self, key, default=None):
        if key == "osmatch":
            return self._osmatch
        return self._data.get(key, default)

    def all_protocols(self):
        return [k for k in self._data if k in ("tcp", "udp")]

    def __getitem__(self, proto):
        return self._data[proto]


def test_detect_os_prefers_osmatch():
    node = _FakeNode({}, osmatch=[{"name": "Linux 5.X"}])
    assert scanner._detect_os(node, []) == "Linux 5.X"


def test_detect_os_uses_os_cpe():
    node = _FakeNode({"tcp": {22: {"cpe": "cpe:/o:canonical:ubuntu_linux:22.04"}}})
    assert "Ubuntu" in scanner._detect_os(node, [])


def test_detect_os_falls_back_to_banner():
    from models import Port

    node = _FakeNode({"tcp": {22: {"cpe": ""}}})
    ports = [Port(port=22, service="ssh", version="OpenSSH 8.9 Ubuntu")]
    assert scanner._detect_os(node, ports) == "Linux (Ubuntu)"


def test_detect_os_unknown():
    node = _FakeNode({"tcp": {80: {"cpe": ""}}})
    assert scanner._detect_os(node, []) == "Unknown"


# --- nmap scan profiles (Zenmap-style) + injection safety ------------------ #
def test_profile_default_and_unknown_fallback():
    a = scanner.build_host_scan_args("default", None, None, privileged=False, deep=False)
    assert "-sV" in a and "--top-ports" in a
    # unknown profile name falls back to default (never an arbitrary string)
    assert scanner.build_host_scan_args("../../evil", None, None, False, False).startswith("-sV")


def test_profile_aggressive_uses_dash_A():
    a = scanner.build_host_scan_args("aggressive", None, None, privileged=False, deep=False)
    assert "-A" in a.split()
    # -A already includes -O, so we must NOT add a duplicate -O
    assert a.split().count("-O") == 0


def test_profile_vuln_adds_scripts():
    a = scanner.build_host_scan_args("vuln", None, None, False, False)
    assert "--script" in a and "vuln" in a and "vulners" in a


def test_deep_forces_vuln_scripts_on_any_profile():
    a = scanner.build_host_scan_args("quick", None, None, False, deep=True)
    assert "--script" in a and "vuln" in a


def test_privileged_adds_os_detection():
    a = scanner.build_host_scan_args("default", None, None, privileged=True, deep=False)
    assert "-O" in a.split() and "--osscan-guess" in a


def test_ports_override_is_validated():
    ok = scanner.build_host_scan_args("default", None, "1-1024,3389", False, False)
    assert "-p 1-1024,3389" in ok
    # an injection attempt is rejected (the space-containing spec fails the regex)
    bad = scanner.build_host_scan_args("default", None, "80 -oG output", False, False)
    assert "-oG" not in bad and "-p 80" not in bad


def test_scripts_are_validated_and_intrusive_blocked():
    assert scanner._safe_scripts("http-title,ssl-cert") == ["http-title", "ssl-cert"]
    # injection + intrusive categories are dropped
    assert scanner._safe_scripts("http-title; rm -rf /") == []
    assert scanner._safe_scripts("brute,exploit,dos,malware") == []
    assert scanner._safe_scripts("") == []


def test_scripts_flow_into_args_safely():
    a = scanner.build_host_scan_args("default", "http-title,$(whoami)", None, False, False)
    assert "http-title" in a
    assert "whoami" not in a and "$" not in a
