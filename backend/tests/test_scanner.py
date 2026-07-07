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
    # Every CVE carries a clickable NVD reference link (the headline feature).
    assert by_id["CVE-2020-9999"].url == "https://nvd.nist.gov/vuln/detail/CVE-2020-9999"


# --- CVE reference links (auto "is this version vulnerable?" hyperlinks) ----- #
def test_cve_url_for_real_cve():
    assert scanner._cve_url("CVE-2021-44228") == "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
    assert scanner._cve_url("cve-2021-44228") == "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"


def test_cve_url_blank_for_non_cve():
    assert scanner._cve_url("ssl-heartbleed") == ""
    assert scanner._cve_url("") == ""


def test_script_vuln_with_cve_gets_url():
    v = scanner._script_to_vuln("smb-check", "State: VULNERABLE references CVE-2017-0144")
    assert v is not None and v.url == "https://nvd.nist.gov/vuln/detail/CVE-2017-0144"


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


# --- confidence + false-positive guards ------------------------------------ #
def test_confirmed_state_marks_confidence_confirmed():
    v = scanner._script_to_vuln("smb-vuln", "State: VULNERABLE\nRemote code execution")
    assert v is not None and v.confidence == "confirmed"


def test_cve_mention_without_state_is_version_confidence():
    v = scanner._script_to_vuln("some-check", "references CVE-2019-1234 in changelog")
    assert v is not None and v.confidence == "version"


@pytest.mark.parametrize(
    "output",
    [
        "No vulnerabilities found",
        "Couldn't determine if the target is vulnerable",
        "ERROR: script execution failed",
        "could not connect; no reply",
        "Server is NOT VULNERABLE to this check",
    ],
)
def test_non_finding_phrases_never_false_positive(output):
    assert scanner._script_to_vuln("http-check", output) is None


def test_vulners_findings_are_version_confidence():
    out = "CVE-2020-9999 9.8 https://vulners.com/x\n"
    vulns = scanner._parse_vulners(out)
    assert vulns and all(v.confidence == "version" for v in vulns)


def test_dedupe_prefers_confirmed_over_version():
    from models import Severity, Vuln

    merged = scanner._dedupe([
        Vuln(id="CVE-1", severity=Severity.HIGH, confidence="version", cvss=7.5),
        Vuln(id="CVE-1", severity=Severity.HIGH, confidence="confirmed"),
    ])
    assert len(merged) == 1
    assert merged[0].confidence == "confirmed"
    assert merged[0].cvss == 7.5  # the score carries over from the version match


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


def test_profile_recon_uses_safe_enum_scripts():
    a = scanner.build_host_scan_args("recon", None, None, False, False)
    assert "--script" in a and "ssl-cert" in a and "smb-os-discovery" in a
    # SMB share listing is info-gathering (not brute), so it belongs in recon.
    assert "smb-enum-shares" in a
    # recon must never pull in intrusive categories
    for bad in ("brute", "exploit", "dos", "malware"):
        assert bad not in a


def test_profile_stealth_is_syn_scan():
    a = scanner.build_host_scan_args("stealth", None, None, False, False)
    assert "-sS" in a.split()


def test_profile_comprehensive_full_range():
    a = scanner.build_host_scan_args("comprehensive", None, None, False, False)
    assert "-A" in a.split() and "-p-" in a.split()
    assert "--script" in a and "vuln" in a


def test_every_profile_builds_without_error():
    # Every advertised profile must produce a valid arg string (no KeyError, and
    # always a real scan type) — guards against a profile/meta drift.
    for name in scanner.SCAN_PROFILES:
        args = scanner.build_host_scan_args(name, None, None, False, False)
        assert args and "--host-timeout" in args
    # PROFILE_META and SCAN_PROFILES must stay in lockstep.
    assert set(scanner.PROFILE_META) == set(scanner.SCAN_PROFILES)


def test_deep_forces_vuln_scripts_on_any_profile():
    a = scanner.build_host_scan_args("quick", None, None, False, deep=True)
    assert "--script" in a and "vuln" in a


def test_privileged_adds_os_detection():
    a = scanner.build_host_scan_args("default", None, None, privileged=True, deep=False)
    assert "-O" in a.split() and "--osscan-guess" in a


def test_auto_cve_adds_vulners_without_deep():
    # A per-host scan checks versions for CVEs automatically (vulners), even when
    # the heavier deep 'vuln' pass is off.
    a = scanner.build_host_scan_args("default", None, None, False, deep=False, auto_cve=True)
    assert "--script" in a and "vulners" in a
    assert "vuln," not in a and a.count("vulners") == 1  # no duplicate / no active 'vuln'


def test_auto_cve_no_duplicate_when_deep():
    a = scanner.build_host_scan_args("default", None, None, False, deep=True, auto_cve=True)
    assert a.count("vulners") == 1


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


# --- privilege auto-adaptation (the unprivileged/sudo fix) ----------------- #
# Root-only scan types (-sS/-sU/-O) HARD-FAIL unprivileged ("requires root
# privileges. QUITTING!"). _adapt_args rewrites them to unprivileged-safe
# equivalents so every profile still runs. These tests pin that behaviour.


def test_adapt_downgrades_syn_to_connect():
    out, note = scanner._adapt_args("-sS -Pn -T2 --top-ports 200")
    toks = out.split()
    assert "-sT" in toks and "-sS" not in toks
    assert "connect" in note.lower()


def test_adapt_downgrades_udp_to_connect():
    out, note = scanner._adapt_args("-sU -sV -Pn --top-ports 50")
    toks = out.split()
    assert "-sT" in toks and "-sU" not in toks and "-sV" in toks
    assert "udp" in note.lower()


def test_adapt_expands_aggressive_keeping_safe_parts():
    out, note = scanner._adapt_args("-A -Pn -T4")
    toks = out.split()
    assert "-A" not in toks and "-sV" in toks and "-sC" in toks
    assert "-A" in note  # explains the -A downgrade


def test_adapt_strips_os_detection_and_source_port():
    out, note = scanner._adapt_args(
        "-sS -Pn --source-port 53 -O --osscan-guess --host-timeout 120s"
    )
    toks = out.split()
    assert "-O" not in toks and "--osscan-guess" not in toks
    assert "--source-port" not in toks and "53" not in toks
    assert "-sT" in toks and "-sS" not in toks
    assert "--host-timeout" in toks  # benign flags are preserved


def test_adapt_guarantees_a_scan_type_remains():
    # Even if every scan-type flag is dropped, a connect scan is forced in.
    out, _ = scanner._adapt_args("-O --osscan-guess -Pn")
    assert "-sT" in out.split()


def test_adapt_is_noop_for_unprivileged_safe_profiles():
    safe = "-sV -Pn -T4 --top-ports 200 --script vulners"
    out, note = scanner._adapt_args(safe)
    assert out == safe and note == ""


def test_adapt_dedupes_repeated_scan_type():
    # -sU -sV both touch scan flags; downgrading -sU must not yield two -sV/-sT.
    out, _ = scanner._adapt_args("-sV -sU -Pn")
    toks = out.split()
    assert toks.count("-sV") == 1 and toks.count("-sT") == 1


def test_every_profile_adapts_without_error_unprivileged():
    # The core guarantee: no profile's adapted command can require root.
    root_only = {"-sS", "-sA", "-sW", "-sM", "-sN", "-sF", "-sX", "-sU", "-sO",
                 "-O", "--osscan-guess", "-A", "-PR"}
    for name in scanner.SCAN_PROFILES:
        args = scanner.build_host_scan_args(name, None, None, privileged=True, deep=True)
        adapted, _ = scanner._adapt_args(args)
        leftover = root_only.intersection(adapted.split())
        assert not leftover, f"{name}: still root-only after adapt: {leftover}"
        assert any(t in adapted.split() for t in ("-sT", "-sV", "-sn", "-sL"))


def test_scan_capability_root(monkeypatch):
    scanner._reset_capability_cache()
    monkeypatch.setattr(scanner.os, "geteuid", lambda: 0, raising=False)
    assert scanner.scan_capability() == "root"
    assert scanner.can_raw_scan() is True
    assert scanner.is_privileged() is True
    scanner._reset_capability_cache()


def test_scan_capability_sudo(monkeypatch):
    scanner._reset_capability_cache()
    monkeypatch.setattr(scanner.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(scanner, "_probe_sudo", lambda: True)
    assert scanner.scan_capability() == "sudo"
    assert scanner.can_raw_scan() is True
    assert scanner.is_privileged() is False  # not root itself, elevates per-scan
    scanner._reset_capability_cache()


def test_scan_capability_unprivileged(monkeypatch):
    scanner._reset_capability_cache()
    monkeypatch.setattr(scanner.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(scanner, "_probe_sudo", lambda: False)
    assert scanner.scan_capability() == "unprivileged"
    assert scanner.can_raw_scan() is False
    scanner._reset_capability_cache()


def test_run_scan_unprivileged_adapts_and_returns_note(monkeypatch):
    """_run_scan rewrites root-only args and reports the note (no nmap binary)."""
    scanner._reset_capability_cache()
    monkeypatch.setattr(scanner, "scan_capability", lambda: "unprivileged")

    captured = {}

    class _FakeScanner:
        def scan(self, hosts, arguments):  # noqa: D401 - test double
            captured["hosts"] = hosts
            captured["args"] = arguments

    monkeypatch.setattr(scanner.nmap, "PortScanner", _FakeScanner)
    _, note = scanner._run_scan("192.168.0.1", "-sS -Pn --top-ports 10")
    assert "-sT" in captured["args"].split() and "-sS" not in captured["args"].split()
    assert "connect" in note.lower()
    scanner._reset_capability_cache()


def test_run_scan_sudo_falls_back_when_sudo_fails(monkeypatch):
    """If a cached sudo credential expired mid-session, _run_scan degrades
    gracefully to the unprivileged (adapted) path instead of erroring."""
    scanner._reset_capability_cache()
    monkeypatch.setattr(scanner, "scan_capability", lambda: "sudo")
    monkeypatch.setattr(scanner, "_sudo_scan", lambda hosts, args: None)  # sudo failed

    captured = {}

    class _FakeScanner:
        def scan(self, hosts, arguments):
            captured["args"] = arguments

    monkeypatch.setattr(scanner.nmap, "PortScanner", _FakeScanner)
    _, note = scanner._run_scan("192.168.0.1", "-sU -sV -Pn")
    assert "-sT" in captured["args"].split() and "-sU" not in captured["args"].split()
    assert note  # the downgrade was reported
    scanner._reset_capability_cache()


# --- runtime privilege elevation (dashboard "Elevate" — sudo password) ------ #
# The backend can be raised from unprivileged to real raw-socket scans at
# runtime by validating a sudo password, without a restart. These pin that the
# password is validated, held only in memory, lifts capability to "sudo", and is
# dropped cleanly — and is never required to run.


class _Proc:
    def __init__(self, returncode):
        self.returncode = returncode
        self.stdout = b""
        self.stderr = b""


def _reset_priv():
    scanner._SUDO_PASSWORD = None
    scanner._reset_capability_cache()


def test_elevate_sudo_success_lifts_capability(monkeypatch):
    _reset_priv()
    monkeypatch.setattr(scanner.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(scanner, "sudo_available", lambda: True)
    monkeypatch.setattr(scanner, "_AUTO_SUDO", True)
    seen = {}

    def _fake_run(argv, **kw):
        seen["argv"] = argv
        seen["input"] = kw.get("input")
        return _Proc(0)  # sudo accepted the password

    monkeypatch.setattr(scanner.subprocess, "run", _fake_run)
    ok, msg = scanner.elevate_sudo("s3cret")
    assert ok is True
    assert "-S" in seen["argv"] and "-k" in seen["argv"]  # stdin auth, forced re-auth
    assert seen["input"] == b"s3cret\n"
    # Capability now reports sudo even though _probe_sudo isn't consulted.
    assert scanner.scan_capability() == "sudo"
    assert scanner.can_raw_scan() is True
    assert scanner.privilege_status()["elevated"] is True
    _reset_priv()


def test_elevate_sudo_rejects_wrong_password(monkeypatch):
    _reset_priv()
    monkeypatch.setattr(scanner.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(scanner, "sudo_available", lambda: True)
    monkeypatch.setattr(scanner, "_AUTO_SUDO", True)
    monkeypatch.setattr(scanner.subprocess, "run", lambda argv, **kw: _Proc(1))
    ok, msg = scanner.elevate_sudo("wrong")
    assert ok is False and "rejected" in msg.lower()
    assert scanner._SUDO_PASSWORD is None  # never retained on failure
    _reset_priv()


def test_elevate_sudo_no_sudo_binary(monkeypatch):
    _reset_priv()
    monkeypatch.setattr(scanner.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(scanner, "sudo_available", lambda: False)
    ok, msg = scanner.elevate_sudo("pw")
    assert ok is False and "sudo" in msg.lower()
    _reset_priv()


def test_elevate_sudo_noop_when_root(monkeypatch):
    _reset_priv()
    monkeypatch.setattr(scanner.os, "geteuid", lambda: 0, raising=False)
    ok, msg = scanner.elevate_sudo("ignored")
    assert ok is True and "root" in msg.lower()
    _reset_priv()


def test_drop_privileges_forgets_password(monkeypatch):
    _reset_priv()
    monkeypatch.setattr(scanner.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(scanner, "sudo_available", lambda: True)
    monkeypatch.setattr(scanner, "_AUTO_SUDO", True)
    monkeypatch.setattr(scanner.subprocess, "run", lambda argv, **kw: _Proc(0))
    scanner.elevate_sudo("pw")
    assert scanner.scan_capability() == "sudo"
    scanner.drop_privileges()
    assert scanner._SUDO_PASSWORD is None
    monkeypatch.setattr(scanner, "_probe_sudo", lambda: False)
    assert scanner.scan_capability() == "unprivileged"
    _reset_priv()


def test_sudo_scan_feeds_password_via_stdin(monkeypatch):
    _reset_priv()
    scanner._SUDO_PASSWORD = "pw"  # primed
    seen = {}

    def _fake_run(argv, **kw):
        seen["argv"] = argv
        seen["input"] = kw.get("input")
        return _Proc(0)

    # Parse path returns something non-None; stub PortScanner to a trivial object.
    class _S:
        def analyse_nmap_xml_scan(self, **kw):
            pass

    monkeypatch.setattr(scanner.subprocess, "run", _fake_run)
    # Force stdout so _sudo_scan proceeds to parse.
    monkeypatch.setattr(scanner.subprocess, "run", lambda argv, **kw: type(
        "P", (), {"returncode": 0, "stdout": b"<xml/>", "stderr": b""})())
    monkeypatch.setattr(scanner.nmap, "PortScanner", _S)
    result = scanner._sudo_scan("192.168.0.1", "-sS -Pn")
    assert result is not None
    _reset_priv()


def test_sudo_scan_password_argv_uses_S(monkeypatch):
    _reset_priv()
    scanner._SUDO_PASSWORD = "pw"
    seen = {}

    def _fake_run(argv, **kw):
        seen["argv"] = argv
        seen["input"] = kw.get("input")
        return type("P", (), {"returncode": 1, "stdout": b"", "stderr": b""})()

    monkeypatch.setattr(scanner.subprocess, "run", _fake_run)
    scanner._sudo_scan("192.168.0.1", "-sS -Pn")
    assert "-S" in seen["argv"] and "-n" not in seen["argv"]
    assert seen["input"] == b"pw\n"
    _reset_priv()


def test_privilege_status_shape(monkeypatch):
    _reset_priv()
    monkeypatch.setattr(scanner.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(scanner, "_probe_sudo", lambda: False)
    monkeypatch.setattr(scanner, "sudo_available", lambda: True)
    monkeypatch.setattr(scanner, "_AUTO_SUDO", True)
    st = scanner.privilege_status()
    assert set(st) >= {
        "capability", "can_raw", "is_root", "elevated", "sudo_available", "can_elevate",
    }
    assert st["capability"] == "unprivileged"
    assert st["can_elevate"] is True  # not root + sudo present → elevation offered
    _reset_priv()
