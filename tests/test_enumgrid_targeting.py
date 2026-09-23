"""Targeting, IPv6, option-validation and export-interop tests.

These cover the capabilities an operator drives a real engagement with: the
target forms they actually type (ranges, hostnames, scope files), the
exclusions that keep out-of-scope assets out of scope, IPv6 reaching the wire
at all, and the export formats other tools consume.

Like the rest of the suite these perform **no network I/O**: DNS is mocked at
``socket.getaddrinfo`` and every socket is a stub, so the tests are safe and
deterministic in CI.
"""

import socket
import xml.etree.ElementTree as ET

import pytest

import purple_recon as pr


# --------------------------------------------------------------------------- #
# IPv6: a v6 target must actually reach the wire.
#
# Regression: the sweep opened an AF_INET socket for every target, so probing a
# v6 address raised OSError on every port and the host was reported **down** --
# a silent false negative, the worst failure mode for an enumeration tool.
# --------------------------------------------------------------------------- #
def test_af_for_picks_the_targets_own_family():
    assert pr._af_for("192.168.1.1") == socket.AF_INET
    assert pr._af_for("10.0.0.1") == socket.AF_INET
    assert pr._af_for("2001:db8::1") == socket.AF_INET6
    assert pr._af_for("fe80::1") == socket.AF_INET6


def test_sweep_opens_an_ipv6_socket_for_an_ipv6_target(monkeypatch):
    """The TCP knock must use AF_INET6, not fail every port on AF_INET."""
    seen: list[int] = []

    class _Sock:
        def __init__(self, family, kind):
            seen.append(family)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def settimeout(self, _):
            pass

        def connect_ex(self, _addr):
            return 0                      # completed handshake -> strong signal

    monkeypatch.setattr(pr.socket, "socket", _Sock)
    engine = pr.DiscoveryEngine(timeout=0.1, workers=1, use_ping=False, use_arp=False)

    up, via, ports, confidence = engine.is_alive("2001:db8::1")
    assert up is True and confidence == "strong"
    assert ports, "an open port must be recorded for a v6 host"
    assert set(seen) == {socket.AF_INET6}

    seen.clear()
    engine.is_alive("192.168.1.1")
    assert set(seen) == {socket.AF_INET}


def test_ping_command_uses_an_ipv6_capable_invocation(monkeypatch):
    """macOS needs `ping6`; Linux/Windows take `-6`. Plain `ping` fails on v6."""
    monkeypatch.setattr(pr.platform, "system", lambda: "Darwin")
    assert pr._ping_command("2001:db8::1", 3.0)[0] == "ping6"
    assert pr._ping_command("192.168.1.1", 3.0)[0] == "ping"

    monkeypatch.setattr(pr.platform, "system", lambda: "Linux")
    assert pr._ping_command("2001:db8::1", 3.0)[:2] == ["ping", "-6"]
    assert "-6" not in pr._ping_command("192.168.1.1", 3.0)

    monkeypatch.setattr(pr.platform, "system", lambda: "Windows")
    assert pr._ping_command("2001:db8::1", 3.0)[:2] == ["ping", "-6"]
    assert "-6" not in pr._ping_command("192.168.1.1", 3.0)


def test_socket_scan_uses_the_targets_family(monkeypatch):
    families: list[int] = []

    class _Sock:
        def __init__(self, family, kind):
            families.append(family)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def settimeout(self, _):
            pass

        def connect_ex(self, _addr):
            return 1                       # closed: no banner grab needed

    monkeypatch.setattr(pr.socket, "socket", _Sock)
    engine = pr.EnumerationEngine(nmap_args="-sV", workers=1, have_nmap=False)
    engine._socket_scan("2001:db8::1", [80])
    assert set(families) == {socket.AF_INET6}


def test_nmap_scan_passes_dash_6_for_ipv6_targets(monkeypatch):
    """Without -6 nmap rejects a v6 address and the host is reported down."""
    calls: list[str] = []

    class _Scanner:
        def scan(self, hosts, arguments):
            calls.append(arguments)

        def all_hosts(self):
            return []

    monkeypatch.setattr(pr, "nmap", type("M", (), {"PortScanner": _Scanner}))
    engine = pr.EnumerationEngine(nmap_args="-sV -Pn", workers=1, have_nmap=True)

    engine._nmap_scan("2001:db8::1")
    assert calls[-1].startswith("-6 ")

    engine._nmap_scan("192.168.1.1")
    assert "-6" not in calls[-1]


# --------------------------------------------------------------------------- #
# Hyphenated ranges: the syntax nmap accepts and operators type.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "spec, expected",
    [
        ("192.168.1.10-12", ["192.168.1.10", "192.168.1.11", "192.168.1.12"]),
        ("10.0.0.1-10.0.0.3", ["10.0.0.1", "10.0.0.2", "10.0.0.3"]),
        ("192.168.1.7-7", ["192.168.1.7"]),
    ],
)
def test_ranges_expand_inclusively(spec, expected):
    assert pr.ScopeValidator().validate(spec).hosts == expected


def test_range_is_not_widened_to_a_cidr():
    """A .10-.20 range is not CIDR-aligned; it must not pull in .0-.9."""
    hosts = pr.ScopeValidator().validate("192.168.1.10-20").hosts
    assert hosts[0] == "192.168.1.10" and hosts[-1] == "192.168.1.20"
    assert len(hosts) == 11


def test_reversed_and_malformed_ranges_are_rejected():
    for bad in ("192.168.1.20-10", "192.168.1.1-999"):
        with pytest.raises(pr.ScopeError):
            pr.ScopeValidator().validate(bad)


def test_oversized_range_trips_the_host_cap():
    with pytest.raises(pr.ScopeError, match="too large"):
        pr.ScopeValidator(max_hosts=10).validate("10.0.0.1-10.0.0.200")


# --------------------------------------------------------------------------- #
# Hostnames: resolved, never silently dropped.
# --------------------------------------------------------------------------- #
def _fake_getaddrinfo(mapping):
    def _inner(name, *_a, **_kw):
        if name not in mapping:
            raise socket.gaierror(f"no such host: {name}")
        return [(socket.AF_INET, None, None, "", (addr, 0)) for addr in mapping[name]]

    return _inner


def test_hostname_is_resolved_to_its_addresses(monkeypatch):
    monkeypatch.setattr(
        pr.socket, "getaddrinfo", _fake_getaddrinfo({"host.example.com": ["10.0.0.7"]})
    )
    assert pr.ScopeValidator().validate("host.example.com").hosts == ["10.0.0.7"]


def test_hostname_with_several_records_scans_all_of_them(monkeypatch):
    """A name serving several hosts must not be silently narrowed to one."""
    monkeypatch.setattr(
        pr.socket,
        "getaddrinfo",
        _fake_getaddrinfo({"ha.example.com": ["10.0.0.1", "10.0.0.2", "10.0.0.1"]}),
    )
    assert pr.ScopeValidator().validate("ha.example.com").hosts == ["10.0.0.1", "10.0.0.2"]


def test_unresolvable_hostname_raises_rather_than_scanning_nothing(monkeypatch):
    monkeypatch.setattr(pr.socket, "getaddrinfo", _fake_getaddrinfo({}))
    with pytest.raises(pr.ScopeError, match="Cannot resolve hostname"):
        pr.ScopeValidator().validate("nope.example.com")


def test_a_resolved_hostname_still_obeys_the_scope_policy(monkeypatch):
    """DNS is not an escape hatch: a name pointing at loopback is still refused."""
    monkeypatch.setattr(
        pr.socket, "getaddrinfo", _fake_getaddrinfo({"evil.example.com": ["127.0.0.1"]})
    )
    with pytest.raises(pr.ScopeError):
        pr.ScopeValidator().validate("evil.example.com")


def test_malformed_ip_is_an_address_error_not_a_dns_lookup(monkeypatch):
    """`999.1.1.1` is a bad address, not a hostname to resolve."""
    monkeypatch.setattr(
        pr.socket,
        "getaddrinfo",
        lambda *a, **k: pytest.fail("must not attempt DNS for a numeric target"),
    )
    with pytest.raises(pr.ScopeError):
        pr.ScopeValidator().validate("999.1.1.1")


# --------------------------------------------------------------------------- #
# Exclusions: what the operator declared out of scope stays out.
# --------------------------------------------------------------------------- #
def test_exclusions_remove_hosts_and_are_reported():
    scope = pr.ScopeValidator().validate(
        "192.168.1.0/24", exclude="192.168.1.1,192.168.1.100-110"
    )
    assert scope.n_hosts == 254 - 1 - 11
    assert "192.168.1.1" not in scope.hosts
    assert "192.168.1.105" not in scope.hosts
    # Reported, so the operator can verify what was left out.
    assert len(scope.excluded) == 12
    assert "192.168.1.1" in scope.excluded


def test_exclusion_accepts_a_cidr():
    """A /28 exclusion removes .0-.15; .1-.15 are the 15 that were in scope."""
    scope = pr.ScopeValidator().validate("192.168.1.0/24", exclude="192.168.1.0/28")
    assert scope.n_hosts == 254 - 15
    assert "192.168.1.5" not in scope.hosts
    assert "192.168.1.15" not in scope.hosts
    assert "192.168.1.16" in scope.hosts
    assert "192.168.1.20" in scope.hosts


def test_no_exclusion_leaves_the_scope_untouched():
    plain = pr.ScopeValidator().validate("192.168.1.0/30")
    assert plain.excluded == []
    assert plain.n_hosts == 2


def test_a_bad_exclusion_entry_is_reported_not_ignored(monkeypatch):
    """An exclusion that silently failed would scan a host believed out of scope."""
    monkeypatch.setattr(pr.socket, "getaddrinfo", _fake_getaddrinfo({}))
    with pytest.raises(pr.ScopeError):
        pr.ScopeValidator().validate("192.168.1.0/24", exclude="not-a-host.example")


# --------------------------------------------------------------------------- #
# Scope files (-iL / --exclude-file).
# --------------------------------------------------------------------------- #
def test_target_file_ignores_comments_and_blank_lines(tmp_path):
    path = tmp_path / "scope.txt"
    path.write_text(
        "# engagement scope\n"
        "\n"
        "192.168.1.1\n"
        "192.168.1.2   # the gateway\n"
        "192.168.1.3,192.168.1.4\n"
    )
    assert pr.read_target_file(str(path)) == (
        "192.168.1.1,192.168.1.2,192.168.1.3,192.168.1.4"
    )


def test_missing_target_file_fails_loudly(tmp_path):
    with pytest.raises(pr.ScopeError, match="Cannot read target file"):
        pr.read_target_file(str(tmp_path / "absent.txt"))


def test_empty_target_file_fails_loudly(tmp_path):
    path = tmp_path / "empty.txt"
    path.write_text("# only a comment\n\n")
    with pytest.raises(pr.ScopeError, match="no entries"):
        pr.read_target_file(str(path))


# --------------------------------------------------------------------------- #
# Scan-option validation: fail before the scan, not per host during it.
# --------------------------------------------------------------------------- #
def _args(**overrides):
    argv = ["192.168.1.0/24"]
    for key, value in overrides.items():
        argv += [f"--{key.replace('_', '-')}", str(value)]
    return pr.build_parser().parse_args(argv)


@pytest.mark.parametrize(
    "overrides",
    [
        {"top_ports": 0},
        {"top_ports": -5},
        {"top_ports": 99999},
        {"ports": "1-65535; rm -rf /"},
        {"ports": "$(id)"},
        {"ports": "99999"},
        {"host_timeout": "120s; id"},
        {"max_hosts": 0},
        {"scan_workers": 0},
        {"sweep_workers": 0},
    ],
)
def test_bad_scan_options_are_rejected_up_front(overrides):
    with pytest.raises(pr.ScopeError):
        pr.validate_scan_options(_args(**overrides))


@pytest.mark.parametrize(
    "overrides",
    [
        {"ports": "22,80,443"},
        {"ports": "1-1024"},
        {"ports": "T:80,U:53"},
        {"host_timeout": "2m"},
        {"host_timeout": "120s"},
        {"top_ports": 1000},
    ],
)
def test_valid_scan_options_are_accepted(overrides):
    pr.validate_scan_options(_args(**overrides))     # must not raise


# --------------------------------------------------------------------------- #
# Operator vs tool author: a deliverable must name who ran the scan.
# --------------------------------------------------------------------------- #
def test_resolve_operator_prefers_explicit_then_env(monkeypatch):
    monkeypatch.setenv("ENUMGRID_OPERATOR", "from-env")
    assert pr.resolve_operator("explicit") == "explicit"
    assert pr.resolve_operator(None) == "from-env"
    assert pr.resolve_operator("   ") == "from-env"


def test_resolve_operator_falls_back_without_inventing_a_name(monkeypatch):
    monkeypatch.delenv("ENUMGRID_OPERATOR", raising=False)
    monkeypatch.delenv("USER", raising=False)
    monkeypatch.delenv("USERNAME", raising=False)
    monkeypatch.setattr(pr.os, "getlogin", lambda: (_ for _ in ()).throw(OSError()))
    assert pr.resolve_operator(None) == "unknown"


def test_resolve_operator_never_returns_the_tool_author(monkeypatch):
    monkeypatch.setenv("ENUMGRID_OPERATOR", "alice")
    assert pr.resolve_operator(None) != pr.AUTHOR


# --------------------------------------------------------------------------- #
# Export interop.
# --------------------------------------------------------------------------- #
_REPORT = {
    "tool": "ENUMGRID",
    "version": "1.0.0",
    "target": "192.168.1.0/24",
    "operator": "alice",
    "engine": "nmap -sV",
    "started_at": "2026-09-23T10:00:00+00:00",
    "finished_at": "2026-09-23T10:02:00+00:00",
    "duration_seconds": 120.0,
    "summary": {"live_hosts": 1, "candidates": 254, "total_open_ports": 1},
    "hosts": [
        {
            "ip": "192.168.1.1",
            "hostname": "gw.local",
            "mac": "aa:bb:cc:dd:ee:ff",
            "vendor": 'Acme & <Co> "Ltd"',
            "os": "Linux",
            "status": "up",
            "open_count": 1,
            "ports": [
                {
                    "port": 443,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "https",
                    "product": "nginx",
                    "version": "1.24.0",
                }
            ],
        }
    ],
}


def test_nmap_xml_is_well_formed_and_carries_the_findings():
    root = ET.fromstring(pr.render_nmap_xml(_REPORT))
    assert root.tag == "nmaprun"
    host = root.find("host")
    assert host.find("address").get("addr") == "192.168.1.1"
    assert host.find("address").get("addrtype") == "ipv4"
    port = host.find("ports/port")
    assert port.get("portid") == "443"
    assert port.find("service").get("version") == "1.24.0"
    assert root.find("runstats/hosts").get("up") == "1"


def test_nmap_xml_declares_enumgrid_as_the_scanner():
    """The schema is nmap's; the data is ours. Claiming otherwise would
    misrepresent where the results came from."""
    root = ET.fromstring(pr.render_nmap_xml(_REPORT))
    assert root.get("scanner") == "enumgrid"


def test_nmap_xml_escapes_attribute_values():
    """An unescaped vendor string would produce unparseable XML."""
    root = ET.fromstring(pr.render_nmap_xml(_REPORT))
    vendor = root.findall("host/address")[1].get("vendor")
    assert vendor == 'Acme & <Co> "Ltd"'


def test_nmap_xml_marks_ipv6_addresses_correctly():
    report = {**_REPORT, "hosts": [{**_REPORT["hosts"][0], "ip": "2001:db8::1"}]}
    root = ET.fromstring(pr.render_nmap_xml(report))
    assert root.find("host/address").get("addrtype") == "ipv6"


def test_nmap_xml_omits_hosts_that_are_down():
    report = {**_REPORT, "hosts": [{**_REPORT["hosts"][0], "status": "down"}]}
    assert ET.fromstring(pr.render_nmap_xml(report)).find("host") is None


def test_markdown_report_records_operator_and_findings():
    out = pr.render_markdown_report(_REPORT)
    assert "# ENUMGRID scan report" in out
    assert "**Operator:** alice" in out
    assert "192.168.1.1" in out and "gw.local" in out
    assert "| 443 | tcp | open | https | nginx | 1.24.0 |" in out


def test_markdown_report_handles_an_empty_result():
    report = {**_REPORT, "hosts": []}
    assert "_No live hosts found._" in pr.render_markdown_report(report)


def test_exports_write_files(tmp_path):
    xml_path = pr.write_nmap_xml_report(_REPORT, str(tmp_path))
    md_path = pr.write_markdown_report(_REPORT, str(tmp_path))
    assert xml_path.endswith(".xml") and md_path.endswith(".md")
    ET.parse(xml_path)                                   # parses from disk
    assert "ENUMGRID scan report" in open(md_path).read()


# --------------------------------------------------------------------------- #
# Branding: the product has one name, including in client-facing artifacts.
# --------------------------------------------------------------------------- #
def test_no_legacy_brand_survives_in_any_rendered_surface():
    surfaces = [
        pr.render_html_report(_REPORT),
        pr.render_markdown_report(_REPORT),
        pr.render_nmap_xml(_REPORT),
    ]
    for surface in surfaces:
        assert "PURPLERECON" not in surface.upper().replace(" ", "")


def test_report_separates_the_tool_author_from_the_operator():
    state = pr.SharedState("192.168.1.0/24", False, "socket-scan", operator="alice")
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    scope = pr.ScopeValidator().validate("192.168.1.0/30")
    report = pr.build_report(state, scope, now, now)
    assert report["tool_author"] == pr.AUTHOR
    assert report["operator"] == "alice"
    assert report["author"] == "alice"           # deprecated alias
