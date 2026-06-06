"""Deterministic pytest suite for ``purple_recon.py``.

These tests exercise the security-critical and pure-logic paths only — the
guardrails, host expansion, report build/write, the differential analysis and
the renderer.  They perform **no network I/O**, so they are safe and
reproducible in CI and for the project write-up.

Run:  python3 -m pytest            (uses pytest.ini)
      python3 -m pytest -v
"""

import io
import json
import os
import stat
import string
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from hypothesis import given
from hypothesis import strategies as st
from rich.console import Console

import purple_recon as pr

# --------------------------------------------------------------------------- #
# Guardrails — ScopeValidator must hard-refuse protected address space
# --------------------------------------------------------------------------- #
FORBIDDEN_TARGETS = [
    "127.0.0.1",          # loopback host
    "127.0.0.0/8",        # loopback network
    "224.0.0.1",          # multicast host
    "239.1.1.1",          # multicast (administratively scoped)
    "255.255.255.255",    # limited broadcast
    "169.254.1.5",        # link-local
    "0.0.0.0",            # unspecified
    "::1",                # IPv6 (unsupported in v1)
    "not.an.ip",          # garbage
    "",                   # empty
]


@pytest.mark.parametrize("target", FORBIDDEN_TARGETS)
def test_scope_rejects_forbidden(target):
    with pytest.raises(pr.ScopeError):
        pr.ScopeValidator().validate(target)


def test_scope_cidr_excludes_network_and_broadcast():
    scope = pr.ScopeValidator().validate("192.168.1.0/30")
    assert scope.hosts == ["192.168.1.1", "192.168.1.2"]
    assert "192.168.1.0" not in scope.hosts      # network address excluded
    assert "192.168.1.3" not in scope.hosts      # broadcast excluded
    assert scope.n_hosts == 2


def test_scope_single_host_forms():
    assert pr.ScopeValidator().validate("192.168.1.50").hosts == ["192.168.1.50"]
    assert pr.ScopeValidator().validate("192.168.1.50/32").hosts == ["192.168.1.50"]


def test_scope_slash31_uses_both_addresses():
    # RFC 3021 point-to-point links: both addresses are usable.
    assert pr.ScopeValidator().validate("10.0.0.0/31").hosts == ["10.0.0.0", "10.0.0.1"]


def test_scope_mixed_skips_forbidden_keeps_valid():
    scope = pr.ScopeValidator().validate("192.168.1.10,127.0.0.1,8.8.8.8")
    assert scope.hosts == ["8.8.8.8", "192.168.1.10"]      # numeric IP sort
    assert len(scope.blocked) == 1 and scope.blocked[0][0] == "127.0.0.1"
    assert "loopback" in scope.blocked[0][1]
    assert scope.has_public is True                        # 8.8.8.8 is public


def test_scope_private_only_not_flagged_public():
    assert pr.ScopeValidator().validate("192.168.1.0/30").has_public is False


def test_scope_host_cap_raises():
    with pytest.raises(pr.ScopeError):
        pr.ScopeValidator(max_hosts=100).validate("192.168.0.0/23")  # 510 hosts


def test_scope_deduplicates_overlapping_entries():
    scope = pr.ScopeValidator().validate("192.168.1.0/30,192.168.1.1")
    assert scope.hosts == ["192.168.1.1", "192.168.1.2"]  # .1 listed once


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def test_ping_command_is_safe_and_targets_host():
    cmd = pr._ping_command("1.2.3.4", 3.0)
    assert cmd[0] == "ping" and cmd[-1] == "1.2.3.4"
    # the generous timeout must be reflected in the command (3s, not the old 1s)
    assert "3" in cmd


def test_ping_command_rounds_timeout_up():
    # 2.1s must not truncate to 2s and miss a ~2.1s responder.
    assert "3" in pr._ping_command("1.2.3.4", 2.1)


# ---- ARP-cache discovery (catches local devices that ignore ICMP) ----
def test_normalise_mac_zero_pads_octets():
    # macOS `arp -a` strips leading zeros: '0:f:15:..' must become '00:0f:15:..'.
    assert pr._normalise_mac("0:f:15:58:df:43") == "00:0f:15:58:df:43"
    assert pr._normalise_mac("8c:98:6b:37:39:70") == "8c:98:6b:37:39:70"


@pytest.mark.parametrize(
    "mac, is_host",
    [
        ("8c:98:6b:37:39:70", True),    # ordinary unicast host
        ("ff:ff:ff:ff:ff:ff", False),   # broadcast
        ("00:00:00:00:00:00", False),   # empty/incomplete
        ("01:00:5e:00:00:fb", False),   # IPv4 multicast
        ("33:33:00:00:00:01", False),   # IPv6 multicast
        ("not-a-mac", False),           # garbage
    ],
)
def test_is_host_mac(mac, is_host):
    assert pr._is_host_mac(mac) is is_host


def test_read_arp_table_parses_and_filters(monkeypatch):
    import subprocess as _sp

    sample = (
        "? (192.168.1.0) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]\n"
        "? (192.168.1.1) at 0:f:15:58:df:43 on en0 ifscope [ethernet]\n"
        "? (192.168.1.2) at (incomplete) on en0 ifscope [ethernet]\n"
        "iphone (192.168.1.108) at e:7f:fc:f7:58:97 on en0 ifscope [ethernet]\n"
        "? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope [ethernet]\n"
    )
    monkeypatch.setattr(
        pr.subprocess,
        "run",
        lambda *a, **k: _sp.CompletedProcess(a, 0, stdout=sample, stderr=""),
    )
    table = pr._read_arp_table()
    assert table["192.168.1.1"] == "00:0f:15:58:df:43"   # zero-padded
    assert table["192.168.1.108"] == "0e:7f:fc:f7:58:97"  # the ICMP-silent phone
    assert "192.168.1.0" not in table                     # broadcast excluded
    assert "192.168.1.2" not in table                     # (incomplete) excluded
    assert "224.0.0.251" not in table                     # multicast excluded


def test_proxy_macs_detects_router_answering_for_many_ips():
    # One MAC answering for many IPs == proxy-ARP router (the 172.16 case).
    table = {f"172.16.3.{i}": "2c:c8:1b:61:73:00" for i in range(1, 30)}
    table["172.16.3.50"] = "aa:bb:cc:dd:ee:01"  # a genuine distinct device
    table["172.16.3.51"] = "aa:bb:cc:dd:ee:02"
    proxy = pr._proxy_macs(table, threshold=8)
    assert "2c:c8:1b:61:73:00" in proxy          # the proxying router
    assert "aa:bb:cc:dd:ee:01" not in proxy       # real devices are NOT flagged


def test_proxy_macs_empty_when_all_unique():
    table = {f"10.0.0.{i}": f"aa:bb:cc:00:00:{i:02x}" for i in range(1, 20)}
    assert pr._proxy_macs(table, threshold=8) == set()


# ---- MAC-vendor (OUI) lookup ----
def test_oui_key_format():
    assert pr._oui_key("d84489") == "D8:44:89"


@pytest.mark.parametrize(
    "mac, expected",
    [
        ("d8:44:89:11:22:33", "TP-Link"),         # universal OUI -> built-in vendor
        ("00:0f:15:aa:bb:cc", "Icotera"),         # the user's router
        ("8c:98:6b:aa:bb:cc", "Apple"),           # the user's non-random iPhone
        ("0e:7f:fc:f7:58:97", pr.VENDOR_RANDOM),  # 0x02 bit set -> randomized phone
        ("d2:5a:d6:e4:64:5c", pr.VENDOR_RANDOM),  # randomized (private Wi-Fi addr)
        ("00:11:22:dd:ee:ff", None),              # universal but unknown OUI
        (None, None),
        ("", None),
    ],
)
def test_mac_vendor(mac, expected):
    assert pr._mac_vendor(mac, {}) == expected


def test_mac_vendor_loaded_table_overrides_fallback():
    assert pr._mac_vendor("8c:98:6b:00:00:00", {"8C:98:6B": "CustomCorp"}) == "CustomCorp"


def test_load_oui_table_csv(tmp_path):
    f = tmp_path / "oui.csv"
    f.write_text(
        "Registry,Assignment,Organization Name,Organization Address\n"
        "MA-L,ABCDEF,Acme Networks Inc,Somewhere\n"
    )
    table = pr.load_oui_table(str(f))
    assert table["AB:CD:EF"].startswith("Acme")


def test_load_oui_table_txt(tmp_path):
    f = tmp_path / "oui.txt"
    f.write_text("ABCDEF     (base 16)\t\tAcme Networks Inc\n")
    assert "AB:CD:EF" in pr.load_oui_table(str(f))


def test_load_oui_table_missing_returns_empty():
    assert pr.load_oui_table("/nonexistent/oui.csv") == {}


def test_sanitize_filename():
    assert pr._sanitize_filename("192.168.1.0/24") == "192-168-1-0-24"
    assert pr._sanitize_filename("///") == "scan"


def test_ip_key_orders_numerically_not_lexically():
    assert pr._ip_key("192.168.1.9") < pr._ip_key("192.168.1.10")


def test_build_nmap_args():
    base = SimpleNamespace(full=False, ports=None, top_ports=100, host_timeout="120s")
    args = pr.build_nmap_args(base, privileged=False)
    assert "-sV" in args and "-Pn" in args and "--top-ports 100" in args
    assert "-O" not in args                                   # no root → no -O
    assert "-O" in pr.build_nmap_args(base, privileged=True)  # root → -O
    full = SimpleNamespace(full=True, ports=None, top_ports=100, host_timeout="60s")
    assert "-p-" in pr.build_nmap_args(full, privileged=False)


# --------------------------------------------------------------------------- #
# Discovery liveness policy — the host-discovery false-positive guard
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "strong, saw_rst, rst_up, expected",
    [
        (True, False, False, (True, "strong")),    # open port / ICMP -> up
        (True, True, False, (True, "strong")),     # strong signal wins over RST
        (False, True, False, (False, "weak")),     # RST-only SUPPRESSED by default
        (False, True, True, (True, "weak")),        # RST-only included with --rst-up
        (False, False, False, (False, "none")),    # no response -> down
        (False, False, True, (False, "none")),     # --rst-up never invents liveness
    ],
)
def test_discovery_decide_policy(strong, saw_rst, rst_up, expected):
    # The crux of the false-positive fix: a bare TCP RST is NOT 'up' unless the
    # operator explicitly opts in with --rst-up.
    assert pr.DiscoveryEngine._decide(strong, saw_rst, rst_up) == expected


def test_discovery_default_suppresses_rst_only():
    # A firewall that RSTs dead addresses must not produce a 'live' host.
    up, conf = pr.DiscoveryEngine._decide(strong=False, saw_rst=True, rst_up=False)
    assert up is False and conf == "weak"


# --------------------------------------------------------------------------- #
# Report build / write
# --------------------------------------------------------------------------- #
def _sample_state():
    state = pr.SharedState(target="192.168.1.0/30", privileged=False, engine_label="nmap -sV")
    state.set_sweep_total(2)
    state.mark_swept(2)
    state.add_live_host("192.168.1.1", "tcp/80", [80])
    state.update_host_record(
        pr.HostRecord(
            ip="192.168.1.1",
            os="Linux",
            state="DONE",
            ports=[pr.PortRecord(port=80, service="http", version="nginx 1.24")],
        )
    )
    return state


def _sample_scope():
    return SimpleNamespace(n_hosts=2, has_public=False, blocked=[])


def test_build_report_structure():
    now = datetime.now(timezone.utc)
    report = pr.build_report(_sample_state(), _sample_scope(), now, now)
    assert report["tool"] == pr.APP_NAME
    assert report["author"] == pr.AUTHOR
    assert report["summary"]["live_hosts"] == 1
    assert report["summary"]["total_open_ports"] == 1
    assert report["hosts"][0]["ip"] == "192.168.1.1"
    assert report["hosts"][0]["ports"][0]["port"] == 80


def test_write_report_is_atomic_and_mode_600(tmp_path):
    now = datetime.now(timezone.utc)
    report = pr.build_report(_sample_state(), _sample_scope(), now, now)
    path = pr.write_report(report, str(tmp_path))

    assert os.path.exists(path)
    assert not os.path.exists(path + ".tmp")                 # temp file renamed away
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600      # owner-only
    assert json.load(open(path))["hosts"][0]["ip"] == "192.168.1.1"


# --------------------------------------------------------------------------- #
# Differential analysis
# --------------------------------------------------------------------------- #
def _report_with(hosts):
    return {"finished_at": "2026-01-01T00:00:00+00:00", "hosts": hosts}


def test_diff_detects_appeared_disappeared_and_port_changes():
    old = _report_with(
        [
            {
                "ip": "10.0.0.1",
                "os": "Linux",
                "ports": [
                    {"port": 22, "service": "ssh", "version": "8.9"},
                    {"port": 80, "service": "http", "version": "nginx 1.18"},
                ],
            },
            {"ip": "10.0.0.2", "os": "Windows", "ports": []},
        ]
    )
    new = _report_with(
        [
            {
                "ip": "10.0.0.1",
                "os": "Linux",
                "ports": [
                    {"port": 80, "service": "http", "version": "nginx 1.24"},
                    {"port": 443, "service": "https", "version": ""},
                ],
            },
            {"ip": "10.0.0.9", "os": "Linux", "ports": []},
        ]
    )
    diff = pr.diff_reports(old, new)

    assert diff["has_changes"] is True
    assert diff["appeared_hosts"] == ["10.0.0.9"]
    assert diff["disappeared_hosts"] == ["10.0.0.2"]

    changed = {c["ip"]: c for c in diff["changed_hosts"]}
    assert "10.0.0.1" in changed
    assert changed["10.0.0.1"]["opened_ports"] == [443]
    assert changed["10.0.0.1"]["closed_ports"] == [22]
    assert changed["10.0.0.1"]["service_changes"][0]["port"] == 80
    assert "1.18" in changed["10.0.0.1"]["service_changes"][0]["from"]
    assert "1.24" in changed["10.0.0.1"]["service_changes"][0]["to"]


def test_diff_identical_reports_are_stable():
    report = _report_with(
        [{"ip": "10.0.0.1", "os": "Linux",
          "ports": [{"port": 22, "service": "ssh", "version": "8.9"}]}]
    )
    diff = pr.diff_reports(report, report)
    assert diff["has_changes"] is False
    assert diff["appeared_hosts"] == []
    assert diff["disappeared_hosts"] == []
    assert diff["changed_hosts"] == []


def test_diff_detects_os_change():
    old = _report_with([{"ip": "10.0.0.1", "os": "Unknown", "ports": []}])
    new = _report_with([{"ip": "10.0.0.1", "os": "Windows Server 2019", "ports": []}])
    diff = pr.diff_reports(old, new)
    assert diff["changed_hosts"][0]["os_from"] == "Unknown"
    assert diff["changed_hosts"][0]["os_to"] == "Windows Server 2019"


# --------------------------------------------------------------------------- #
# load_baseline error handling (graceful, typed exceptions)
# --------------------------------------------------------------------------- #
def test_load_baseline_rejects_non_report(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"not": "a report"}')
    with pytest.raises(ValueError):
        pr.load_baseline(str(bad))


def test_load_baseline_rejects_invalid_json(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{ this is not json")
    with pytest.raises(json.JSONDecodeError):
        pr.load_baseline(str(bad))


def test_load_baseline_missing_file():
    with pytest.raises(OSError):
        pr.load_baseline("/nonexistent/path/report.json")


# --------------------------------------------------------------------------- #
# Renderers build and emit output without raising
# --------------------------------------------------------------------------- #
def _render(renderable, width=120):
    buf = io.StringIO()
    Console(file=buf, force_terminal=True, width=width, height=40).print(renderable)
    return buf.getvalue()


def test_dashboard_renders_with_content():
    out = _render(pr.render_dashboard(_sample_state().snapshot()))
    assert "RECON" in out
    assert "LIVE ASSET MATRIX" in out
    assert "192.168.1.1" in out
    assert pr.AUTHOR in out


def test_dashboard_empty_state_renders():
    out = _render(pr.render_dashboard(pr.SharedState("x", False, "y").snapshot()))
    assert "LIVE ASSET MATRIX" in out


def test_device_list_renders_with_mac_and_hostname():
    st = _sample_state()
    st.set_host_mac("192.168.1.1", "00:0f:15:58:df:43")
    st.set_host_hostname("192.168.1.1", "router.local")
    out = _render(pr.render_device_list(st.snapshot()))
    assert "NETWORK DEVICES" in out
    assert "192.168.1.1" in out
    assert "00:0f:15:58:df:43" in out
    assert "router.local" in out


def test_diff_panel_renders():
    diff = pr.diff_reports(
        _report_with([{"ip": "10.0.0.1", "os": "Linux", "ports": []}]),
        _report_with([{"ip": "10.0.0.1", "os": "Linux",
                       "ports": [{"port": 80, "service": "http", "version": ""}]}]),
    )
    assert "CONFIGURATION DRIFT" in _render(pr.render_diff_panel(diff))


# --------------------------------------------------------------------------- #
# Alternative export formats — CSV + self-contained HTML
# --------------------------------------------------------------------------- #
def _export_report():
    now = datetime.now(timezone.utc)
    report = pr.build_report(_sample_state(), _sample_scope(), now, now)
    # Enrich one host so the export has MAC/vendor/hostname to render.
    report["hosts"][0]["mac"] = "00:0f:15:58:df:43"
    report["hosts"][0]["vendor"] = "Icotera"
    report["hosts"][0]["hostname"] = "router.local"
    return report


def test_csv_rows_have_header_and_per_port_row():
    rows = pr.csv_rows(_export_report())
    assert rows[0][:3] == ["ip", "hostname", "os"]   # header
    body = rows[1:]
    assert any(r[0] == "192.168.1.1" and r[6] == "80" for r in body)  # ip + port col
    assert any("http" in r for r in body)


def test_csv_includes_hosts_with_no_open_ports():
    report = {"target": "x", "summary": {}, "hosts": [
        {"ip": "10.0.0.5", "ports": []},
    ]}
    rows = pr.csv_rows(report)
    assert len(rows) == 2                 # header + one row for the port-less host
    assert rows[1][0] == "10.0.0.5"
    assert rows[1][6] == ""               # empty port column


def test_write_csv_is_atomic_and_mode_600(tmp_path):
    path = pr.write_csv_report(_export_report(), str(tmp_path))
    assert path.endswith(".csv")
    assert not os.path.exists(path + ".tmp")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert "192.168.1.1" in open(path).read()


def test_html_report_is_self_contained_and_escapes():
    report = _export_report()
    report["hosts"][0]["hostname"] = "<script>evil</script>"
    out = pr.render_html_report(report)
    assert out.lstrip().startswith("<!doctype html>")
    assert "</html>" in out
    assert "192.168.1.1" in out
    assert "Icotera" in out
    assert "PURPLE" in out
    # User-controlled hostname must be escaped, never emitted as a live tag.
    assert "<script>evil" not in out
    assert "&lt;script&gt;evil" in out


def test_write_html_is_atomic_and_mode_600(tmp_path):
    path = pr.write_html_report(_export_report(), str(tmp_path))
    assert path.endswith(".html")
    assert not os.path.exists(path + ".tmp")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert "<!doctype html>" in open(path).read().lower()


# --------------------------------------------------------------------------- #
# IPv6 support (ScopeValidator dual-stack + NDP neighbour-cache parsing)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "target",
    ["::1", "ff02::1", "fe80::1", "fe80::1%en0", "::"],
)
def test_scope_refuses_forbidden_ipv6(target):
    with pytest.raises(pr.ScopeError):
        pr.ScopeValidator(max_hosts=4096).validate(target)


@pytest.mark.parametrize("target", ["fd00::1", "2001:db8::/120"])
def test_scope_allows_safe_ipv6(target):
    result = pr.ScopeValidator(max_hosts=4096).validate(target)
    assert result.n_hosts >= 1


def test_scope_refuses_oversized_ipv6_prefix():
    with pytest.raises(pr.ScopeError):
        pr.ScopeValidator(max_hosts=4096).validate("2001:db8::/64")


def test_read_ndp_table_macos(monkeypatch):
    sample = (
        "Neighbor                                Linklayer Address  Netif Expire    St Flgs Prbs\n"
        "fe80::1%lo0                             (incomplete)         lo0 permanent R\n"
        "fe80::c68:f607:56bb:45%en0             7e:79:7:fd:3:34      en0 20h S\n"
        "fe80::4449:5fff:feb6:cb60%awdl0         46:49:5f:b6:cb:60  awdl0 permanent R\n"
    )

    class _Result:
        stdout = sample

    monkeypatch.setattr(pr.subprocess, "run", lambda *a, **k: _Result())
    table = pr._read_ndp_table()
    # MAC is normalized (zero-padded) and correlated to its IPv6 address.
    assert table.get("7e:79:07:fd:03:34") == ["fe80::c68:f607:56bb:45"]
    # Non-physical interfaces (awdl) and incomplete (lo) entries are filtered.
    assert "46:49:5f:b6:cb:60" not in table
    assert all("lo0" not in v for vs in table.values() for v in vs)


def test_read_ndp_table_linux(monkeypatch):
    # macOS `ndp` returns nothing -> Linux `ip -6 neigh` fallback kicks in.
    calls = {"n": 0}
    linux = "2001:db8::5 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\nfe80::9 dev awdl0 lladdr 11:22:33:44:55:66 STALE\n"

    class _R:
        def __init__(self, out):
            self.stdout = out

    def fake_run(cmd, *a, **k):
        calls["n"] += 1
        return _R("" if cmd[:1] == ["ndp"] else linux)

    monkeypatch.setattr(pr.subprocess, "run", fake_run)
    table = pr._read_ndp_table()
    assert table.get("aa:bb:cc:dd:ee:ff") == ["2001:db8::5"]
    assert "11:22:33:44:55:66" not in table  # awdl0 filtered


# --------------------------------------------------------------------------- #
# Property-based fuzzing — the CLI primitives must never crash on hostile input
# (MACs/vendors come straight off the wire; targets come from the operator).
# --------------------------------------------------------------------------- #
@given(st.text(alphabet=string.printable, max_size=40))
def test_fuzz_normalise_mac(s):
    assert isinstance(pr._normalise_mac(s), str)


@given(st.text(max_size=40))
def test_fuzz_is_host_mac(s):
    assert isinstance(pr._is_host_mac(s), bool)


@given(st.text(max_size=40))
def test_fuzz_mac_vendor(s):
    out = pr._mac_vendor(s, {})
    assert out is None or isinstance(out, str)


@given(st.text(alphabet=string.printable, max_size=48))
def test_fuzz_scope_validate_only_scopeerror(s):
    # validate() either returns a vetted namespace or raises *ScopeError* —
    # never any other exception, regardless of the input string.
    try:
        pr.ScopeValidator(max_hosts=4096).validate(s)
    except pr.ScopeError:
        pass


@given(st.lists(st.text(max_size=20), max_size=6))
def test_fuzz_proxy_macs(values):
    ip_to_mac = {f"10.0.0.{i}": v for i, v in enumerate(values)}
    assert isinstance(pr._proxy_macs(ip_to_mac, 2), set)
