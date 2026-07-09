"""Tests for the discover-mode helpers (port probe + device-type sharpening)."""

from __future__ import annotations

import socket

import discovery as d
from fingerprint import guess_device_type
from models import PortState, Protocol


def test_make_port_labels_service_and_state():
    p = d._make_port(443)
    assert p.port == 443
    assert p.service == "https"
    assert p.protocol == Protocol.TCP
    assert p.state == PortState.OPEN
    assert p.critical is False


def test_make_port_flags_critical_ports():
    # 3389 (RDP), 445 (SMB), 6379 (Redis) are inherently risky on a LAN.
    for port in (3389, 445, 6379, 23):
        assert d._make_port(port).critical is True
    # An ordinary web port is not flagged critical.
    assert d._make_port(8080).critical is False


def test_make_port_unknown_service_label():
    # A port with no curated label still produces a valid record.
    p = d._make_port(12345)
    assert p.port == 12345
    assert p.service == "unknown"


def test_probe_pair_closed_port_is_false():
    # A connect to a port nothing listens on must not be reported open. We grab a
    # free port from the OS, close it, then probe it — guaranteed closed/refused.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    free_port = s.getsockname()[1]
    s.close()
    assert d._probe_pair(("127.0.0.1", free_port)) is False


def test_probe_pair_open_port_is_true():
    # A real listening socket must be reported open (a completed handshake).
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        assert d._probe_pair(("127.0.0.1", port)) is True
    finally:
        srv.close()


def test_open_ports_drive_device_type():
    # The wiring that the discovery step relies on: open ports are the strongest
    # device-type signal, so they win over a generic vendor hint.
    services = [d._make_port(p).service for p in (53, 80)]
    assert guess_device_type(ports=[53, 80], services=services) == "Router / Gateway"
    assert guess_device_type(ports=[9100], services=["jetdirect"]) == "Printer"


# --- pure helpers ----------------------------------------------------------- #
def test_ensure_on_path_inserts_once():
    path = ["/x"]
    d._ensure_on_path("/root", path)
    assert path == ["/root", "/x"]
    d._ensure_on_path("/root", path)
    assert path == ["/root", "/x"]                       # already present → no dup


def test_expand_target_variants():
    assert d.expand_target("10.0.0.5") == ["10.0.0.5"]                    # single host
    assert d.expand_target("10.0.0.0/31") == ["10.0.0.0", "10.0.0.1"]     # /31 (both addrs)
    assert d.expand_target("10.0.0.0/30") == ["10.0.0.1", "10.0.0.2"]     # usable hosts
    assert d.expand_target("bad, ::1, 10.0.0.1") == ["10.0.0.1"]          # junk + IPv6 skipped
    assert len(d.expand_target("10.0.0.0/24", max_hosts=5)) == 5          # capped


def test_ip_key_and_reverse_dns(monkeypatch):
    assert d._ip_key("10.0.0.5") == (10, 0, 0, 5)
    assert d._ip_key("bad") == (0,)
    monkeypatch.setattr(d.socket, "gethostbyaddr", lambda ip: ("host.local", [], []))
    assert d._reverse_dns("10.0.0.1") == ("10.0.0.1", "host.local")
    monkeypatch.setattr(d.socket, "gethostbyaddr", lambda ip: (_ for _ in ()).throw(OSError()))
    assert d._reverse_dns("10.0.0.1") == ("10.0.0.1", None)


def test_oui_table_caches_and_handles_missing_path(monkeypatch):
    d._OUI_TABLE = None
    monkeypatch.setattr(d.pr, "resolve_oui_path", lambda x: "/some/path")
    monkeypatch.setattr(d.pr, "load_oui_table", lambda p: {"AABBCC": "Acme"})
    assert d._oui_table() == {"AABBCC": "Acme"}
    monkeypatch.setattr(d.pr, "load_oui_table", lambda p: {"z": "y"})
    assert d._oui_table() == {"AABBCC": "Acme"}           # cached, not reloaded
    d._OUI_TABLE = None
    monkeypatch.setattr(d.pr, "resolve_oui_path", lambda x: None)
    assert d._oui_table() == {}                           # no OUI file → empty table
    d._OUI_TABLE = None


# --- run_discovery pipeline (every signal source stubbed; no network) ------- #
import asyncio  # noqa: E402


def _install_stubs(monkeypatch, *, is_alive=None, arp=None, proxy=None, ndp=None,
                   probe_open=(), nbns=None, snmp_info=None, ttl="", mdns=None, ssdp=None):
    monkeypatch.setattr(d, "_oui_table", lambda: {})

    class _Engine:
        def __init__(self, **kw): pass
        def is_alive(self, ip): return (is_alive or {}).get(ip, (False, "", [], 0))

    monkeypatch.setattr(d.pr, "DiscoveryEngine", _Engine)
    monkeypatch.setattr(d.pr, "_read_arp_table", lambda: dict(arp or {}))
    monkeypatch.setattr(d.pr, "_proxy_macs", lambda a, n: set(proxy or ()))
    monkeypatch.setattr(d.pr, "_mac_vendor", lambda mac, oui: "VendorX")
    monkeypatch.setattr(d.pr, "_read_ndp_table", lambda: dict(ndp or {}))
    monkeypatch.setattr(d, "_probe_pair", lambda pair: pair in set(probe_open))
    monkeypatch.setattr(d, "_reverse_dns", lambda ip: (ip, None))          # default: no DNS name
    monkeypatch.setattr(d, "nbns_names", lambda ips, t=1.0: dict(nbns or {}))
    monkeypatch.setattr(d.snmp, "sysinfo", lambda ip, timeout=1.0: (snmp_info or {}).get(ip, {}))
    monkeypatch.setattr(d, "os_hint", lambda ip: ttl)
    monkeypatch.setattr(d, "discover_mdns", lambda secs: dict(mdns or {}))
    monkeypatch.setattr(d, "discover_ssdp", lambda secs: dict(ssdp or {}))


def _run(target):
    async def _go():
        return [s async for s in d.run_discovery(target, "sid")]
    return asyncio.run(_go())


def test_run_discovery_fuses_all_signals(monkeypatch):
    _install_stubs(
        monkeypatch,
        is_alive={"10.0.0.1": (True, "ping", [80], 7), "10.0.0.2": (True, "ping", [], 5)},
        arp={"10.0.0.1": "aa:bb:cc:dd:ee:01"},
        ndp={"aa:bb:cc:dd:ee:01": ["fe80::1"]},
        probe_open=[("10.0.0.2", 445)],
        nbns={"10.0.0.2": "WINPC"},
        snmp_info={},          # .1 stays unnamed → the SNMP block runs (and finds nothing)
        ttl="Linux / macOS / Unix",
    )
    final = _run("10.0.0.0/30")[-1]
    assert final.phase == d.ScanPhase.COMPLETE and final.progress == 100
    by_ip = {h.ip: h for h in final.hosts}
    assert set(by_ip) == {"10.0.0.1", "10.0.0.2"}
    assert by_ip["10.0.0.1"].mac == "aa:bb:cc:dd:ee:01" and by_ip["10.0.0.1"].vendor == "VendorX"
    assert by_ip["10.0.0.1"].ipv6 == ["fe80::1"]                # NDP correlation by MAC
    assert 80 in [p.port for p in by_ip["10.0.0.1"].ports]      # seed port from is_alive
    assert 445 in [p.port for p in by_ip["10.0.0.2"].ports]     # port-probe hit
    assert by_ip["10.0.0.2"].hostname == "WINPC"                # NBNS name


def test_run_discovery_proxy_arp_skipped(monkeypatch):
    # A MAC flagged as proxy-ARP (a router answering for many IPs) is not a device.
    _install_stubs(
        monkeypatch,
        is_alive={"10.0.0.1": (False, "", [], 0)},
        arp={"10.0.0.2": "ff:ff:ff:00:00:01"},          # in-scope for /30, but proxied
        proxy={"ff:ff:ff:00:00:01"},
    )
    final = _run("10.0.0.0/30")[-1]
    assert all(h.ip != "10.0.0.2" for h in final.hosts)         # proxied entry dropped


def test_run_discovery_names_from_dns_and_snmp(monkeypatch):
    _install_stubs(
        monkeypatch,
        is_alive={"10.0.0.1": (True, "ping", [], 7), "10.0.0.2": (True, "ping", [], 7)},
        snmp_info={"10.0.0.2": {"name": "switch01", "descr": "Cisco IOS Software"}},
    )
    # .1 resolves via reverse-DNS; .2 has no DNS/NBNS name → SNMP names it.
    monkeypatch.setattr(d, "_reverse_dns",
                        lambda ip: (ip, "host1.local") if ip == "10.0.0.1" else (ip, None))
    by_ip = {h.ip: h for h in _run("10.0.0.0/30")[-1].hosts}
    assert by_ip["10.0.0.1"].hostname == "host1.local"          # reverse DNS
    assert by_ip["10.0.0.2"].hostname == "switch01"             # SNMP sysName
    assert by_ip["10.0.0.2"].os.startswith("Cisco")            # SNMP sysDescr → OS


def test_probe_pair_socket_error_is_false(monkeypatch):
    def _boom(*a, **k):
        raise OSError("no socket")

    monkeypatch.setattr(d.socket, "socket", _boom)
    assert d._probe_pair(("10.0.0.1", 80)) is False


def test_run_discovery_mdns_and_ssdp_enrichment(monkeypatch):
    _install_stubs(
        monkeypatch,
        is_alive={"10.0.0.1": (True, "ping", [], 7)},
        mdns={"10.0.0.1": {"hostname": "TV", "device_type": "Media / TV", "os": "tvOS"},
              "10.0.0.2": {"hostname": "Printer", "device_type": "Printer", "os": ""},  # new host
              "10.0.0.99": {"hostname": "outside", "device_type": "x"}},                # out of scope
        ssdp={"10.0.0.3": {"hostname": "Router", "manufacturer": "Acme",
                           "device_type": "Router / Gateway", "os": "Linux"},            # new host
              "10.0.0.99": {"hostname": "outside"}},                                     # out of scope
    )
    by_ip = {h.ip: h for h in _run("10.0.0.0/29")[-1].hosts}
    assert by_ip["10.0.0.1"].device_type == "Media / TV" and by_ip["10.0.0.1"].os == "tvOS"
    assert "10.0.0.2" in by_ip and by_ip["10.0.0.2"].device_type == "Printer"    # created via mDNS
    assert "10.0.0.3" in by_ip and by_ip["10.0.0.3"].vendor == "Acme"            # created via SSDP
    assert "10.0.0.99" not in by_ip                                              # out-of-scope skipped


def test_run_discovery_survives_enricher_exceptions(monkeypatch):
    _install_stubs(monkeypatch, is_alive={"10.0.0.1": (True, "ping", [80], 7)},
                   arp={"10.0.0.1": "aa:bb:cc:dd:ee:01"})

    def _boom(*a, **k):
        raise RuntimeError("feed down")

    monkeypatch.setattr(d, "nbns_names", _boom)
    monkeypatch.setattr(d.pr, "_read_ndp_table", _boom)
    monkeypatch.setattr(d, "discover_mdns", _boom)
    monkeypatch.setattr(d, "discover_ssdp", _boom)
    monkeypatch.setattr(d.snmp, "sysinfo", lambda i, timeout=1.0: (_ for _ in ()).throw(RuntimeError()))
    final = _run("10.0.0.0/30")[-1]
    assert final.phase == d.ScanPhase.COMPLETE                  # every failure swallowed


def test_run_discovery_port_probe_disabled(monkeypatch):
    _install_stubs(monkeypatch, is_alive={"10.0.0.1": (True, "ping", [80], 7)})
    monkeypatch.setattr(d, "PORT_PROBE", False)
    final = _run("10.0.0.0/30")[-1]
    assert final.phase == d.ScanPhase.COMPLETE
    assert next(h for h in final.hosts if h.ip == "10.0.0.1").ports == []   # probe skipped
