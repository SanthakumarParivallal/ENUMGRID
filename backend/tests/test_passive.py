"""
test_passive.py — the passive-discovery aggregation core (no scapy, no root).

Covers protocol classification, host accumulation, snapshot shape/ordering, and
the honest "unavailable" paths (no scapy, bad interface). The scapy capture
itself is integration-only; the logic that turns packets into an inventory is
what's verified here.
"""

from __future__ import annotations

import passive


# --- protocol classification ----------------------------------------------- #
def test_method_for_ports_named_protocols():
    assert passive.method_for_ports(5353, 5353) == "mDNS"
    assert passive.method_for_ports(0, 5355) == "LLMNR"
    assert passive.method_for_ports(137, 137) == "NBNS"
    assert passive.method_for_ports(68, 67) == "DHCP"


def test_method_for_ports_unknown_is_none():
    assert passive.method_for_ports(12345, 443) is None
    assert passive.method_for_ports(None, "x") is None  # robust to junk


# --- validation helpers ----------------------------------------------------- #
def test_valid_ip_and_iface():
    assert passive._valid_ip("192.168.0.1") is True
    assert passive._valid_ip("nope") is False
    assert passive._valid_iface(None) is True          # auto-select
    assert passive._valid_iface("en0") is True
    assert passive._valid_iface("eth0; rm -rf /") is False


def test_norm_mac():
    assert passive._norm_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"
    assert passive._norm_mac("not-a-mac") is None
    assert passive._norm_mac(None) is None


# --- accumulation ----------------------------------------------------------- #
def test_observe_accumulates_methods_mac_and_counts():
    m = passive.PassiveMonitor()
    m.observe("192.168.0.5", mac="aa:bb:cc:dd:ee:ff", method="ARP", now="t1")
    m.observe("192.168.0.5", method="mDNS", hostname="printer.local", now="t2")
    snap = m.snapshot()
    assert len(snap) == 1
    host = snap[0]
    assert host["ip"] == "192.168.0.5"
    assert host["mac"] == "aa:bb:cc:dd:ee:ff"
    assert host["methods"] == ["ARP", "mDNS"]          # sorted, deduped union
    assert host["hostname"] == "printer.local"
    assert host["packets"] == 2
    assert host["last_seen"] == "t2"                   # most recent wins


def test_observe_ignores_invalid_ip():
    m = passive.PassiveMonitor()
    m.observe("garbage", method="ARP")
    m.observe(None, method="ARP")
    assert m.snapshot() == []


def test_snapshot_is_ip_sorted():
    m = passive.PassiveMonitor()
    for ip in ("192.168.0.20", "192.168.0.3", "192.168.0.100"):
        m.observe(ip, method="ARP", now="t")
    order = [h["ip"] for h in m.snapshot()]
    assert order == ["192.168.0.3", "192.168.0.20", "192.168.0.100"]  # numeric, not lexical


# --- honest unavailable paths ---------------------------------------------- #
def test_discover_passive_unavailable_without_scapy(monkeypatch):
    monkeypatch.setattr(passive, "_HAVE_SCAPY", False)
    res = passive.discover_passive(5)
    assert res["available"] is False
    assert "scapy" in res["reason"].lower()
    assert res["hosts"] == [] and res["count"] == 0


def test_discover_passive_rejects_bad_interface(monkeypatch):
    # Even with scapy "present", a malformed iface is refused before any capture.
    monkeypatch.setattr(passive, "_HAVE_SCAPY", True)
    res = passive.discover_passive(5, iface="en0; evil")
    assert res["available"] is False
    assert "interface" in res["reason"].lower()


def test_discover_passive_clamps_seconds(monkeypatch):
    # No scapy → returns early, but the clamp still must not raise on huge input.
    monkeypatch.setattr(passive, "_HAVE_SCAPY", False)
    assert passive.discover_passive(10_000)["available"] is False
    assert passive.discover_passive(-4)["available"] is False


def test_discover_passive_survives_scapy_permission_exception(monkeypatch):
    # scapy raises its own Scapy_Exception (NOT OSError) when it can't open /dev/bpf.
    # That must degrade to an honest "needs root", never crash the caller.
    monkeypatch.setattr(passive, "_HAVE_SCAPY", True)

    def boom(*_a, **_k):
        raise RuntimeError("Permission denied: could not open /dev/bpf0. Run as root (sudo)")

    monkeypatch.setattr(passive, "sniff", boom, raising=False)
    res = passive.discover_passive(5)
    assert res["available"] is False
    assert "root" in res["reason"].lower() or "bpf" in res["reason"].lower()
    assert res["hosts"] == [] and res["count"] == 0


def test_discover_passive_maps_generic_capture_failure(monkeypatch):
    # A non-permission capture failure keeps its message (truncated), still graceful.
    monkeypatch.setattr(passive, "_HAVE_SCAPY", True)

    def boom(*_a, **_k):
        raise RuntimeError("no such device eth9")

    monkeypatch.setattr(passive, "sniff", boom, raising=False)
    res = passive.discover_passive(5)
    assert res["available"] is False
    assert "device" in res["reason"].lower()


# --- packet handling (real scapy packets — parsing only, no capture) -------- #
from scapy.all import ARP, BOOTP, DHCP, IP, UDP, Ether  # noqa: E402


def test_ip_key_tolerates_bad_ip():
    assert passive._ip_key("not-an-ip") == (1, 0, 0)


def test_handle_packet_arp_records_sender():
    m = passive.PassiveMonitor()
    passive._handle_packet(m, Ether(src="aa:bb:cc:dd:ee:ff") / ARP(
        op=1, psrc="10.0.0.7", hwsrc="aa:bb:cc:dd:ee:ff"))
    snap = m.snapshot()
    assert snap and snap[0]["ip"] == "10.0.0.7" and snap[0]["methods"] == ["ARP"]
    assert snap[0]["mac"] == "aa:bb:cc:dd:ee:ff"


def test_handle_packet_udp_mdns_and_dhcp_hostname():
    m = passive.PassiveMonitor()
    passive._handle_packet(m, Ether() / IP(src="10.0.0.8") / UDP(sport=5353, dport=5353))
    passive._handle_packet(m, Ether(src="11:22:33:44:55:66") / IP(src="10.0.0.9")
                           / UDP(sport=68, dport=67) / BOOTP()
                           / DHCP(options=[("message-type", "request"), ("hostname", b"my-pc"), "end"]))
    by_ip = {h["ip"]: h for h in m.snapshot()}
    assert by_ip["10.0.0.8"]["methods"] == ["mDNS"]
    assert by_ip["10.0.0.9"]["methods"] == ["DHCP"] and by_ip["10.0.0.9"]["hostname"] == "my-pc"


def test_handle_packet_malformed_is_swallowed():
    m = passive.PassiveMonitor()
    passive._handle_packet(m, object())        # not a scapy packet → caught, no crash
    assert m.snapshot() == []


def test_dhcp_hostname_direct_and_missing_layer():
    pkt = Ether() / IP() / UDP() / BOOTP() / DHCP(options=[("hostname", "plain-str"), "end"])
    assert passive._dhcp_hostname(pkt) == "plain-str"
    assert passive._dhcp_hostname(Ether() / IP()) is None   # no DHCP layer → None


def test_discover_passive_permission_error(monkeypatch):
    monkeypatch.setattr(passive, "_HAVE_SCAPY", True)

    def boom(*_a, **_k):
        raise PermissionError("cannot open bpf")

    monkeypatch.setattr(passive, "sniff", boom, raising=False)
    res = passive.discover_passive(5)
    assert res["available"] is False and "root" in res["reason"].lower()


def test_discover_passive_success_returns_hosts(monkeypatch):
    monkeypatch.setattr(passive, "_HAVE_SCAPY", True)
    arp = Ether() / ARP(op=2, psrc="10.0.0.20", hwsrc="aa:bb:cc:dd:ee:01")

    def fake_sniff(prn=None, **_k):
        prn(arp)                                # feed one observed packet, then "timeout"

    monkeypatch.setattr(passive, "sniff", fake_sniff, raising=False)
    res = passive.discover_passive(3)
    assert res["available"] is True and res["count"] == 1
    assert res["hosts"][0]["ip"] == "10.0.0.20"


def test_main_prints_json_and_exit_codes(capsys, monkeypatch):
    monkeypatch.setattr(passive, "discover_passive",
                        lambda s, i: {"available": True, "reason": None, "seconds": s, "hosts": [], "count": 0})
    assert passive._main(["--seconds", "5"]) == 0
    assert '"available": true' in capsys.readouterr().out

    monkeypatch.setattr(passive, "discover_passive",
                        lambda s, i: {"available": False, "reason": "no scapy", "seconds": 0, "hosts": [], "count": 0})
    assert passive._main([]) == 1
