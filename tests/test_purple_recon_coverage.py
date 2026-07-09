"""Full-coverage companion suite for ``purple_recon.py``.

The curated :mod:`tests.test_purple_recon` suite proves the security-critical
and pure-logic behaviour.  This file completes the picture: it drives the
threaded engines, the orchestrator, both run-loops, the CLI ``main``/``cli``
entrypoints, and every defensive branch — all with the network, subprocess and
nmap boundaries mocked, so the suite stays deterministic and offline while
holding the whole module at 100 % line coverage.

No real packets, pings, ARP reads, DNS lookups or nmap invocations happen here.
"""

from __future__ import annotations

import io
import ipaddress
import json
import os
import socket
import subprocess
import threading
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from rich.console import Console

import purple_recon as pr


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #
def _render(renderable, width=120) -> str:
    buf = io.StringIO()
    Console(file=buf, force_terminal=True, width=width, height=40).print(renderable)
    return buf.getvalue()


def _sink_console() -> Console:
    """A non-interactive console that swallows output (is_terminal is False)."""
    return Console(file=io.StringIO(), force_terminal=False)


def _term_console() -> Console:
    """A console that reports as a TTY, writing to a buffer."""
    return Console(file=io.StringIO(), force_terminal=True)


# --------------------------------------------------------------------------- #
# SharedState — the locked mutation/read API the cockpit renders from
# --------------------------------------------------------------------------- #
def test_shared_state_full_mutation_and_read_api():
    st = pr.SharedState(target="10.0.0.0/30", privileged=True, engine_label="nmap -sV")

    st.set_phase("PHASE 1")
    st.set_sweep_total(4)
    st.mark_swept(2)
    st.set_enum_total(3)
    st.mark_enum_done()
    st.push_log("hello")

    st.add_live_host("10.0.0.1", "icmp", [80, 22], "strong")
    assert st.live_count() == 1
    assert st.live_ips() == ["10.0.0.1"]
    assert st.seed_ports_of("10.0.0.1") == [22, 80]
    assert st.seed_ports_of("10.0.0.99") == []      # unknown host -> empty

    # add_live_host is idempotent — a second call for the same IP is a no-op.
    st.add_live_host("10.0.0.1", "arp", [443], "weak")
    assert st.seed_ports_of("10.0.0.1") == [22, 80]

    st.set_host_state("10.0.0.1", "SCANNING")
    st.set_host_state("10.0.0.1", "ERROR", error="boom")
    st.set_host_state("10.0.0.99", "DONE")          # unknown host -> ignored
    st.set_host_mac("10.0.0.1", "aa:bb:cc:dd:ee:ff")
    st.set_host_mac("10.0.0.1", "11:22:33:44:55:66")  # already set -> unchanged
    st.set_host_mac("10.0.0.99", "aa:bb:cc:dd:ee:ff")  # unknown -> ignored
    st.set_host_hostname("10.0.0.1", "router.local")
    st.set_host_hostname("10.0.0.1", "other")       # already set -> unchanged
    st.set_host_hostname("10.0.0.99", "x")          # unknown -> ignored
    st.set_host_vendor("10.0.0.1", "Cisco")
    st.set_host_vendor("10.0.0.1", "Other")         # already set -> unchanged
    st.set_host_vendor("10.0.0.1", None)            # falsy -> ignored
    st.set_host_vendor("10.0.0.99", "X")            # unknown -> ignored

    host = st.hosts()[0]
    assert host.mac == "aa:bb:cc:dd:ee:ff"
    assert host.hostname == "router.local"
    assert host.vendor == "Cisco"
    assert host.state == "ERROR"
    assert host.error == "boom"

    snap = st.snapshot()
    assert snap.sweep_total == 4 and snap.sweep_done == 2
    assert snap.enum_total == 3 and snap.enum_done == 1
    assert snap.live == 1 and snap.phase == "PHASE 1"
    assert any("hello" in line for line in snap.log)

    assert st.is_aborted() is False
    st.abort()
    assert st.is_aborted() is True
    assert st.is_done() is False
    st.finish()
    assert st.is_done() is True


def test_update_host_record_creates_when_absent_and_merges_when_present():
    st = pr.SharedState("x", False, "y")

    # Absent -> the record is inserted verbatim.
    fresh = pr.HostRecord(ip="10.0.0.5", os="Linux", state="DONE")
    st.update_host_record(fresh)
    assert st.hosts()[0].os == "Linux"

    # Present -> enriched fields merge, state becomes DONE, open_count recomputed.
    st.add_live_host("10.0.0.6", "icmp", [80])
    st.set_host_hostname("10.0.0.6", "keepme")
    st.update_host_record(
        pr.HostRecord(
            ip="10.0.0.6",
            hostname=None,                       # None must not clobber existing
            os="Windows",
            ports=[pr.PortRecord(port=80, service="http"),
                   pr.PortRecord(port=443, service="https")],
        )
    )
    merged = {h.ip: h for h in st.hosts()}["10.0.0.6"]
    assert merged.hostname == "keepme"           # preserved
    assert merged.os == "Windows"
    assert merged.open_count == 2
    assert merged.state == "DONE"


# --------------------------------------------------------------------------- #
# ScopeValidator — the two defensive branches unreachable via real IP input
# --------------------------------------------------------------------------- #
def test_classify_limited_broadcast_explicit_guard(monkeypatch):
    """255.255.255.255 is normally caught by ``is_reserved``; the explicit
    all-ones guard is exercised by suppressing that classification."""
    monkeypatch.setattr(
        ipaddress.IPv4Address, "is_reserved", property(lambda self: False)
    )
    addr = ipaddress.IPv4Address("255.255.255.255")
    assert "limited broadcast" in pr.ScopeValidator._classify(addr)


def test_validate_records_forbidden_host_surfacing_mid_expansion(monkeypatch):
    """A forbidden address that only appears while expanding a clean network is
    recorded in ``blocked`` (not scanned) — the per-host guard inside the loop."""
    def fake_classify(addr):
        return "test-forbidden" if str(addr) == "192.168.1.2" else None

    monkeypatch.setattr(pr.ScopeValidator, "_classify", staticmethod(fake_classify))
    scope = pr.ScopeValidator().validate("192.168.1.0/30")
    assert "192.168.1.2" not in scope.hosts
    assert "192.168.1.1" in scope.hosts
    assert ("192.168.1.2", "test-forbidden") in scope.blocked


def test_validate_raises_when_network_yields_no_hosts(monkeypatch):
    """The final 'no scannable hosts' guard: a clean network that expands to an
    empty host set (and blocks nothing) must still be refused, not returned."""
    class _EmptyNet:
        num_addresses = 4
        prefixlen = 30
        network_address = ipaddress.IPv4Address("192.168.1.0")

        def hosts(self):
            return iter(())

    monkeypatch.setattr(
        pr.ScopeValidator, "_parse_entry", staticmethod(lambda entry: _EmptyNet())
    )
    with pytest.raises(pr.ScopeError, match="No scannable hosts"):
        pr.ScopeValidator().validate("192.168.1.0/30")


# --------------------------------------------------------------------------- #
# DiscoveryEngine
# --------------------------------------------------------------------------- #
def _engine(**kw) -> pr.DiscoveryEngine:
    defaults = dict(timeout=0.1, workers=4, use_ping=False, rst_up=False,
                    ping_timeout=1.0, ping_attempts=1, use_arp=False)
    defaults.update(kw)
    return pr.DiscoveryEngine(**defaults)


def test_discovery_init_clamps_and_gates_ping(monkeypatch):
    monkeypatch.setattr(pr, "_ping_available", lambda: True)
    eng = pr.DiscoveryEngine(timeout=0.0, workers=0, use_ping=True,
                             ping_timeout=0.0, ping_attempts=0)
    assert eng.timeout == 0.05          # floored
    assert eng.workers == 1             # floored
    assert eng.use_ping is True         # ping available
    assert eng.ping_timeout == 1.0      # floored
    assert eng.ping_attempts == 1       # floored
    # use_ping requested but no ping binary -> disabled.
    monkeypatch.setattr(pr, "_ping_available", lambda: False)
    assert _engine(use_ping=True).use_ping is False


def test_is_alive_icmp_first(monkeypatch):
    eng = _engine(use_ping=True)
    monkeypatch.setattr(eng, "_ping", lambda ip: True)
    assert eng.is_alive("10.0.0.1") == (True, "icmp", [], "strong")


class _FakeSock:
    """Context-manager socket stub whose connect_ex return is scripted per port."""

    def __init__(self, rc_by_port, recv=b""):
        self._rc_by_port = rc_by_port
        self._recv = recv
        self._port = None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def settimeout(self, _):
        pass

    def connect_ex(self, addr):
        self._port = addr[1]
        rc = self._rc_by_port.get(addr[1], 1)
        if isinstance(rc, Exception):
            raise rc
        return rc

    def recv(self, _n):
        return self._recv


def _patch_socket(monkeypatch, rc_by_port, recv=b""):
    monkeypatch.setattr(
        pr.socket, "socket", lambda *a, **k: _FakeSock(rc_by_port, recv)
    )


def test_is_alive_tcp_open_is_strong(monkeypatch):
    eng = _engine(use_ping=False)
    _patch_socket(monkeypatch, {80: 0})            # port 80 handshake completes
    up, via, ports, conf = eng.is_alive("10.0.0.2")
    assert up is True and conf == "strong"
    assert via == "tcp/80" and ports == [80]


def test_is_alive_rst_only_suppressed_by_default(monkeypatch):
    import errno
    eng = _engine(use_ping=False, rst_up=False)
    _patch_socket(monkeypatch, {p: errno.ECONNREFUSED for p in pr.SWEEP_PORTS})
    up, via, ports, conf = eng.is_alive("10.0.0.3")
    assert up is False and conf == "weak" and ports == []


def test_is_alive_rst_only_included_with_rst_up(monkeypatch):
    import errno
    eng = _engine(use_ping=False, rst_up=True)
    _patch_socket(monkeypatch, {p: errno.ECONNREFUSED for p in pr.SWEEP_PORTS})
    up, via, ports, conf = eng.is_alive("10.0.0.3")
    assert up is True and conf == "weak"
    assert via == "tcp-rst (unconfirmed)"


def test_is_alive_socket_oserror_is_nonfatal(monkeypatch):
    eng = _engine(use_ping=False)
    _patch_socket(monkeypatch, {p: OSError("no route") for p in pr.SWEEP_PORTS})
    assert eng.is_alive("10.0.0.4") == (False, "", [], "none")


def test_ping_success_first_attempt(monkeypatch):
    eng = _engine(use_ping=True, ping_attempts=2)
    monkeypatch.setattr(
        pr.subprocess, "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 0),
    )
    assert eng._ping("10.0.0.5") is True


def test_ping_retries_then_fails(monkeypatch):
    eng = _engine(use_ping=True, ping_attempts=2)
    calls = {"n": 0}

    def fake_run(*a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            raise subprocess.TimeoutExpired(cmd="ping", timeout=1)
        return subprocess.CompletedProcess(a, 1)   # non-zero -> not up

    monkeypatch.setattr(pr.subprocess, "run", fake_run)
    assert eng._ping("10.0.0.6") is False
    assert calls["n"] == 2                          # both attempts consumed


def test_ping_oserror_is_swallowed(monkeypatch):
    eng = _engine(use_ping=True, ping_attempts=1)
    monkeypatch.setattr(
        pr.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(OSError())
    )
    assert eng._ping("10.0.0.7") is False


def test_sweep_records_live_and_logs_suppressed_rst(monkeypatch):
    eng = _engine(use_ping=False, use_arp=False, rst_up=False)
    outcomes = {
        "10.0.0.1": (True, "tcp/80", [80], "strong"),
        "10.0.0.2": (False, "", [], "weak"),        # suppressed RST-only host
    }
    monkeypatch.setattr(eng, "is_alive", lambda ip: outcomes[ip])
    st = pr.SharedState("x", False, "y")
    eng.sweep(["10.0.0.1", "10.0.0.2"], st)
    assert st.live_ips() == ["10.0.0.1"]
    assert any("Suppressed 1 RST-only" in line for line in st.snapshot().log)


def test_sweep_worker_exception_is_isolated(monkeypatch):
    eng = _engine(use_ping=False, use_arp=False)

    def boom(ip):
        raise RuntimeError("probe crashed")

    monkeypatch.setattr(eng, "is_alive", boom)
    st = pr.SharedState("x", False, "y")
    eng.sweep(["10.0.0.1"], st)                     # must not raise
    assert st.live_count() == 0
    assert st.snapshot().sweep_done == 1


def test_sweep_arp_pass_adds_icmp_silent_hosts(monkeypatch):
    eng = _engine(use_ping=False, use_arp=True, oui_table={})
    monkeypatch.setattr(eng, "is_alive", lambda ip: (False, "", [], "none"))
    monkeypatch.setattr(
        pr, "_read_arp_table",
        lambda: {"10.0.0.9": "aa:bb:cc:dd:ee:ff", "10.0.0.8": "aa:bb:cc:dd:ee:01"},
    )
    monkeypatch.setattr(pr, "_proxy_macs", lambda scoped, thr: set())
    monkeypatch.setattr(pr, "_mac_vendor", lambda mac, table: "Cisco")
    st = pr.SharedState("x", False, "y")
    eng.sweep(["10.0.0.9", "10.0.0.8"], st)
    assert set(st.live_ips()) == {"10.0.0.8", "10.0.0.9"}
    assert any("ARP discovery added" in line for line in st.snapshot().log)
    host = {h.ip: h for h in st.hosts()}["10.0.0.9"]
    assert host.mac == "aa:bb:cc:dd:ee:ff" and host.vendor == "Cisco"


def test_sweep_arp_proxy_detected_and_ignored(monkeypatch):
    eng = _engine(use_ping=False, use_arp=True)
    monkeypatch.setattr(eng, "is_alive", lambda ip: (False, "", [], "none"))
    scoped = {"10.0.0.1": "de:ad:be:ef:00:01", "10.0.0.2": "de:ad:be:ef:00:01"}
    monkeypatch.setattr(pr, "_read_arp_table", lambda: scoped)
    monkeypatch.setattr(pr, "_proxy_macs", lambda s, thr: {"de:ad:be:ef:00:01"})
    st = pr.SharedState("x", False, "y")
    eng.sweep(["10.0.0.1", "10.0.0.2"], st)
    assert st.live_count() == 0                      # proxy MAC hosts skipped
    assert any("Proxy-ARP detected" in line for line in st.snapshot().log)


def test_sweep_aborted_skips_arp(monkeypatch):
    eng = _engine(use_ping=False, use_arp=True)
    monkeypatch.setattr(eng, "is_alive", lambda ip: (True, "icmp", [], "strong"))

    def _explode():
        raise AssertionError("ARP must not run once aborted")

    monkeypatch.setattr(pr, "_read_arp_table", _explode)
    st = pr.SharedState("x", False, "y")
    st.abort()
    eng.sweep(["10.0.0.1"], st)                      # aborted before ARP pass


# --------------------------------------------------------------------------- #
# EnumerationEngine
# --------------------------------------------------------------------------- #
class _FakeNode:
    """Stand-in for a python-nmap host node (dict-like with helpers)."""

    def __init__(self, protocols, hostname="", osmatch=None):
        self._protocols = protocols
        self._hostname = hostname
        self._osmatch = osmatch or []

    def all_protocols(self):
        return list(self._protocols)

    def __getitem__(self, proto):
        return self._protocols[proto]

    def hostname(self):
        return self._hostname

    def get(self, key, default=None):
        return {"osmatch": self._osmatch}.get(key, default)


class _FakeScanner:
    def __init__(self, hosts_map):
        self._hosts_map = hosts_map
        self.scanned = None

    def scan(self, hosts, arguments):
        self.scanned = (hosts, arguments)

    def all_hosts(self):
        return list(self._hosts_map)

    def __getitem__(self, ip):
        return self._hosts_map[ip]


def _enum(have_nmap=True) -> pr.EnumerationEngine:
    return pr.EnumerationEngine(nmap_args="-sV", workers=2, have_nmap=have_nmap)


def test_nmap_scan_builds_record_and_filters_non_open(monkeypatch):
    node = _FakeNode(
        protocols={
            "tcp": {
                80: {"state": "open", "name": "http", "product": "nginx",
                     "version": "1.24", "extrainfo": "Ubuntu"},
                81: {"state": "closed", "name": "hosts2-ns"},   # filtered out
            }
        },
        hostname="web.local",
        osmatch=[{"name": "Linux 5.x"}],
    )
    scanner = _FakeScanner({"10.0.0.1": node})
    monkeypatch.setattr(pr.nmap, "PortScanner", lambda: scanner)
    rec = _enum()._nmap_scan("10.0.0.1")
    assert rec.hostname == "web.local" and rec.os == "Linux 5.x"
    assert rec.open_count == 1
    assert rec.ports[0].version == "1.24 Ubuntu"
    assert scanner.scanned == ("10.0.0.1", "-sV")


def test_nmap_scan_host_absent_returns_down(monkeypatch):
    scanner = _FakeScanner({})                       # host not in results
    monkeypatch.setattr(pr.nmap, "PortScanner", lambda: scanner)
    rec = _enum()._nmap_scan("10.0.0.2")
    assert rec.status == "down" and rec.state == "DONE" and rec.os == "Unknown"


def test_detect_os_prefers_osmatch():
    node = _FakeNode({"tcp": {}}, osmatch=[{"name": "Windows Server 2019"}])
    assert pr.EnumerationEngine._detect_os(node, []) == "Windows Server 2019"


def test_detect_os_uses_os_cpe():
    node = _FakeNode(
        {"tcp": {22: {"cpe": ["cpe:/o:linux:linux_kernel:5.15", "cpe:/a:openssh"]}}}
    )
    assert pr.EnumerationEngine._detect_os(node, []) == "Linux Kernel 5.15"


def test_detect_os_cpe_string_form_without_version():
    # A vendor:product CPE with no version segment -> product name, no version.
    node = _FakeNode({"tcp": {22: {"cpe": "cpe:/o:microsoft:windows"}}})
    assert pr.EnumerationEngine._detect_os(node, []) == "Windows"


def test_detect_os_falls_back_to_banner_keyword():
    node = _FakeNode({"tcp": {80: {"cpe": ""}}})
    ports = [pr.PortRecord(port=80, service="http", product="Apache", version="ubuntu")]
    assert pr.EnumerationEngine._detect_os(node, ports) == "Linux (Ubuntu)"


def test_detect_os_unknown_when_no_signal():
    node = _FakeNode({"tcp": {80: {"cpe": ""}}})
    assert pr.EnumerationEngine._detect_os(node, []) == "Unknown"


def test_socket_scan_grabs_open_ports(monkeypatch):
    open_ports = {22: 0}                              # only 22 answers
    monkeypatch.setattr(
        pr.socket, "socket",
        lambda *a, **k: _FakeSock(open_ports, recv=b"SSH-2.0-OpenSSH_9.6\r\n"),
    )
    monkeypatch.setattr(pr, "_reverse_dns", lambda ip: "host.local")
    rec = _enum(have_nmap=False)._socket_scan("10.0.0.3", seed_ports=[22])
    assert rec.hostname == "host.local"
    assert rec.open_count == 1
    assert rec.ports[0].port == 22
    assert "OpenSSH" in rec.ports[0].product


def test_socket_scan_oserror_skips_port(monkeypatch):
    monkeypatch.setattr(
        pr.socket, "socket",
        lambda *a, **k: (_ for _ in ()).throw(OSError("boom")),
    )
    monkeypatch.setattr(pr, "_reverse_dns", lambda ip: None)
    rec = _enum(have_nmap=False)._socket_scan("10.0.0.4", seed_ports=[])
    assert rec.open_count == 0


def test_grab_banner_variants():
    assert pr.EnumerationEngine._grab_banner(_FakeSock({}, recv=b"HTTP/1.1 200\r\nX")) \
        == "HTTP/1.1 200"
    assert pr.EnumerationEngine._grab_banner(_FakeSock({}, recv=b"")) == ""

    class _Raises:
        def settimeout(self, _):
            pass

        def recv(self, _n):
            raise OSError("closed")

    assert pr.EnumerationEngine._grab_banner(_Raises()) == ""


def test_enumerate_one_success_and_error(monkeypatch):
    eng = _enum(have_nmap=False)
    st = pr.SharedState("x", False, "y")
    st.add_live_host("10.0.0.1", "icmp", [80])

    monkeypatch.setattr(
        eng, "_socket_scan",
        lambda ip, seeds: pr.HostRecord(ip=ip, os="Linux", state="DONE",
                                        ports=[pr.PortRecord(port=80)]),
    )
    eng._enumerate_one("10.0.0.1", st)
    assert {h.ip: h for h in st.hosts()}["10.0.0.1"].state == "DONE"

    st.add_live_host("10.0.0.2", "icmp", [])
    monkeypatch.setattr(
        eng, "_socket_scan",
        lambda ip, seeds: (_ for _ in ()).throw(RuntimeError("scan failed")),
    )
    eng._enumerate_one("10.0.0.2", st)
    err_host = {h.ip: h for h in st.hosts()}["10.0.0.2"]
    assert err_host.state == "ERROR" and "scan failed" in err_host.error


def test_enumerate_one_uses_nmap_when_available(monkeypatch):
    eng = _enum(have_nmap=True)
    st = pr.SharedState("x", False, "y")
    st.add_live_host("10.0.0.1", "icmp", [])
    monkeypatch.setattr(
        eng, "_nmap_scan",
        lambda ip: pr.HostRecord(ip=ip, os="Linux", state="DONE",
                                 ports=[pr.PortRecord(port=443)]),
    )
    eng._enumerate_one("10.0.0.1", st)
    assert {h.ip: h for h in st.hosts()}["10.0.0.1"].os == "Linux"


def test_enum_run_enumerates_all_and_honours_abort(monkeypatch):
    eng = _enum(have_nmap=False)
    seen = []
    monkeypatch.setattr(eng, "_enumerate_one", lambda ip, st: seen.append(ip))
    st = pr.SharedState("x", False, "y")
    eng.run(["10.0.0.1", "10.0.0.2"], st)
    assert set(seen) == {"10.0.0.1", "10.0.0.2"}
    assert st.snapshot().enum_total == 2


def test_enum_run_breaks_when_aborted(monkeypatch):
    eng = _enum(have_nmap=False)
    monkeypatch.setattr(eng, "_enumerate_one", lambda ip, st: None)
    st = pr.SharedState("x", False, "y")
    st.abort()                                        # aborted before results drain
    eng.run(["10.0.0.1", "10.0.0.2"], st)
    assert st.snapshot().enum_done == 0               # loop broke on first future


# --------------------------------------------------------------------------- #
# Orchestrator
# --------------------------------------------------------------------------- #
class _FakeDiscovery:
    def __init__(self, live=(), abort=False, raise_exc=None):
        self.live, self.abort, self.raise_exc = live, abort, raise_exc

    def sweep(self, hosts, state):
        if self.raise_exc:
            raise self.raise_exc
        for ip in self.live:
            state.add_live_host(ip, "icmp", [], "strong")
        if self.abort:
            state.abort()


class _FakeEnum:
    def __init__(self):
        self.ran_with = None

    def run(self, ips, state):
        self.ran_with = list(ips)


def _orch(disc, enum, **kw):
    st = pr.SharedState("x", False, "y")
    return st, pr.Orchestrator(st, ["10.0.0.1"], disc, enum, **kw)


def test_orchestrator_full_pipeline():
    enum = _FakeEnum()
    st, orch = _orch(_FakeDiscovery(live=["10.0.0.1"]), enum)
    orch.execute()
    assert enum.ran_with == ["10.0.0.1"]
    assert st.snapshot().phase == "COMPLETE"
    assert st.is_done() is True


def test_orchestrator_no_live_hosts_skips_enumeration():
    enum = _FakeEnum()
    st, orch = _orch(_FakeDiscovery(live=[]), enum)
    orch.execute()
    assert enum.ran_with is None
    assert st.snapshot().phase == "COMPLETE"
    assert any("No live hosts" in line for line in st.snapshot().log)


def test_orchestrator_discover_only_resolves_hostnames(monkeypatch):
    resolved = {"called": False}
    monkeypatch.setattr(
        pr, "resolve_hostnames",
        lambda state, **k: resolved.__setitem__("called", True),
    )
    st, orch = _orch(_FakeDiscovery(live=["10.0.0.1"]), _FakeEnum(), discover_only=True)
    orch.execute()
    assert resolved["called"] is True
    assert st.snapshot().phase == "COMPLETE"


def test_orchestrator_discover_only_no_live_skips_resolve(monkeypatch):
    monkeypatch.setattr(
        pr, "resolve_hostnames",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not resolve")),
    )
    st, orch = _orch(_FakeDiscovery(live=[]), _FakeEnum(), discover_only=True)
    orch.execute()
    assert st.snapshot().phase == "COMPLETE"


def test_orchestrator_aborted_after_sweep():
    enum = _FakeEnum()
    st, orch = _orch(_FakeDiscovery(live=["10.0.0.1"], abort=True), enum)
    orch.execute()
    assert st.snapshot().phase == "ABORTED"
    assert enum.ran_with is None


def test_orchestrator_converts_fatal_error_to_state():
    st, orch = _orch(_FakeDiscovery(raise_exc=RuntimeError("kaboom")), _FakeEnum())
    orch.execute()
    assert st.snapshot().phase == "ERROR"
    assert any("FATAL" in line for line in st.snapshot().log)
    assert st.is_done() is True


# --------------------------------------------------------------------------- #
# Renderers — style helpers and per-cell branches
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "phase, expected_fragment",
    [
        ("PHASE 1 · SWEEP", pr.C_AMBER),
        ("PHASE 2 · NMAP", pr.C_AMBER),
        ("INITIALISING", pr.C_AMBER),
        ("COMPLETE", pr.C_GREEN),
        ("ERROR", pr.C_CRIMSON),
        ("ABORTED", pr.C_CRIMSON),
        ("RESOLVING HOSTNAMES", "white"),
    ],
)
def test_phase_style(phase, expected_fragment):
    assert expected_fragment in pr._phase_style(phase)


def test_services_summary_seed_probing_and_overflow():
    # DISCOVERED host with no ports yet -> seed-port service names.
    seeded = pr.HostRecord(ip="10.0.0.1", state="DISCOVERED", seed_ports=[80, 22])
    assert "http" in _render(pr._services_summary(seeded))

    # DISCOVERED host with no seeds -> the 'probing…' placeholder.
    bare = pr.HostRecord(ip="10.0.0.2", state="SCANNING", seed_ports=[])
    assert "probing" in _render(pr._services_summary(bare))

    # DONE host with more ports than the limit -> a "+N" overflow marker.
    many = pr.HostRecord(
        ip="10.0.0.3", state="DONE",
        ports=[pr.PortRecord(port=p, service=f"svc{p}") for p in range(1, 8)],
    )
    assert "+2" in _render(pr._services_summary(many, limit=5))

    # DONE host with an 'unknown' service falls back to the port number, and a
    # host with zero ports renders the em-dash placeholder.
    unknown = pr.HostRecord(
        ip="10.0.0.4", state="DONE", ports=[pr.PortRecord(port=4444, service="unknown")]
    )
    assert "4444" in _render(pr._services_summary(unknown))
    empty = pr.HostRecord(ip="10.0.0.5", state="DONE", ports=[])
    assert "—" in _render(pr._services_summary(empty))


def test_os_cell_error_and_known_and_unknown():
    err = pr.HostRecord(ip="10.0.0.1", error="timeout")
    assert "scan error" in _render(pr._os_cell(err))
    known = pr.HostRecord(ip="10.0.0.2", os="Linux 5.x")
    assert "Linux 5.x" in _render(pr._os_cell(known))
    unknown = pr.HostRecord(ip="10.0.0.3", os="Unknown")
    assert "Unknown" in _render(pr._os_cell(unknown))


def test_render_device_list_vendor_branches():
    st = pr.SharedState("x", False, "y")
    st.add_live_host("10.0.0.1", "arp", [])
    st.set_host_vendor("10.0.0.1", "Cisco")            # named vendor
    st.add_live_host("10.0.0.2", "arp", [])
    st.set_host_vendor("10.0.0.2", pr.VENDOR_RANDOM)   # randomized MAC
    st.add_live_host("10.0.0.3", "arp", [])            # no vendor at all
    out = _render(pr.render_device_list(st.snapshot()))
    assert "Cisco" in out
    assert "private/random" in out
    assert "NETWORK DEVICES" in out


def test_render_device_list_empty():
    out = _render(pr.render_device_list(pr.SharedState("x", False, "y").snapshot()))
    assert "No devices discovered" in out


# --------------------------------------------------------------------------- #
# Run-loops — cockpit (Live) and headless fallback, normal + Ctrl-C
# --------------------------------------------------------------------------- #
class _FakeOrchestrator:
    """Orchestrator stand-in that keeps the worker thread alive for a bounded
    window (without touching the network) so the render loop iterates at least
    once, then marks the scan finished."""

    def __init__(self, state, alive_for=0.15):
        self.state = state
        self.alive_for = alive_for

    def execute(self):
        self.state.set_phase("PHASE 1 · HORIZONTAL SWEEP")
        threading.Event().wait(self.alive_for)   # never set -> a timed block
        self.state.finish()


def test_run_cockpit_renders_until_worker_done():
    st = pr.SharedState("10.0.0.0/30", False, "socket-scan")
    pr.run_cockpit(st, _FakeOrchestrator(st), _term_console())
    assert st.is_done() is True


def test_run_cockpit_keyboard_interrupt_aborts(monkeypatch):
    st = pr.SharedState("10.0.0.0/30", False, "socket-scan")
    console = _term_console()
    monkeypatch.setattr(pr.time, "sleep", lambda _: (_ for _ in ()).throw(KeyboardInterrupt))
    pr.run_cockpit(st, _FakeOrchestrator(st, alive_for=0.5), console)
    assert st.is_aborted() is True
    assert "abort" in console.file.getvalue().lower()


def test_run_headless_prints_progress_until_done():
    st = pr.SharedState("10.0.0.0/30", False, "socket-scan")
    pr.run_headless(st, _FakeOrchestrator(st), _sink_console())
    assert st.is_done() is True


def test_run_headless_keyboard_interrupt_aborts(monkeypatch):
    st = pr.SharedState("10.0.0.0/30", False, "socket-scan")
    console = _term_console()
    monkeypatch.setattr(pr.time, "sleep", lambda _: (_ for _ in ()).throw(KeyboardInterrupt))
    pr.run_headless(st, _FakeOrchestrator(st, alive_for=0.5), console)
    assert st.is_aborted() is True


# --------------------------------------------------------------------------- #
# Provenance probes — exception branches
# --------------------------------------------------------------------------- #
def test_git_commit_and_nmap_version_handle_missing_binaries(monkeypatch):
    monkeypatch.setattr(
        pr.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(OSError())
    )
    assert pr._git_commit() is None
    assert pr._nmap_version() is None


def test_git_commit_returns_none_on_empty_output(monkeypatch):
    monkeypatch.setattr(
        pr.subprocess, "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout="\n", stderr=""),
    )
    assert pr._git_commit() is None


def test_nmap_version_parses_and_missing(monkeypatch):
    monkeypatch.setattr(
        pr.subprocess, "run",
        lambda *a, **k: subprocess.CompletedProcess(
            a, 0, stdout="Nmap version 7.95 ( https://nmap.org )", stderr=""),
    )
    assert pr._nmap_version() == "7.95"
    monkeypatch.setattr(
        pr.subprocess, "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout="no match", stderr=""),
    )
    assert pr._nmap_version() is None


# --------------------------------------------------------------------------- #
# Atomic writers — the best-effort chmod guard
# --------------------------------------------------------------------------- #
def _one_host_report():
    st = pr.SharedState("10.0.0.0/30", False, "socket-scan")
    st.add_live_host("10.0.0.1", "icmp", [80])
    st.update_host_record(
        pr.HostRecord(ip="10.0.0.1", os="Linux", state="DONE",
                      ports=[pr.PortRecord(port=80, service="http", version="nginx")])
    )
    now = datetime.now(timezone.utc)
    return pr.build_report(st, SimpleNamespace(n_hosts=1, has_public=False, blocked=[]),
                           now, now)


def test_write_report_chmod_failure_is_ignored(monkeypatch, tmp_path):
    monkeypatch.setattr(
        pr.os, "chmod", lambda *a, **k: (_ for _ in ()).throw(OSError("no chmod"))
    )
    path = pr.write_report(_one_host_report(), str(tmp_path))
    assert os.path.exists(path)                       # write still succeeds


def test_atomic_write_text_chmod_failure_is_ignored(monkeypatch, tmp_path):
    monkeypatch.setattr(
        pr.os, "chmod", lambda *a, **k: (_ for _ in ()).throw(OSError())
    )
    target = str(tmp_path / "x.txt")
    pr._atomic_write_text(target, "hello", newline="")
    assert open(target).read() == "hello"


# --------------------------------------------------------------------------- #
# HTML report — the port-less host is skipped in the service-detail section
# --------------------------------------------------------------------------- #
def test_html_report_skips_hosts_without_ports_in_detail():
    report = {
        "target": "10.0.0.0/30", "version": "1.0.0", "engine": "socket-scan",
        "author": pr.AUTHOR, "summary": {"blocked_entries": [{"entry": "127.0.0.1"}]},
        "hosts": [
            {"ip": "10.0.0.1", "ports": [{"port": 80, "service": "http"}]},
            {"ip": "10.0.0.2", "ports": []},          # skipped in detail section
        ],
    }
    out = pr.render_html_report(report)
    assert "Service detail" in out
    assert "Skipped 1 protected" in out
    assert out.count("<h3") == 1                        # only the host with ports


# --------------------------------------------------------------------------- #
# load_baseline — the success return
# --------------------------------------------------------------------------- #
def test_load_baseline_accepts_valid_report(tmp_path):
    good = tmp_path / "report.json"
    good.write_text(json.dumps({"hosts": [{"ip": "10.0.0.1"}], "finished_at": "t"}))
    data = pr.load_baseline(str(good))
    assert data["hosts"][0]["ip"] == "10.0.0.1"


# --------------------------------------------------------------------------- #
# render_diff_panel — stable and full-change renderings
# --------------------------------------------------------------------------- #
def test_render_diff_panel_no_changes():
    diff = {"has_changes": False, "appeared_hosts": [], "disappeared_hosts": [],
            "changed_hosts": [], "baseline_finished_at": None}
    assert "stable" in _render(pr.render_diff_panel(diff))


def test_render_diff_panel_all_change_kinds():
    diff = {
        "has_changes": True,
        "appeared_hosts": ["10.0.0.9"],
        "disappeared_hosts": ["10.0.0.2"],
        "changed_hosts": [
            {
                "ip": "10.0.0.1",
                "opened_ports": [443],
                "closed_ports": [22],
                "service_changes": [{"port": 80, "from": "http 1.18", "to": "http 1.24"}],
                "os_from": "Linux", "os_to": "Windows",
            }
        ],
        "baseline_finished_at": "2026-01-01T00:00:00+00:00",
    }
    out = _render(pr.render_diff_panel(diff))
    assert "NEW HOSTS" in out and "10.0.0.9" in out
    assert "GONE HOSTS" in out and "10.0.0.2" in out
    assert "443" in out and "22" in out
    assert "http 1.18" in out and "Windows" in out


# --------------------------------------------------------------------------- #
# print_summary — weak-host and blocked-entry rows
# --------------------------------------------------------------------------- #
def test_print_summary_with_weak_and_blocked():
    st = pr.SharedState("10.0.0.0/24", False, "socket-scan")
    st.add_live_host("10.0.0.1", "tcp-rst (unconfirmed)", [], "weak")
    scope = SimpleNamespace(n_hosts=254, has_public=False,
                            blocked=[("127.0.0.1", "loopback")])
    console = _term_console()
    now = datetime.now(timezone.utc)
    pr.print_summary(console, st, scope, now, now)
    out = console.file.getvalue()
    assert "SCAN COMPLETE" in out
    assert "RST-only" in out
    assert "Blocked" in out


# --------------------------------------------------------------------------- #
# Privilege / ping portability
# --------------------------------------------------------------------------- #
def test_is_privileged_root_nonroot_and_oserror(monkeypatch):
    monkeypatch.setattr(pr.os, "geteuid", lambda: 0, raising=False)
    assert pr.is_privileged() is True
    monkeypatch.setattr(pr.os, "geteuid", lambda: 1000, raising=False)
    assert pr.is_privileged() is False
    monkeypatch.setattr(
        pr.os, "geteuid", lambda: (_ for _ in ()).throw(OSError()), raising=False
    )
    assert pr.is_privileged() is False


def test_is_privileged_without_geteuid(monkeypatch):
    monkeypatch.delattr(pr.os, "geteuid", raising=False)
    assert pr.is_privileged() is False


def test_ping_available(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/sbin/ping")
    assert pr._ping_available() is True
    monkeypatch.setattr("shutil.which", lambda name: None)
    assert pr._ping_available() is False


@pytest.mark.parametrize(
    "system, expected_flag",
    [("darwin", "-t"), ("windows", "-w"), ("linux", "-W")],
)
def test_ping_command_per_os(monkeypatch, system, expected_flag):
    monkeypatch.setattr(pr.platform, "system", lambda: system)
    cmd = pr._ping_command("1.2.3.4", 2.0)
    assert cmd[0] == "ping" and cmd[-1] == "1.2.3.4"
    assert expected_flag in cmd


# --------------------------------------------------------------------------- #
# ARP / NDP fallbacks and error paths
# --------------------------------------------------------------------------- #
def test_read_arp_table_falls_back_to_proc(monkeypatch, tmp_path):
    # `arp -an` raises -> the Linux /proc/net/arp fallback parses instead.
    monkeypatch.setattr(
        pr.subprocess, "run",
        lambda *a, **k: (_ for _ in ()).throw(OSError("no arp binary")),
    )
    proc = tmp_path / "arp"
    proc.write_text(
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "192.168.1.5      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n"
        "192.168.1.6      0x1         0x0         00:00:00:00:00:00     *        eth0\n"
    )
    monkeypatch.setattr(pr.os.path, "exists", lambda p: p == "/proc/net/arp")

    real_open = open
    monkeypatch.setattr(
        "builtins.open",
        lambda p, *a, **k: real_open(proc, *a, **k) if p == "/proc/net/arp"
        else real_open(p, *a, **k),
    )
    table = pr._read_arp_table()
    assert table.get("192.168.1.5") == "aa:bb:cc:dd:ee:ff"
    assert "192.168.1.6" not in table                 # all-zero MAC filtered


def test_read_arp_table_proc_open_error(monkeypatch):
    monkeypatch.setattr(
        pr.subprocess, "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout="", stderr=""),
    )
    monkeypatch.setattr(pr.os.path, "exists", lambda p: p == "/proc/net/arp")
    monkeypatch.setattr(
        "builtins.open", lambda *a, **k: (_ for _ in ()).throw(OSError("denied"))
    )
    assert pr._read_arp_table() == {}


def test_read_ndp_table_ndp_error_then_linux_fallback(monkeypatch):
    # `ndp -an` raises; `ip -6 neigh` provides the neighbours.
    linux = ("2001:db8::5 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"
             "fe80::9 dev eth0 lladdr 11:22:33:44:55:66 FAILED\n"
             "somejunk without markers\n")

    def fake_run(cmd, *a, **k):
        if cmd[:1] == ["ndp"]:
            raise OSError("no ndp")
        return subprocess.CompletedProcess(cmd, 0, stdout=linux, stderr="")

    monkeypatch.setattr(pr.subprocess, "run", fake_run)
    table = pr._read_ndp_table()
    assert table.get("aa:bb:cc:dd:ee:ff") == ["2001:db8::5"]
    assert "11:22:33:44:55:66" not in table           # FAILED state excluded


def test_read_ndp_table_both_sources_error(monkeypatch):
    monkeypatch.setattr(
        pr.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(OSError())
    )
    assert pr._read_ndp_table() == {}


# --------------------------------------------------------------------------- #
# OUI resolution / download
# --------------------------------------------------------------------------- #
def test_resolve_oui_path_explicit_and_none(tmp_path, monkeypatch):
    # Point HOME at an empty temp dir so the real user's OUI cache can't leak in.
    monkeypatch.setattr(pr.os.path, "expanduser", lambda p: str(tmp_path / "home"))
    explicit = tmp_path / "oui.csv"
    explicit.write_text("x")
    assert pr.resolve_oui_path(str(explicit)) == str(explicit)
    assert pr.resolve_oui_path(None) is None           # nothing on disk


def test_download_oui_registry_success(monkeypatch, tmp_path):
    monkeypatch.setattr(pr.os.path, "expanduser", lambda p: str(tmp_path))

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b"Registry,Assignment,Organization Name\nMA-L,ABCDEF,Acme\n"

    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: _Resp())
    dest = pr.download_oui_registry(_sink_console())
    assert dest and dest.endswith("oui.csv")
    assert os.path.exists(dest)


def test_download_oui_registry_failure_returns_none(monkeypatch, tmp_path):
    monkeypatch.setattr(pr.os.path, "expanduser", lambda p: str(tmp_path))
    import urllib.request
    monkeypatch.setattr(
        urllib.request, "urlopen",
        lambda *a, **k: (_ for _ in ()).throw(OSError("network down")),
    )
    console = _sink_console()
    assert pr.download_oui_registry(console) is None
    assert "failed" in console.file.getvalue().lower()


def test_download_oui_registry_rejects_non_https(monkeypatch, tmp_path):
    # Defence-in-depth HTTPS guard: a non-HTTPS source is refused before urlopen.
    monkeypatch.setattr(pr.os.path, "expanduser", lambda p: str(tmp_path))
    monkeypatch.setattr(pr, "_OUI_REGISTRY_URL", "http://insecure.example/oui.csv")
    import urllib.request
    monkeypatch.setattr(
        urllib.request, "urlopen",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("urlopen must not run")),
    )
    assert pr.download_oui_registry(_sink_console()) is None


# --------------------------------------------------------------------------- #
# DNS helpers
# --------------------------------------------------------------------------- #
def test_mac_vendor_non_hex_first_octet_returns_none():
    # A MAC-shaped string whose first octet is not valid hex trips the
    # ValueError guard in _mac_vendor and yields None (deterministic cover for a
    # branch the property-based fuzz test only hits nondeterministically).
    assert pr._mac_vendor("zz:44:89:11:22:33", {}) is None


def test_reverse_dns_success_and_failure(monkeypatch):
    monkeypatch.setattr(pr.socket, "gethostbyaddr", lambda ip: ("host.local", [], [ip]))
    assert pr._reverse_dns("10.0.0.1") == "host.local"
    monkeypatch.setattr(
        pr.socket, "gethostbyaddr", lambda ip: (_ for _ in ()).throw(socket.herror())
    )
    assert pr._reverse_dns("10.0.0.1") is None


def test_resolve_hostnames_populates_and_noop(monkeypatch):
    st = pr.SharedState("x", False, "y")
    st.add_live_host("10.0.0.1", "icmp", [])
    monkeypatch.setattr(
        pr.socket, "gethostbyaddr", lambda ip: ("router.local", [], [ip])
    )
    pr.resolve_hostnames(st, workers=2)
    assert {h.ip: h for h in st.hosts()}["10.0.0.1"].hostname == "router.local"
    # Second pass: every host already named -> early return, no lookups.
    monkeypatch.setattr(
        pr.socket, "gethostbyaddr",
        lambda ip: (_ for _ in ()).throw(AssertionError("must not resolve")),
    )
    pr.resolve_hostnames(st, workers=2)


def test_resolve_hostnames_lookup_failure(monkeypatch):
    st = pr.SharedState("x", False, "y")
    st.add_live_host("10.0.0.1", "icmp", [])
    monkeypatch.setattr(
        pr.socket, "gethostbyaddr", lambda ip: (_ for _ in ()).throw(OSError())
    )
    pr.resolve_hostnames(st, workers=2)
    assert {h.ip: h for h in st.hosts()}["10.0.0.1"].hostname is None


# --------------------------------------------------------------------------- #
# Small helpers + nmap arg building + engine detection
# --------------------------------------------------------------------------- #
def test_ip_key_handles_garbage():
    assert pr._ip_key("not-an-ip") == (0,)
    assert pr._ip_key(None) == (0,)


def test_build_nmap_args_explicit_ports():
    ns = SimpleNamespace(full=False, ports="1-1024", top_ports=100, host_timeout="120s")
    args = pr.build_nmap_args(ns, privileged=False)
    assert "-p 1-1024" in args


def test_detect_nmap_no_pynmap(monkeypatch):
    monkeypatch.setattr(pr, "_HAVE_PYNMAP", False)
    assert pr.detect_nmap(_sink_console()) is False


def test_detect_nmap_binary_present(monkeypatch):
    monkeypatch.setattr(pr, "_HAVE_PYNMAP", True)
    monkeypatch.setattr(pr.nmap, "PortScanner", lambda: object())
    assert pr.detect_nmap(_sink_console()) is True


def test_detect_nmap_binary_missing(monkeypatch):
    monkeypatch.setattr(pr, "_HAVE_PYNMAP", True)
    monkeypatch.setattr(
        pr.nmap, "PortScanner", lambda: (_ for _ in ()).throw(RuntimeError("no nmap"))
    )
    assert pr.detect_nmap(_sink_console()) is False


# --------------------------------------------------------------------------- #
# CLI plumbing — parser, banner, scope confirmation
# --------------------------------------------------------------------------- #
def test_build_parser_defaults_and_flags():
    parser = pr.build_parser()
    args = parser.parse_args(["192.168.1.0/24", "-D", "--full", "-y"])
    assert args.target == "192.168.1.0/24"
    assert args.discover is True and args.full is True and args.yes is True
    assert args.top_ports == 100                       # default preserved


def test_print_banner_emits_brand():
    console = _term_console()
    pr.print_banner(console)
    assert "PURPLE" in console.file.getvalue()


def test_confirm_scope_not_risky_returns_true():
    scope = SimpleNamespace(has_public=False, n_hosts=10)
    args = SimpleNamespace(yes=False)
    assert pr.confirm_scope(scope, args, _term_console()) is True


def test_confirm_scope_yes_bypasses_prompt():
    scope = SimpleNamespace(has_public=True, n_hosts=1000)
    args = SimpleNamespace(yes=True)
    assert pr.confirm_scope(scope, args, _term_console()) is True


def test_confirm_scope_non_terminal_risky_refuses():
    scope = SimpleNamespace(has_public=True, n_hosts=300)
    args = SimpleNamespace(yes=False)
    console = _sink_console()
    assert pr.confirm_scope(scope, args, console) is False
    assert "Refusing" in console.file.getvalue()


def test_confirm_scope_terminal_prompts(monkeypatch):
    scope = SimpleNamespace(has_public=False, n_hosts=500)
    args = SimpleNamespace(yes=False)
    monkeypatch.setattr(pr.Confirm, "ask", lambda *a, **k: True)
    assert pr.confirm_scope(scope, args, _term_console()) is True


# --------------------------------------------------------------------------- #
# main() — end-to-end CLI driver (network engines & run-loops stubbed)
# --------------------------------------------------------------------------- #
def _stub_runner(add_host=True):
    """A run_cockpit/run_headless stand-in that (optionally) seeds one live host
    then marks the scan finished — no threads, no network."""
    def _run(state, orchestrator, console):
        if add_host:
            state.add_live_host("10.0.0.1", "icmp", [80], "strong")
            state.update_host_record(
                pr.HostRecord(
                    ip="10.0.0.1", os="Linux", state="DONE",
                    ports=[pr.PortRecord(port=80, service="http", version="nginx")],
                )
            )
        state.finish()
    return _run


@pytest.fixture
def main_env(monkeypatch):
    """Deterministic environment for main(): no nmap probe, no OUI on disk."""
    monkeypatch.setattr(pr, "detect_nmap", lambda console: False)
    monkeypatch.setattr(pr, "resolve_oui_path", lambda explicit: None)
    return monkeypatch


def test_main_rejects_forbidden_scope(main_env):
    assert pr.main(["127.0.0.1", "--no-ui", "--no-export"]) == 2


def test_main_refuses_risky_scope_without_yes(main_env):
    # Public target, non-interactive console, no -y -> refuse (exit 1).
    assert pr.main(["8.8.8.8", "--no-ui", "--no-export"]) == 1


def test_main_headless_with_all_exports(main_env, tmp_path):
    main_env.setattr(pr, "run_headless", _stub_runner(add_host=True))
    rc = pr.main(["192.168.1.10", "--no-ui", "--html", "--csv", "-o", str(tmp_path)])
    assert rc == 0
    suffixes = {f.suffix for f in tmp_path.iterdir()}
    assert {".json", ".html", ".csv"} <= suffixes


def test_main_cockpit_discover_mode_with_diff(main_env, tmp_path):
    main_env.setattr(
        pr, "Console", lambda *a, **k: Console(file=io.StringIO(), force_terminal=True)
    )
    main_env.setattr(pr, "run_cockpit", _stub_runner(add_host=True))
    baseline = tmp_path / "base.json"
    baseline.write_text(json.dumps({"hosts": [], "finished_at": "2026-01-01T00:00:00+00:00"}))
    rc = pr.main(["192.168.1.10", "-D", "--diff", str(baseline), "-o", str(tmp_path)])
    assert rc == 0


def test_main_diff_baseline_load_failure(main_env, tmp_path):
    main_env.setattr(pr, "run_headless", _stub_runner(add_host=False))
    rc = pr.main(["192.168.1.10", "--no-ui", "--no-export",
                  "--diff", str(tmp_path / "missing.json")])
    assert rc == 0


def test_main_export_failures_are_reported_not_fatal(main_env, tmp_path):
    main_env.setattr(pr, "run_headless", _stub_runner(add_host=True))
    boom = lambda report, out: (_ for _ in ()).throw(OSError("disk full"))
    main_env.setattr(pr, "write_report", boom)
    main_env.setattr(pr, "write_html_report", boom)
    main_env.setattr(pr, "write_csv_report", boom)
    rc = pr.main(["192.168.1.10", "--no-ui", "--html", "--csv", "-o", str(tmp_path)])
    assert rc == 0


def test_main_blocked_entries_and_downloaded_oui(monkeypatch, tmp_path):
    monkeypatch.setattr(pr, "detect_nmap", lambda console: False)
    oui = tmp_path / "oui.csv"
    oui.write_text("Registry,Assignment,Organization Name\nMA-L,ABCDEF,Acme Networks\n")
    monkeypatch.setattr(pr, "download_oui_registry", lambda console: str(oui))
    monkeypatch.setattr(pr, "run_headless", _stub_runner(add_host=True))
    rc = pr.main(["192.168.1.10,127.0.0.1", "--no-ui", "--download-oui",
                  "--no-export", "-o", str(tmp_path)])
    assert rc == 0


# --------------------------------------------------------------------------- #
# cli() — the installed console-script last-resort guard
# --------------------------------------------------------------------------- #
def test_cli_success_exit_code(monkeypatch):
    monkeypatch.setattr(pr, "main", lambda: 0)
    with pytest.raises(SystemExit) as exc:
        pr.cli()
    assert exc.value.code == 0


def test_cli_keyboard_interrupt(monkeypatch):
    monkeypatch.setattr(pr, "main", lambda: (_ for _ in ()).throw(KeyboardInterrupt))
    with pytest.raises(SystemExit) as exc:
        pr.cli()
    assert exc.value.code == 130


def test_cli_systemexit_passthrough(monkeypatch):
    def _raise():
        raise SystemExit(3)

    monkeypatch.setattr(pr, "main", _raise)
    with pytest.raises(SystemExit) as exc:
        pr.cli()
    assert exc.value.code == 3


def test_cli_generic_exception_maps_to_exit_1(monkeypatch):
    monkeypatch.setattr(pr, "main", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(SystemExit) as exc:
        pr.cli()
    assert exc.value.code == 1


def test_cli_generic_exception_when_console_also_fails(monkeypatch):
    monkeypatch.setattr(pr, "main", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr(
        pr, "Console", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no console"))
    )
    with pytest.raises(SystemExit) as exc:
        pr.cli()
    assert exc.value.code == 1
