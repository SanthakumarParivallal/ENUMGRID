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
