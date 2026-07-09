"""
test_nbns.py — NetBIOS node-status request build + reply parse.

The live UDP query isn't unit-tested (needs a responder); this pins the packet
construction and the reply parser against a hand-built node-status response so a
real device's name is extracted correctly (and malformed packets return None
instead of crashing).
"""

from __future__ import annotations

import struct

import nbns


def test_build_query_is_a_valid_nbstat_request():
    pkt = nbns._build_query()
    # QDCOUNT == 1, and the question ends with QTYPE=NBSTAT(0x21) QCLASS=IN(0x01).
    qdcount = struct.unpack(">H", pkt[4:6])[0]
    assert qdcount == 1
    assert pkt[-4:] == struct.pack(">HH", 0x0021, 0x0001)
    assert b"CKAAAAAAAA" in pkt  # wildcard-name first-level encoding


def _fake_node_status_reply(name: str, *, group: bool = False) -> bytes:
    """Build a minimal NBSTAT response carrying a single 15-char name."""
    header = struct.pack(">HHHHHH", 0x4247, 0x8400, 0, 1, 0, 0)
    # Echo an answer RR: encoded name (use the wildcard), TYPE/CLASS/TTL/RDLEN.
    enc_name = bytes([32]) + nbns._WILDCARD_ENCODED + b"\x00"
    padded = name.ljust(15)[:15].encode("ascii")
    flags = 0x8000 if group else 0x0400  # group bit vs a unique active name
    rdata = bytes([1]) + padded + bytes([0x00]) + struct.pack(">H", flags)
    rr = enc_name + struct.pack(">HHIH", 0x0021, 0x0001, 0, len(rdata)) + rdata
    return header + rr


def test_parse_extracts_unique_name():
    reply = _fake_node_status_reply("OFFICE-NAS")
    assert nbns._parse_response(reply) == "OFFICE-NAS"


def test_parse_skips_group_names():
    reply = _fake_node_status_reply("WORKGROUP", group=True)
    assert nbns._parse_response(reply) is None


def test_parse_malformed_returns_none():
    assert nbns._parse_response(b"") is None
    assert nbns._parse_response(b"\x00\x01\x02") is None


def test_nbns_name_rejects_ipv6():
    assert nbns.nbns_name("fe80::1") is None


def test_nbns_names_empty_list():
    assert nbns.nbns_names([]) == {}


def test_parse_returns_none_when_no_answers():
    header = struct.pack(">HHHHHH", 0x4247, 0x8400, 0, 0, 0, 0)  # ANCOUNT=0
    assert nbns._parse_response(header + b"\x00" * 8) is None


def test_parse_skips_echoed_question_record():
    # A reply that echoes the question (QDCOUNT=1) is walked past to the answer RR.
    header = struct.pack(">HHHHHH", 0x4247, 0x8400, 1, 1, 0, 0)   # QDCOUNT=1, ANCOUNT=1
    question = bytes([32]) + nbns._WILDCARD_ENCODED + b"\x00" + struct.pack(">HH", 0x21, 0x01)
    enc_name = bytes([32]) + nbns._WILDCARD_ENCODED + b"\x00"
    padded = "ECHO-HOST".ljust(15)[:15].encode("ascii")
    rdata = bytes([1]) + padded + bytes([0x00]) + struct.pack(">H", 0x0400)
    rr = enc_name + struct.pack(">HHIH", 0x21, 0x01, 0, len(rdata)) + rdata
    assert nbns._parse_response(header + question + rr) == "ECHO-HOST"


def test_parse_returns_none_when_truncated_after_rr_header():
    header = struct.pack(">HHHHHH", 0x4247, 0x8400, 0, 1, 0, 0)   # ANCOUNT=1
    enc_name = bytes([32]) + nbns._WILDCARD_ENCODED + b"\x00"
    rr = enc_name + struct.pack(">HHIH", 0x21, 0x01, 0, 0)        # stops before num_names byte
    assert nbns._parse_response(header + rr) is None


def test_parse_breaks_on_truncated_name_entry():
    header = struct.pack(">HHHHHH", 0x4247, 0x8400, 0, 1, 0, 0)
    enc_name = bytes([32]) + nbns._WILDCARD_ENCODED + b"\x00"
    rdata = bytes([1]) + b"SHORT"                                  # num_names=1 but < 18 bytes follow
    rr = enc_name + struct.pack(">HHIH", 0x21, 0x01, 0, len(rdata)) + rdata
    assert nbns._parse_response(header + rr) is None


def test_nbns_name_sends_and_parses(monkeypatch):
    reply = _fake_node_status_reply("OFFICE-NAS")

    class _Sock:
        def settimeout(self, t): pass
        def sendto(self, pkt, addr): self.addr = addr
        def recvfrom(self, n): return reply, ("192.168.0.5", 137)
        def close(self): pass

    monkeypatch.setattr(nbns.socket, "socket", lambda *a, **k: _Sock())
    assert nbns.nbns_name("192.168.0.5") == "OFFICE-NAS"


def test_nbns_name_returns_none_on_socket_error(monkeypatch):
    class _Sock:
        def settimeout(self, t): pass
        def sendto(self, *a): raise OSError("unreachable")
        def close(self): pass

    monkeypatch.setattr(nbns.socket, "socket", lambda *a, **k: _Sock())
    assert nbns.nbns_name("192.168.0.5") is None


def test_nbns_names_resolves_responders_only(monkeypatch):
    monkeypatch.setattr(nbns, "nbns_name",
                        lambda ip, timeout_s=1.0: "NAS" if ip.endswith(".5") else None)
    assert nbns.nbns_names(["192.168.0.5", "192.168.0.6"]) == {"192.168.0.5": "NAS"}


def test_parse_degrades_gracefully_on_unexpected_decode_error(monkeypatch):
    # Robustness contract: this parser consumes untrusted UDP from the wire, so an
    # unexpected decode failure must be caught and reported as "no name" — never
    # propagated as a crash. We fault-inject a struct error to prove the safety net
    # (the reason the try/except exists) actually holds.
    reply = _fake_node_status_reply("OFFICE-NAS")
    real_unpack = nbns.struct.unpack

    def _boom(fmt, buf):
        raise nbns.struct.error("injected decode failure")

    monkeypatch.setattr(nbns.struct, "unpack", _boom)
    assert nbns._parse_response(reply) is None            # caught, not raised
    monkeypatch.setattr(nbns.struct, "unpack", real_unpack)
