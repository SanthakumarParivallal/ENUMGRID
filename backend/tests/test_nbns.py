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
