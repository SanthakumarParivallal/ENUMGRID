"""test_snmp.py — SNMP v2c BER encode/decode (no network)."""

from __future__ import annotations

import snmp


def test_oid_roundtrip():
    for oid in (snmp.SYS_NAME, snmp.SYS_DESCR, "1.3.6.1.4.1.9.2.1.3.0"):
        encoded = snmp._enc_oid(oid)
        assert encoded[0] == 0x06  # OID tag
        # decode the value bytes (strip tag+len)
        _t, body, _ = snmp._read_tlv(encoded, 0)
        assert snmp._decode_oid(body) == oid


def test_build_get_is_a_sequence():
    pkt = snmp.build_get("public", [snmp.SYS_NAME])
    assert pkt[0] == 0x30  # SEQUENCE
    assert b"public" in pkt


def _craft_response(oid: str, value: str) -> bytes:
    vb = snmp._tlv(0x30, snmp._enc_oid(oid) + snmp._tlv(0x04, value.encode()))
    vbl = snmp._tlv(0x30, vb)
    pdu = snmp._tlv(0xA2, snmp._enc_int(1) + snmp._enc_int(0) + snmp._enc_int(0) + vbl)
    return snmp._tlv(0x30, snmp._enc_int(1) + snmp._tlv(0x04, b"public") + pdu)


def test_parse_response_extracts_value():
    resp = _craft_response(snmp.SYS_NAME, "core-switch-01")
    out = snmp.parse_response(resp)
    assert out.get(snmp.SYS_NAME) == "core-switch-01"


def test_parse_garbage_is_empty():
    assert snmp.parse_response(b"\x00\x01") == {}
    assert snmp.parse_response(b"") == {}


def test_sysinfo_maps_name_and_descr(monkeypatch):
    monkeypatch.setattr(snmp, "snmp_get", lambda *a, **k: {
        snmp.SYS_NAME: "ap-lobby", snmp.SYS_DESCR: "Cisco IOS Software",
    })
    info = snmp.sysinfo("192.168.0.2")
    assert info == {"name": "ap-lobby", "descr": "Cisco IOS Software"}


def test_snmp_get_rejects_ipv6():
    assert snmp.snmp_get("fe80::1", [snmp.SYS_NAME]) == {}
