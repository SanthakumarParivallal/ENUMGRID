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


def test_enc_len_short_and_long_form():
    assert snmp._enc_len(5) == b"\x05"                  # short form
    assert snmp._enc_len(0x80) == b"\x81\x80"           # long form, 1 length byte
    assert snmp._enc_len(0x1234) == b"\x82\x12\x34"     # long form, 2 length bytes


def test_enc_int_pads_high_bit_to_stay_positive():
    assert snmp._enc_int(0) == b"\x02\x01\x00"
    assert snmp._enc_int(128) == b"\x02\x02\x00\x80"    # leading 0x00 keeps it positive


def test_b128_multibyte_and_decode_empty_oid():
    assert snmp._b128(0x81) == [0x81, 0x01]             # multi-byte base-128
    assert snmp._decode_oid(b"") == ""                  # empty OID body → ""


def test_read_tlv_handles_long_form_length():
    value = b"A" * 200
    tlv = bytes([0x04, 0x81, 200]) + value              # long-form length (0x81 → 1 length byte)
    tag, body, nxt = snmp._read_tlv(tlv, 0)
    assert tag == 0x04 and body == value and nxt == len(tlv)


def test_parse_response_skips_null_valued_varbind():
    # A varbind whose value is noSuchObject (0x81) is skipped, not emitted as a value.
    vb = snmp._tlv(0x30, snmp._enc_oid(snmp.SYS_NAME) + snmp._tlv(0x81, b""))
    vbl = snmp._tlv(0x30, vb)
    pdu = snmp._tlv(0xA2, snmp._enc_int(1) + snmp._enc_int(0) + snmp._enc_int(0) + vbl)
    resp = snmp._tlv(0x30, snmp._enc_int(1) + snmp._tlv(0x04, b"public") + pdu)
    assert snmp.parse_response(resp) == {}


def test_snmp_get_sends_and_parses(monkeypatch):
    reply = _craft_response(snmp.SYS_NAME, "core-switch-01")

    class _Sock:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def settimeout(self, t): pass
        def sendto(self, pkt, addr): self.addr = addr
        def recvfrom(self, n): return reply, ("192.168.0.2", 161)

    monkeypatch.setattr(snmp.socket, "socket", lambda *a, **k: _Sock())
    assert snmp.snmp_get("192.168.0.2", [snmp.SYS_NAME]).get(snmp.SYS_NAME) == "core-switch-01"


def test_snmp_get_returns_empty_on_socket_error(monkeypatch):
    class _Sock:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def settimeout(self, t): pass
        def sendto(self, *a): raise OSError("net unreachable")

    monkeypatch.setattr(snmp.socket, "socket", lambda *a, **k: _Sock())
    assert snmp.snmp_get("192.168.0.2", [snmp.SYS_NAME]) == {}
