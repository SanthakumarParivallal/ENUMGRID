"""
snmp.py — minimal SNMP v2c read for device name / description.

Network gear (switches, APs, printers, UPS, some IoT) often has no reverse-DNS
or mDNS record but answers SNMP on UDP/161 with a community string (frequently
the default `public`). Reading `sysName` and `sysDescr` fills the name/OS column
for exactly those devices — a classic enumeration win.

This is a tiny, dependency-free SNMP v2c GET: just enough BER to build a request
for two OIDs and decode the reply. Best-effort and bounded; any error yields no
data. Pure stdlib (sockets). Read-only — it never writes via SNMP.
"""

from __future__ import annotations

import socket

SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"


# --------------------------------------------------------------------------- #
# Minimal BER (ASN.1) codec
# --------------------------------------------------------------------------- #
def _enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = []
    while n:
        body.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(body)]) + bytes(body)


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _enc_len(len(value)) + value


def _enc_int(n: int) -> bytes:
    if n == 0:
        return _tlv(0x02, b"\x00")
    body = []
    v = n
    while v:
        body.insert(0, v & 0xFF)
        v >>= 8
    if body[0] & 0x80:  # keep it positive
        body.insert(0, 0)
    return _tlv(0x02, bytes(body))


def _b128(n: int) -> list[int]:
    out = [n & 0x7F]
    n >>= 7
    while n:
        out.insert(0, (n & 0x7F) | 0x80)
        n >>= 7
    return out


def _enc_oid(oid: str) -> bytes:
    parts = [int(x) for x in oid.split(".")]
    body = _b128(40 * parts[0] + parts[1])
    for arc in parts[2:]:
        body += _b128(arc)
    return _tlv(0x06, bytes(body))


def _decode_oid(body: bytes) -> str:
    if not body:
        return ""
    arcs = [body[0] // 40, body[0] % 40]
    n = 0
    for b in body[1:]:
        n = (n << 7) | (b & 0x7F)
        if not (b & 0x80):
            arcs.append(n)
            n = 0
    return ".".join(str(a) for a in arcs)


def _read_tlv(data: bytes, i: int) -> tuple[int, bytes, int]:
    tag = data[i]
    i += 1
    length = data[i]
    i += 1
    if length & 0x80:
        nbytes = length & 0x7F
        length = int.from_bytes(data[i:i + nbytes], "big")
        i += nbytes
    value = data[i:i + length]
    return tag, value, i + length


def build_get(community: str, oids: list[str], request_id: int = 1) -> bytes:
    """Build an SNMP v2c GetRequest for the given OIDs."""
    varbinds = b"".join(_tlv(0x30, _enc_oid(o) + _tlv(0x05, b"")) for o in oids)
    vbl = _tlv(0x30, varbinds)
    pdu = _tlv(0xA0, _enc_int(request_id) + _enc_int(0) + _enc_int(0) + vbl)
    msg = _enc_int(1) + _tlv(0x04, community.encode()) + pdu  # version 1 == v2c
    return _tlv(0x30, msg)


def parse_response(data: bytes) -> dict[str, str]:
    """Decode an SNMP response into {oid: value} (octet strings as text)."""
    out: dict[str, str] = {}
    try:
        _tag, seq, _ = _read_tlv(data, 0)
        items = []
        i = 0
        while i < len(seq):
            t, v, i = _read_tlv(seq, i)
            items.append((t, v))
        pdu = items[-1][1]  # GetResponse PDU
        p = []
        i = 0
        while i < len(pdu):
            t, v, i = _read_tlv(pdu, i)
            p.append((t, v))
        vbl = p[-1][1]  # varbind list
        i = 0
        while i < len(vbl):
            _t, vb, i = _read_tlv(vbl, i)
            j = 0
            _ot, oid_v, j = _read_tlv(vb, j)
            vt, val_v, j = _read_tlv(vb, j)
            oid = _decode_oid(oid_v)
            if vt == 0x04:  # OCTET STRING
                out[oid] = val_v.decode("utf-8", "replace").strip()
            elif vt in (0x05, 0x80, 0x81, 0x82):  # NULL / noSuchObject/Instance/endOfMib
                continue
        return out
    except (IndexError, ValueError):
        return out


def snmp_get(ip: str, oids: list[str], community: str = "public", timeout: float = 1.5) -> dict[str, str]:
    """Send one SNMP v2c GET to `ip:161` and return {oid: value} ({} on failure)."""
    if ":" in ip:  # IPv4 only here
        return {}
    pkt = build_get(community, oids)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(pkt, (ip, 161))
            data, _ = sock.recvfrom(4096)
    except OSError:
        return {}
    return parse_response(data)


def sysinfo(ip: str, community: str = "public", timeout: float = 1.5) -> dict:
    """Return {"name", "descr"} from SNMP sysName/sysDescr ({} if unreachable)."""
    vals = snmp_get(ip, [SYS_NAME, SYS_DESCR], community, timeout)
    name = vals.get(SYS_NAME, "")
    descr = vals.get(SYS_DESCR, "")
    out = {}
    if name:
        out["name"] = name
    if descr:
        out["descr"] = descr
    return out
