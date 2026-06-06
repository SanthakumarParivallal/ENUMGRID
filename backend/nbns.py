"""
nbns.py — NetBIOS Name Service (NBNS) node-status name resolution.

Reverse-DNS and mDNS miss a whole class of devices — Windows PCs, many printers,
NAS boxes and IoT gear — that nonetheless answer a NetBIOS "node status" query on
UDP/137 with their own name (this is exactly what Angry IP Scanner / Fing use to
fill the name column). We send the standard wildcard NBSTAT request and parse the
unique workstation name from the reply.

Pure stdlib (sockets), best-effort, and bounded: any error or timeout just yields
no name for that host. Everything returned is the device's *own* announced name —
never inferred or invented.
"""

from __future__ import annotations

import socket
import struct
from concurrent.futures import ThreadPoolExecutor

NBNS_PORT = 137

# Node-status request for the wildcard name "*". The encoded question name is the
# first-level encoding of "*" + 15 NULs: 0x2A -> "CK", each 0x00 -> "AA".
_WILDCARD_ENCODED = b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  # 32 bytes


def _build_query() -> bytes:
    """Build an NBSTAT (node status) request packet for the wildcard name."""
    txn_id = 0x4247  # arbitrary, fixed — we don't multiplex
    header = struct.pack(
        ">HHHHHH",
        txn_id,   # transaction id
        0x0000,   # flags: standard query
        1,        # QDCOUNT
        0, 0, 0,  # ANCOUNT, NSCOUNT, ARCOUNT
    )
    question = (
        bytes([len(_WILDCARD_ENCODED)]) + _WILDCARD_ENCODED + b"\x00"  # encoded name
        + struct.pack(">HH", 0x0021, 0x0001)  # QTYPE=NBSTAT, QCLASS=IN
    )
    return header + question


def _skip_name(data: bytes, idx: int) -> int:
    """Advance past a length-prefixed NetBIOS name terminated by a 0x00 byte."""
    while idx < len(data) and data[idx] != 0:
        idx += data[idx] + 1
    return idx + 1  # step over the null terminator


def _parse_response(data: bytes) -> str | None:
    """Extract the device's unique NetBIOS name from a node-status reply."""
    try:
        if len(data) < 12:
            return None
        qdcount = struct.unpack(">H", data[4:6])[0]
        ancount = struct.unpack(">H", data[6:8])[0]
        if ancount < 1:
            return None
        idx = 12
        # Skip any echoed question records (real replies usually have QDCOUNT=0).
        for _ in range(qdcount):
            idx = _skip_name(data, idx) + 4  # name + QTYPE/QCLASS
        # Answer RR: NAME TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) then RDATA.
        idx = _skip_name(data, idx)
        idx += 2 + 2 + 4 + 2
        if idx >= len(data):
            return None
        num_names = data[idx]
        idx += 1
        for _ in range(num_names):
            if idx + 18 > len(data):
                break
            raw_name = data[idx : idx + 15]
            flags = struct.unpack(">H", data[idx + 16 : idx + 18])[0]
            idx += 18
            is_group = bool(flags & 0x8000)
            name = raw_name.decode("ascii", "ignore").strip().strip("\x00").strip()
            # The first unique (non-group) printable name is the machine name.
            if name and not is_group and name != "__MSBROWSE__":
                return name
    except (IndexError, struct.error, UnicodeDecodeError):
        return None
    return None


def nbns_name(ip: str, timeout_s: float = 1.0) -> str | None:
    """Return the NetBIOS name of `ip`, or None if it doesn't answer."""
    if ":" in ip:  # NBNS is IPv4-only
        return None
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout_s)
        sock.sendto(_build_query(), (ip, NBNS_PORT))
        data, _ = sock.recvfrom(2048)
    except OSError:
        return None
    finally:
        sock.close()
    return _parse_response(data)


def nbns_names(ips: list[str], timeout_s: float = 1.0, workers: int = 64) -> dict[str, str]:
    """Resolve NetBIOS names for many IPs in parallel ({ip: name} for responders)."""
    out: dict[str, str] = {}
    if not ips:
        return out
    with ThreadPoolExecutor(max_workers=min(workers, len(ips)), thread_name_prefix="nbns") as pool:
        for ip, name in zip(ips, pool.map(lambda i: nbns_name(i, timeout_s), ips)):
            if name:
                out[ip] = name
    return out
