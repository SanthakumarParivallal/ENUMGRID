"""
passive.py — zero-packet ("passive") host discovery.

Every other discovery path in ENUMGRID is *active*: it sends a probe (ICMP, TCP,
ARP request, mDNS query) and waits for a reply. This module is the opposite — it
sends **nothing**. It listens for the broadcast/multicast chatter hosts emit on
their own (ARP announcements, DHCP, mDNS/Bonjour, LLMNR, NetBIOS) and records who
is talking. That makes it stealthy (invisible to an IDS watching for scans) and a
clean research contrast: *active coverage vs passive coverage vs noise*.

Design
------
* The aggregation + classification core (`PassiveMonitor`, `method_for_ports`,
  `_valid_ip`, `_valid_iface`) is pure Python and fully unit-tested — no scapy,
  no root, no network.
* The actual capture (`discover_passive`) uses scapy, which is an *optional*
  dependency and needs raw-socket/BPF privilege. When either is missing we return
  ``available: False`` with an honest reason — we never fabricate hosts.

Run standalone (needs sudo + `pip install scapy`):

    sudo ../.venv/bin/python passive.py --seconds 20 --iface en0

Or via the API:  POST /api/passive?seconds=20  (admin-gated).
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone

try:  # scapy is optional (raw-socket capture); gate on it like ldap3/boto3.
    from scapy.all import ARP, DHCP, IP, UDP, Ether, sniff  # type: ignore

    _HAVE_SCAPY = True
except Exception:  # noqa: BLE001  # pragma: no cover - optional dependency; import/link error means unavailable
    _HAVE_SCAPY = False

# UDP ports whose mere presence names the discovery protocol (host is live).
_UDP_METHODS = {5353: "mDNS", 5355: "LLMNR", 137: "NBNS", 67: "DHCP", 68: "DHCP"}

# Only broadcast/multicast discovery traffic — keeps capture tiny and on-topic.
BPF_FILTER = "arp or (udp and (port 5353 or port 5355 or port 137 or port 67 or port 68))"

_IFACE_RE = re.compile(r"^[A-Za-z0-9_.:\-]{1,32}$")
_MAX_SECONDS = 300


def _unavailable(reason: str) -> dict:
    """The standard 'no result' payload — used for every honest failure path."""
    return {"available": False, "reason": reason, "seconds": 0, "hosts": [], "count": 0}


def _valid_ip(value: str | None) -> bool:
    try:
        ipaddress.ip_address(str(value))
        return True
    except (ValueError, TypeError):
        return False


def _valid_iface(iface: str | None) -> bool:
    """None (auto-select) is fine; otherwise a conservative interface-name shape."""
    return iface is None or bool(_IFACE_RE.match(iface))


def _norm_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    mac = mac.strip().lower()
    return mac if re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", mac) else None


def method_for_ports(sport, dport) -> str | None:
    """Name the discovery protocol implied by a UDP port pair, else None."""
    for port in (dport, sport):
        try:
            name = _UDP_METHODS.get(int(port))
        except (TypeError, ValueError):
            name = None
        if name:
            return name
    return None


def _ip_key(ip: str):
    try:
        return (0, ipaddress.ip_address(ip).version, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, 0, 0)


class PassiveMonitor:
    """Accumulates observed hosts from passive traffic. Pure, deterministic."""

    def __init__(self) -> None:
        self._hosts: dict[str, dict] = {}

    def observe(self, ip: str | None, *, mac: str | None = None,
                method: str | None = None, hostname: str | None = None,
                now: str | None = None) -> None:
        if not _valid_ip(ip):
            return
        rec = self._hosts.setdefault(
            ip, {"mac": None, "methods": set(), "hostname": None, "packets": 0, "last_seen": None},
        )
        rec["packets"] += 1
        if mac:
            rec["mac"] = mac
        if method:
            rec["methods"].add(method)
        if hostname:
            rec["hostname"] = hostname
        rec["last_seen"] = now or datetime.now(timezone.utc).isoformat()

    def snapshot(self) -> list[dict]:
        out = []
        for ip in sorted(self._hosts, key=_ip_key):
            rec = self._hosts[ip]
            out.append({
                "ip": ip,
                "mac": rec["mac"],
                "methods": sorted(rec["methods"]),
                "hostname": rec["hostname"],
                "packets": rec["packets"],
                "last_seen": rec["last_seen"],
            })
        return out


def _handle_packet(monitor: PassiveMonitor, pkt) -> None:
    """Extract (ip, mac, method) from one sniffed packet → monitor. Best-effort."""
    try:
        if ARP in pkt:  # who-has (op 1) or is-at (op 2): the sender is live
            arp = pkt[ARP]
            if arp.op in (1, 2) and _valid_ip(arp.psrc):
                monitor.observe(arp.psrc, mac=_norm_mac(arp.hwsrc), method="ARP")
            return
        if IP in pkt and UDP in pkt:
            method = method_for_ports(pkt[UDP].sport, pkt[UDP].dport)
            if method:
                mac = _norm_mac(pkt[Ether].src) if Ether in pkt else None
                hostname = _dhcp_hostname(pkt) if method == "DHCP" else None
                monitor.observe(pkt[IP].src, mac=mac, method=method, hostname=hostname)
    except Exception:  # noqa: BLE001 - a malformed packet must never crash the sniffer
        pass


def _dhcp_hostname(pkt) -> str | None:
    """The DHCP 'hostname' option (12), if the client advertised one."""
    try:
        for opt in pkt[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == "hostname":
                value = opt[1]
                return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
    except Exception:  # noqa: BLE001
        pass
    return None


def discover_passive(seconds: int = 15, iface: str | None = None) -> dict:
    """Listen passively for ``seconds`` and report the hosts that announced
    themselves. Sends nothing on the wire. Honest about what it can/can't do."""
    seconds = max(1, min(int(seconds), _MAX_SECONDS))
    if not _valid_iface(iface):
        return _unavailable("invalid interface name")
    if not _HAVE_SCAPY:
        return _unavailable("scapy not installed (pip install scapy)")
    monitor = PassiveMonitor()
    try:
        sniff(prn=lambda p: _handle_packet(monitor, p),
              filter=BPF_FILTER, store=False, timeout=seconds, iface=iface)
    except PermissionError:
        return _unavailable("raw-socket capture needs root / BPF access")
    except Exception as exc:  # noqa: BLE001 - scapy raises its own Scapy_Exception (not
        # OSError) on BPF / permission / interface errors; any capture failure must
        # degrade to an honest "unavailable", never crash the caller.
        reason = " ".join(str(exc).split()).strip() or type(exc).__name__
        low = reason.lower()
        if any(word in low for word in ("permission", "bpf", "root", "sudo")):
            reason = "raw-socket capture needs root / BPF access"
        return _unavailable(reason[:200])
    hosts = monitor.snapshot()
    return {"available": True, "reason": None, "seconds": seconds, "hosts": hosts, "count": len(hosts)}


def _main(argv: list[str] | None = None) -> int:
    import argparse
    import json
    import sys

    ap = argparse.ArgumentParser(description="Passive (zero-packet) host discovery")
    ap.add_argument("--seconds", type=int, default=15, help="listen window (1-300)")
    ap.add_argument("--iface", default=None, help="capture interface (default: scapy auto)")
    args = ap.parse_args(argv)
    result = discover_passive(args.seconds, args.iface)
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")
    if not result["available"]:
        print(f"passive discovery unavailable: {result['reason']}", file=sys.stderr)
    return 0 if result["available"] else 1


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint; _main() is unit-tested
    raise SystemExit(_main())
