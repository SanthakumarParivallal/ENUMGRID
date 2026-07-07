"""
campaign.py — multi-subnet "campaign" aggregation.

A single scan covers one target. Real engagements span several — an office /24, a
server VLAN, a DMZ. This rolls the *latest* stored scan of each subnet into one
combined picture: total unique hosts, open ports, a merged inventory, and mixed
device/service/severity rollups across the whole estate.

Pure by construction: `aggregate_campaign` takes already-fetched snapshots and
returns the combined view, so it is fully unit-tested without a database. The API
layer just supplies each subnet's newest snapshot from history.
"""

from __future__ import annotations

import ipaddress
from collections import Counter

_SEV_ORDER = ("critical", "high", "medium", "low", "info")


def _ip_key(ip: str):
    try:
        addr = ipaddress.ip_address(ip)
        return (0, addr.version, int(addr))
    except (ValueError, TypeError):
        return (1, 0, 0)


def _open_ports(host: dict) -> list[dict]:
    return [p for p in (host.get("ports") or []) if str(p.get("state", "")).startswith("open")]


def _host_vulns(host: dict) -> list[dict]:
    """Every vuln attached to a host — at host level and per open port."""
    out = list(host.get("vulns") or [])
    for port in host.get("ports") or []:
        out.extend(port.get("vulns") or [])
    return out


def aggregate_campaign(subnets: list[dict]) -> dict:
    """Combine per-subnet snapshots into one campaign view.

    ``subnets`` is a list of ``{"target", "scanned_at", "snapshot"}``. ``snapshot``
    is ``None`` for a subnet that has never been scanned (reported honestly as
    ``scanned: false`` rather than as an empty result)."""
    per_subnet: list[dict] = []
    by_ip: dict[str, dict] = {}
    device_mix: Counter = Counter()
    service_mix: Counter = Counter()
    severity: Counter = Counter()
    total_open = 0
    scanned_subnets = 0

    for sub in subnets:
        target = sub.get("target")
        snapshot = sub.get("snapshot")
        scanned = snapshot is not None
        if scanned:
            scanned_subnets += 1
        hosts = (snapshot or {}).get("hosts") or []
        subnet_open = 0

        for host in hosts:
            opens = _open_ports(host)
            subnet_open += len(opens)
            ip = host.get("ip")
            if ip:
                by_ip[ip] = {   # last scan wins for an IP seen in overlapping ranges
                    "ip": ip,
                    "subnet": target,
                    "hostname": host.get("hostname"),
                    "vendor": host.get("vendor"),
                    "os": host.get("os"),
                    "device_type": host.get("device_type"),
                    "open_ports": len(opens),
                }
            if host.get("device_type"):
                device_mix[host["device_type"]] += 1
            for port in opens:
                if port.get("service"):
                    service_mix[port["service"]] += 1
            for vuln in _host_vulns(host):
                sev = str(vuln.get("severity", "")).lower()
                if sev in _SEV_ORDER:
                    severity[sev] += 1

        total_open += subnet_open
        per_subnet.append({
            "target": target,
            "scanned_at": sub.get("scanned_at"),
            "scanned": scanned,
            "hosts": len(hosts),
            "open_ports": subnet_open,
        })

    hosts_sorted = sorted(by_ip.values(), key=lambda h: _ip_key(h["ip"]))
    return {
        "totals": {
            "subnets": len(subnets),
            "scanned_subnets": scanned_subnets,
            "hosts": len(by_ip),
            "open_ports": total_open,
        },
        "subnets": per_subnet,
        "device_mix": device_mix.most_common(8),
        "top_services": service_mix.most_common(8),
        "severity": {sev: severity.get(sev, 0) for sev in _SEV_ORDER},
        "hosts": hosts_sorted,
    }
