"""
test_campaign.py — multi-subnet aggregation (pure, no database).

Verifies cross-subnet totals, IP de-duplication across overlapping ranges,
device/service/severity rollups, and honest handling of an unscanned subnet.
"""

from __future__ import annotations

import campaign


def _host(ip, *, device_type=None, os=None, ports=None, vulns=None):
    return {"ip": ip, "device_type": device_type, "os": os,
            "ports": ports or [], "vulns": vulns or []}


def _port(port, service, state="open", vulns=None):
    return {"port": port, "service": service, "state": state, "vulns": vulns or []}


def test_aggregate_totals_and_rollups():
    subnets = [
        {"target": "192.168.0.0/24", "scanned_at": "t1", "snapshot": {"hosts": [
            _host("192.168.0.1", device_type="Router", ports=[_port(80, "http")]),
            _host("192.168.0.5", device_type="Server",
                  ports=[_port(22, "ssh"), _port(443, "https",
                                                 vulns=[{"severity": "high"}])]),
        ]}},
        {"target": "10.0.0.0/24", "scanned_at": "t2", "snapshot": {"hosts": [
            _host("10.0.0.9", device_type="Server", ports=[_port(22, "ssh")]),
        ]}},
    ]
    result = campaign.aggregate_campaign(subnets)
    assert result["totals"]["subnets"] == 2
    assert result["totals"]["scanned_subnets"] == 2
    assert result["totals"]["hosts"] == 3
    assert result["totals"]["open_ports"] == 4          # 1 + 2 + 1
    assert dict(result["device_mix"])["Server"] == 2
    assert dict(result["top_services"])["ssh"] == 2
    assert result["severity"]["high"] == 1
    # hosts are merged + IP-sorted (10.* before 192.* numerically)
    assert [h["ip"] for h in result["hosts"]] == ["10.0.0.9", "192.168.0.1", "192.168.0.5"]


def test_overlapping_ip_is_deduped_last_wins():
    subnets = [
        {"target": "192.168.0.0/24", "scanned_at": "t1",
         "snapshot": {"hosts": [_host("192.168.0.1", device_type="Router")]}},
        {"target": "192.168.0.0/25", "scanned_at": "t2",
         "snapshot": {"hosts": [_host("192.168.0.1", device_type="Firewall")]}},
    ]
    result = campaign.aggregate_campaign(subnets)
    assert result["totals"]["hosts"] == 1               # same IP counted once
    assert result["hosts"][0]["device_type"] == "Firewall"   # later subnet wins
    assert result["hosts"][0]["subnet"] == "192.168.0.0/25"


def test_unscanned_subnet_reported_honestly():
    subnets = [
        {"target": "192.168.0.0/24", "scanned_at": "t1",
         "snapshot": {"hosts": [_host("192.168.0.1")]}},
        {"target": "172.16.0.0/24", "scanned_at": None, "snapshot": None},
    ]
    result = campaign.aggregate_campaign(subnets)
    assert result["totals"]["scanned_subnets"] == 1
    unscanned = next(s for s in result["subnets"] if s["target"] == "172.16.0.0/24")
    assert unscanned["scanned"] is False and unscanned["hosts"] == 0


def test_empty_campaign_is_zeros_not_crash():
    result = campaign.aggregate_campaign([])
    assert result["totals"] == {"subnets": 0, "scanned_subnets": 0, "hosts": 0, "open_ports": 0}
    assert result["hosts"] == [] and result["subnets"] == []
    assert result["severity"] == {s: 0 for s in ("critical", "high", "medium", "low", "info")}


def test_only_open_ports_counted():
    subnets = [{"target": "192.168.0.0/24", "scanned_at": "t1", "snapshot": {"hosts": [
        _host("192.168.0.1", ports=[_port(80, "http"), _port(23, "telnet", state="closed")]),
    ]}}]
    result = campaign.aggregate_campaign(subnets)
    assert result["totals"]["open_ports"] == 1          # closed port excluded
    assert result["hosts"][0]["open_ports"] == 1
