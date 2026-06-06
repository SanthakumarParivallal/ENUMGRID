"""test_cloudscan.py — AWS response parsers (no boto3/network)."""

from __future__ import annotations

import cloudscan


def test_parse_ec2_flattens_and_tags():
    reservations = [{
        "Instances": [{
            "InstanceId": "i-123", "InstanceType": "t3.micro",
            "State": {"Name": "running"},
            "PublicIpAddress": "1.2.3.4", "PrivateIpAddress": "10.0.0.5",
            "Placement": {"AvailabilityZone": "us-east-1a"},
            "Tags": [{"Key": "Name", "Value": "web-1"}],
        }]
    }]
    out = cloudscan.parse_ec2(reservations)
    assert out[0]["id"] == "i-123" and out[0]["name"] == "web-1"
    assert out[0]["public_ip"] == "1.2.3.4" and out[0]["state"] == "running"


def test_open_sg_findings_flags_world_ingress():
    sgs = [{
        "GroupId": "sg-1", "GroupName": "web",
        "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
             "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80,
             "IpRanges": [{"CidrIp": "10.0.0.0/8"}]},  # internal — not flagged
        ],
    }]
    out = cloudscan.open_sg_findings(sgs)
    assert len(out) == 1
    assert out[0]["severity"] == "high" and "22" in out[0]["detail"]


def test_public_buckets_detected():
    acls = [
        ("secret", {"Grants": [{"Grantee": {"URI": "x"}}]}),
        ("open", {"Grants": [{"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}}]}),
    ]
    out = cloudscan.public_buckets(acls)
    assert len(out) == 1 and out[0]["bucket"] == "open"


def test_inventory_without_boto3_is_clean(monkeypatch):
    monkeypatch.setattr(cloudscan, "_HAVE_BOTO3", False)
    r = cloudscan.aws_inventory()
    assert r["ok"] is False and "boto3" in r["error"]
