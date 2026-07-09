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


def test_open_sg_findings_flags_ipv6_world_ingress():
    # A SG open to ::/0 (IPv6) is just as exposed as 0.0.0.0/0 and must be flagged.
    sgs = [{
        "GroupId": "sg-2", "GroupName": "api",
        "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389,
             "Ipv6Ranges": [{"CidrIpv6": "::/0"}]},
        ],
    }]
    out = cloudscan.open_sg_findings(sgs)
    assert len(out) == 1
    assert out[0]["severity"] == "high" and "::/0" in out[0]["detail"]


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


def test_available_reports_boto3(monkeypatch):
    monkeypatch.setattr(cloudscan, "_HAVE_BOTO3", True)
    assert cloudscan.available() is True


class _FakeEC2:
    def describe_instances(self):
        return {"Reservations": [{"Instances": [{
            "InstanceId": "i-123", "InstanceType": "t3.micro", "State": {"Name": "running"},
            "PublicIpAddress": "1.2.3.4", "Tags": [{"Key": "Name", "Value": "web-1"}],
        }]}]}

    def describe_security_groups(self):
        return {"SecurityGroups": [{"GroupId": "sg-1", "GroupName": "web", "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        ]}]}


class _FakeS3:
    _PUBLIC = "http://acs.amazonaws.com/groups/global/AllUsers"

    def list_buckets(self):
        return {"Buckets": [{"Name": "open"}, {"Name": "denied"}]}

    def get_bucket_acl(self, Bucket):
        if Bucket == "denied":
            raise RuntimeError("AccessDenied")          # per-bucket permission error → skipped
        return {"Grants": [{"Grantee": {"URI": self._PUBLIC}}]}


def test_aws_inventory_assembles_assets_and_findings(monkeypatch):
    monkeypatch.setattr(cloudscan, "_HAVE_BOTO3", True)
    monkeypatch.setattr(cloudscan.boto3, "client",
                        lambda svc, region_name=None: _FakeEC2() if svc == "ec2" else _FakeS3())
    r = cloudscan.aws_inventory("us-east-1")
    assert r["ok"] is True
    assert any(a["id"] == "i-123" for a in r["assets"])
    assert any(f["type"] == "aws-open-sg" for f in r["findings"])
    assert any(f["type"] == "aws-public-s3" and f["bucket"] == "open" for f in r["findings"])


def test_aws_inventory_reports_query_failure(monkeypatch):
    monkeypatch.setattr(cloudscan, "_HAVE_BOTO3", True)

    def _boom(*a, **k):
        raise RuntimeError("no credentials")

    monkeypatch.setattr(cloudscan.boto3, "client", _boom)
    r = cloudscan.aws_inventory()
    assert r["ok"] is False and "AWS query failed" in r["error"]
