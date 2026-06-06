"""
cloudscan.py — AWS cloud asset discovery (real, credential-gated).

The LAN is only half the attack surface; the other half is cloud. This module
inventories AWS the way EnumGrid inventories a subnet: live EC2 instances (with
public IPs), security groups open to the world (0.0.0.0/0), and public S3
buckets. It uses `boto3` (optional dependency) with your standard AWS credential
chain (env vars / shared config / IAM role) — nothing is hardcoded.

The pure response parsers are fully unit-tested; the live AWS calls are
best-effort and only run when boto3 + credentials are present. Read-only:
Describe/List calls only, never any mutation. Authorized use only — your own
accounts.
"""

from __future__ import annotations

try:
    import boto3

    _HAVE_BOTO3 = True
except Exception:  # pragma: no cover - optional dependency
    _HAVE_BOTO3 = False


def available() -> bool:
    """True if boto3 is installed (AWS discovery is possible)."""
    return _HAVE_BOTO3


def parse_ec2(reservations: list[dict]) -> list[dict]:
    """Flatten `describe_instances` reservations → asset rows."""
    assets: list[dict] = []
    for res in reservations or []:
        for inst in res.get("Instances", []):
            name = ""
            for tag in inst.get("Tags", []) or []:
                if tag.get("Key") == "Name":
                    name = tag.get("Value", "")
            assets.append({
                "type": "ec2",
                "id": inst.get("InstanceId", ""),
                "name": name,
                "state": (inst.get("State") or {}).get("Name", ""),
                "instance_type": inst.get("InstanceType", ""),
                "public_ip": inst.get("PublicIpAddress", ""),
                "private_ip": inst.get("PrivateIpAddress", ""),
                "az": (inst.get("Placement") or {}).get("AvailabilityZone", ""),
            })
    return assets


def open_sg_findings(security_groups: list[dict]) -> list[dict]:
    """Security groups with ingress open to 0.0.0.0/0 → findings."""
    out: list[dict] = []
    for sg in security_groups or []:
        for perm in sg.get("IpPermissions", []) or []:
            world = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", []) or [])
            if not world:
                continue
            frm, to = perm.get("FromPort"), perm.get("ToPort")
            proto = perm.get("IpProtocol", "?")
            port = "all" if frm is None else (str(frm) if frm == to else f"{frm}-{to}")
            out.append({
                "type": "aws-open-sg",
                "group_id": sg.get("GroupId", ""),
                "group_name": sg.get("GroupName", ""),
                "detail": f"{proto}/{port} open to 0.0.0.0/0",
                "severity": "high" if proto == "-1" or port in ("all", "22", "3389") else "medium",
            })
    return out


def public_buckets(acl_results: list[tuple[str, dict]]) -> list[dict]:
    """[(bucket, get_bucket_acl response)] → buckets granting public access."""
    out: list[dict] = []
    public_uri = "http://acs.amazonaws.com/groups/global/AllUsers"
    for bucket, acl in acl_results or []:
        for grant in (acl or {}).get("Grants", []):
            if (grant.get("Grantee") or {}).get("URI") == public_uri:
                out.append({"type": "aws-public-s3", "bucket": bucket,
                            "detail": "S3 bucket grants access to AllUsers", "severity": "high"})
                break
    return out


def aws_inventory(region: str | None = None) -> dict:
    """Live AWS inventory (EC2 + open SGs + public S3). Best-effort, read-only."""
    if not _HAVE_BOTO3:
        return {"ok": False, "error": "boto3 not installed (pip install boto3)"}
    try:
        ec2 = boto3.client("ec2", region_name=region)
        instances = parse_ec2(ec2.describe_instances().get("Reservations", []))
        sg_findings = open_sg_findings(ec2.describe_security_groups().get("SecurityGroups", []))
        s3 = boto3.client("s3")
        acls = []
        for b in s3.list_buckets().get("Buckets", []):
            name = b.get("Name", "")
            try:
                acls.append((name, s3.get_bucket_acl(Bucket=name)))
            except Exception:  # noqa: BLE001 - per-bucket permission errors are fine
                continue
        bucket_findings = public_buckets(acls)
    except Exception as exc:  # noqa: BLE001 - surface a clean reason (creds/network)
        return {"ok": False, "error": f"AWS query failed ({type(exc).__name__})"}
    return {
        "ok": True,
        "assets": instances,
        "findings": sg_findings + bucket_findings,
    }
