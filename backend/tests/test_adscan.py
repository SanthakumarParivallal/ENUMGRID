"""test_adscan.py — AD/LDAP helpers + entry shaping (no ldap3/network)."""

from __future__ import annotations

import adscan


def test_base_dn_from_domain():
    assert adscan.base_dn_from_domain("corp.example.com") == "DC=corp,DC=example,DC=com"
    assert adscan.base_dn_from_domain("example.local") == "DC=example,DC=local"
    assert adscan.base_dn_from_domain("") == ""


def test_shape_computers():
    entries = [{"attributes": {
        "dNSHostName": "DC01.corp.local", "operatingSystem": "Windows Server 2022",
        "operatingSystemVersion": "10.0 (20348)", "lastLogonTimestamp": "133",
    }}]
    out = adscan.shape_computers(entries)
    assert out[0]["name"] == "DC01.corp.local"
    assert out[0]["os"] == "Windows Server 2022"


def test_shape_users_enabled_flag():
    entries = [
        {"attributes": {"sAMAccountName": "alice", "displayName": "Alice", "userAccountControl": 512}},
        {"attributes": {"sAMAccountName": "bob", "cn": "Bob", "userAccountControl": 514}},  # 0x2 disabled
    ]
    out = adscan.shape_users(entries)
    by_sam = {u["sam"]: u for u in out}
    assert by_sam["alice"]["enabled"] is True
    assert by_sam["bob"]["enabled"] is False


def test_is_enabled_handles_bad_input():
    assert adscan._is_enabled(None) is True       # unknown → assume enabled
    assert adscan._is_enabled("not-an-int") is True
    assert adscan._is_enabled(2) is False


def test_enumerate_without_ldap3_is_clean(monkeypatch):
    monkeypatch.setattr(adscan, "_HAVE_LDAP3", False)
    r = adscan.enumerate_domain("dc01", "corp.local", "user", "pass")
    assert r["ok"] is False and "ldap3" in r["error"]


def test_enumerate_rejects_bad_domain(monkeypatch):
    monkeypatch.setattr(adscan, "_HAVE_LDAP3", True)
    # base_dn empty → rejected before any bind attempt
    r = adscan.enumerate_domain("dc01", "", "user", "pass")
    assert r["ok"] is False and "domain" in r["error"]
