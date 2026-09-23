"""test_smbscan.py: authenticated SMB helpers + live path (fake smbclient, no network).

The pure helpers (type labels, admin-share detection, credential splitting, share
shaping, nmap-output parsing) are tested directly. The live `enumerate_shares`
path is exercised by injecting a fake `smbclient` module and flipping
`_HAVE_SMB`, exactly as `test_adscan.py` tests the LDAP path with a fake ldap3,
so no SMB server or `smbprotocol` install is required.
"""

from __future__ import annotations

import smbscan


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #
def test_share_type_label_bases_and_flags():
    assert smbscan.share_type_label(0) == "disk"
    assert smbscan.share_type_label(1) == "print"
    assert smbscan.share_type_label(2) == "device"
    assert smbscan.share_type_label(3) == "ipc"
    assert smbscan.share_type_label(0x80000000) == "disk (admin)"
    assert smbscan.share_type_label(0x80000003) == "ipc (admin)"
    assert smbscan.share_type_label(0x40000000) == "disk (temporary)"
    assert smbscan.share_type_label(0xC0000000) == "disk (admin, temporary)"
    assert smbscan.share_type_label(99) == "unknown"  # base 99 is not a known type
    assert smbscan.share_type_label("bad") == "unknown"


def test_is_admin_share():
    assert smbscan.is_admin_share("C$")
    assert smbscan.is_admin_share("ADMIN$")
    assert smbscan.is_admin_share("IPC$")
    assert not smbscan.is_admin_share("Public")
    assert not smbscan.is_admin_share("")


def test_split_credential_forms():
    assert smbscan.split_credential("CORP\\alice") == ("CORP", "alice")
    assert smbscan.split_credential("alice@corp.local") == ("corp.local", "alice")
    assert smbscan.split_credential("alice", domain="CORP") == ("CORP", "alice")
    # A fully-qualified username is never re-homed by the domain argument.
    assert smbscan.split_credential("CORP\\alice", domain="OTHER") == ("CORP", "alice")
    assert smbscan.split_credential("bob") == ("", "bob")
    assert smbscan.split_credential("") == ("", "")


def test_shape_shares_normalises_and_drops_nameless():
    rows = smbscan.shape_shares([
        {"name": "C$", "type": 0x80000000, "comment": "Default share"},
        {"name": "Public", "type": 0, "access": "READ"},
        {"name": "", "type": 0},              # dropped: no name
        {"name": "  Docs  ", "comment": ""},   # trimmed, no type
        None,                                   # ignored: not a dict-ish entry
    ])
    assert [r["name"] for r in rows] == ["C$", "Public", "Docs"]
    assert rows[0] == {"name": "C$", "comment": "Default share", "admin": True,
                       "type_label": "disk (admin)"}
    assert rows[1]["access"] == "READ" and rows[1]["admin"] is False
    assert "type_label" not in rows[2]  # no 'type' key → no label


def test_shape_shares_empty():
    assert smbscan.shape_shares([]) == []
    assert smbscan.shape_shares(None) == []


def test_parse_nmap_smb_shares():
    sample = r"""
  \\10.0.0.5\ADMIN$:
    Type: STYPE_DISKTREE_HIDDEN
    Comment: Remote Admin
    Current user access: <none>
  \\10.0.0.5\C$:
    Type: STYPE_DISKTREE_HIDDEN
    Current user access: READ/WRITE
  \\10.0.0.5\Public:
    Current user access: READ
"""
    parsed = smbscan.parse_nmap_smb_shares(sample)
    assert [p["name"] for p in parsed] == ["ADMIN$", "C$", "Public"]
    acc = {p["name"]: p.get("access") for p in parsed}
    assert acc["C$"] == "READ/WRITE"
    assert acc["Public"] == "READ"
    assert acc["ADMIN$"] == "<none>"
    assert parsed[0]["admin"] is True and parsed[2]["admin"] is False


def test_parse_nmap_smb_shares_empty_and_accessless():
    assert smbscan.parse_nmap_smb_shares("") == []
    assert smbscan.parse_nmap_smb_shares(None) == []
    # A share with no access line still yields the name (no crash on the branch
    # where `current` is None before the first share, and no access match).
    out = smbscan.parse_nmap_smb_shares("random preamble line\n  \\\\h\\Share:\n    Type: x")
    assert out == [{"name": "Share", "comment": "", "admin": False}]


# --------------------------------------------------------------------------- #
# available()
# --------------------------------------------------------------------------- #
def test_available_reflects_flag(monkeypatch):
    monkeypatch.setattr(smbscan, "_HAVE_SMB", True)
    assert smbscan.available() is True
    monkeypatch.setattr(smbscan, "_HAVE_SMB", False)
    assert smbscan.available() is False


# --------------------------------------------------------------------------- #
# Live path: fake smbclient, no network
# --------------------------------------------------------------------------- #
class _FakeSmb:
    """A stand-in `smbclient`: listdir behaviour is scripted per share name."""

    def __init__(self, listing=None, connect_error=None, delete_error=False):
        self._listing = listing or {}
        self._connect_error = connect_error
        self._delete_error = delete_error
        self.registered = None
        self.deleted = False

    def register_session(self, host, username=None, password=None, port=445,
                         connection_timeout=8):
        if self._connect_error:
            raise self._connect_error
        self.registered = {"host": host, "username": username, "port": port}

    def listdir(self, unc):
        share = unc.rstrip("\\").split("\\")[-1]
        behaviour = self._listing.get(share, PermissionError("denied"))
        if isinstance(behaviour, Exception):
            raise behaviour
        return behaviour  # a list of entries

    def delete_session(self, host, port=445):
        if self._delete_error:
            raise RuntimeError("cannot delete")
        self.deleted = True


def test_enumerate_without_smbprotocol_is_clean(monkeypatch):
    monkeypatch.setattr(smbscan, "_HAVE_SMB", False)
    r = smbscan.enumerate_shares("192.168.0.5", "alice", "pw", domain="CORP")
    assert r["ok"] is False and "smbprotocol" in r["error"]


def test_enumerate_session_failure_is_clean(monkeypatch):
    fake = _FakeSmb(connect_error=OSError("connection refused"))
    monkeypatch.setattr(smbscan, "_HAVE_SMB", True)
    monkeypatch.setattr(smbscan, "smbclient", fake)
    r = smbscan.enumerate_shares("192.168.0.5", "alice", "pw")
    assert r["ok"] is False and "SMB session failed" in r["error"]
    assert "OSError" in r["error"]


def test_enumerate_classifies_access(monkeypatch):
    fake = _FakeSmb(listing={
        "C$": ["Windows", "Users", "Program Files"],  # READ (3 entries)
        "ADMIN$": PermissionError("nope"),             # DENIED
        "IPC$": RuntimeError("not a disk share"),      # ERROR
    })
    monkeypatch.setattr(smbscan, "_HAVE_SMB", True)
    monkeypatch.setattr(smbscan, "smbclient", fake)
    r = smbscan.enumerate_shares("192.168.0.5", "CORP\\alice", "pw")
    assert r["ok"] is True and r["host"] == "192.168.0.5"
    assert r["account"] == "CORP\\alice"        # domain\user, never the password
    assert r["method"] == "smb-credentialed"
    by = {s["name"]: s for s in r["shares"]}
    assert by["C$"]["access"] == "READ" and by["C$"]["entries"] == 3
    assert by["ADMIN$"]["access"] == "DENIED"
    assert by["IPC$"]["access"] == "ERROR"
    assert by["C$"]["admin"] is True
    # default share set was used
    assert set(by) == set(smbscan.DEFAULT_SHARES)
    assert fake.registered["username"] == "CORP\\alice"
    assert fake.deleted is True


def test_enumerate_custom_shares_and_no_domain(monkeypatch):
    fake = _FakeSmb(listing={"Data": ["report.xlsx"]})
    monkeypatch.setattr(smbscan, "_HAVE_SMB", True)
    monkeypatch.setattr(smbscan, "smbclient", fake)
    r = smbscan.enumerate_shares("192.168.0.5", "alice", "pw", shares=["Data", "  "])
    # Blank share entries are filtered out; no domain → bare account.
    assert [s["name"] for s in r["shares"]] == ["Data"]
    assert r["account"] == "alice"
    assert r["shares"][0]["access"] == "READ"


def test_enumerate_delete_session_error_is_swallowed(monkeypatch):
    fake = _FakeSmb(listing={"C$": []}, delete_error=True)
    monkeypatch.setattr(smbscan, "_HAVE_SMB", True)
    monkeypatch.setattr(smbscan, "smbclient", fake)
    # delete_session raising must not turn a good scan into a failure.
    r = smbscan.enumerate_shares("192.168.0.5", "alice", "pw", shares=["C$"])
    assert r["ok"] is True
    assert r["shares"][0]["access"] == "READ" and r["shares"][0]["entries"] == 0
