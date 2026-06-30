"""test_rbac.py — role-based access (admin vs viewer vs open dev mode).

Uses monkeypatch.setattr on the module-level token vars (auto-restored) rather
than reloading the module, so it never pollutes shared state for other tests.
"""

from __future__ import annotations

import security


def _set(monkeypatch, admin=None, viewer=None, api=None):
    monkeypatch.setattr(security, "ADMIN_TOKEN", admin)
    monkeypatch.setattr(security, "VIEWER_TOKEN", viewer)
    monkeypatch.setattr(security, "API_TOKEN", api)


def test_open_when_no_tokens(monkeypatch):
    _set(monkeypatch)  # nothing configured → zero-config dev → full access
    assert security.role_for(None, None) == "admin"
    assert security.token_ok(None, None) and security.admin_ok(None, None)


def test_admin_token_grants_admin_only(monkeypatch):
    _set(monkeypatch, admin="secret")
    assert security.admin_ok("secret", None) is True
    assert security.admin_ok("wrong", None) is False
    assert security.token_ok(None, None) is False     # no token → unauthorized


def test_viewer_can_read_not_write(monkeypatch):
    _set(monkeypatch, admin="a", viewer="v")
    assert security.role_for("v", None) == "viewer"
    assert security.token_ok("v", None) is True       # read OK
    assert security.admin_ok("v", None) is False      # cannot scan
    assert security.admin_ok("a", None) is True


def test_bearer_header_accepted(monkeypatch):
    _set(monkeypatch, admin="abc")
    assert security.admin_ok(None, "Bearer abc") is True
    assert security.admin_ok(None, "Bearer nope") is False


def test_legacy_api_token_is_admin(monkeypatch):
    _set(monkeypatch, api="legacy")  # ENUMGRID_API_TOKEN counts as admin
    assert security.admin_ok("legacy", None) is True
    assert security.admin_ok(None, None) is False


# --- open-mode locality guard (anti LAN-exposure / DNS-rebinding) ----------- #
def test_open_mode_detection(monkeypatch):
    _set(monkeypatch)
    assert security.open_mode() is True
    _set(monkeypatch, admin="x")
    assert security.open_mode() is False
    _set(monkeypatch, viewer="v")
    assert security.open_mode() is False


def test_client_is_local():
    for ok in ("127.0.0.1", "::1", "localhost", "127.5.6.7", "testclient"):
        assert security.client_is_local(ok) is True, ok
    for bad in ("192.168.0.10", "10.0.0.5", "8.8.8.8", "", None, "evil.com"):
        assert security.client_is_local(bad) is False, bad


def test_host_header_local():
    for ok in ("localhost", "127.0.0.1", "127.0.0.1:8011", "[::1]:8011", "localhost:5173", None):
        assert security.host_header_local(ok) is True, ok
    for bad in ("evil.com", "evil.com:8011", "10.0.0.5:8011", "attacker.example"):
        assert security.host_header_local(bad) is False, bad
