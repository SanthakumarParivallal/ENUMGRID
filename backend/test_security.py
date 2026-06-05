"""
test_security.py — the web API's authorization guardrails.

These assert that the FastAPI backend enforces the *same* scope policy as the
CLI (the project's headline safety requirement), so the dashboard can never be
pointed at loopback / multicast / broadcast / reserved / public space or be used
to inject extra nmap flags.
"""

from __future__ import annotations

import pytest
import security


def _rejects(target: str) -> bool:
    try:
        security.vet_target(target)
        return False
    except security.ScopeRejected:
        return True


# --- forbidden / protected space is refused (parity with the CLI) ---------- #
@pytest.mark.parametrize(
    "target",
    [
        "127.0.0.1",          # loopback
        "127.0.0.0/8",        # loopback network
        "224.0.0.1",          # multicast
        "239.255.255.250",    # multicast (SSDP)
        "255.255.255.255",    # limited broadcast
        "169.254.10.10",      # link-local
        "0.0.0.0",            # unspecified
    ],
)
def test_protected_space_is_refused(target):
    assert _rejects(target), f"{target} must be refused"


# --- flag / command injection is refused ----------------------------------- #
@pytest.mark.parametrize("target", ["-oG", "-sV", "1.2.3.4;rm", "a b", "--script=evil"])
def test_injection_is_refused(target):
    assert _rejects(target)


# --- public space is refused unless explicitly allowed --------------------- #
def test_public_refused_by_default():
    # Default policy (ALLOW_PUBLIC false) must refuse internet-routable targets.
    assert security.ALLOW_PUBLIC is False
    assert _rejects("8.8.8.8")
    assert _rejects("1.1.1.0/30")


def test_public_allowed_when_opted_in(monkeypatch):
    monkeypatch.setattr(security, "ALLOW_PUBLIC", True)
    # Now a public host passes scope (still subject to char/forbidden checks).
    security.vet_target("8.8.8.8")  # should not raise


# --- private space is permitted -------------------------------------------- #
@pytest.mark.parametrize("target", ["192.168.0.0/24", "10.0.0.5", "172.16.3.0/28"])
def test_private_space_is_allowed(target):
    security.vet_target(target)  # should not raise


# --- oversized scopes are capped ------------------------------------------- #
def test_oversized_scope_is_refused():
    assert _rejects("10.0.0.0/8")  # ~16M hosts >> cap


# --- token gate ------------------------------------------------------------ #
def test_token_disabled_allows_all(monkeypatch):
    monkeypatch.setattr(security, "API_TOKEN", None)
    assert security.token_ok(None, None) is True


def test_token_enabled_checks_query_and_header(monkeypatch):
    monkeypatch.setattr(security, "API_TOKEN", "s3cret")
    assert security.token_ok("s3cret", None) is True            # ?token=
    assert security.token_ok(None, "Bearer s3cret") is True     # header
    assert security.token_ok(None, "bearer s3cret") is True     # case-insensitive scheme
    assert security.token_ok("nope", None) is False
    assert security.token_ok(None, None) is False
    assert security.token_ok(None, "Basic s3cret") is False     # wrong scheme
