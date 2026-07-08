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
        "0.0.0.0",            # unspecified  # nosec B104 - test data, not a bind addr
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


# --- policy-knob parsing --------------------------------------------------- #
def test_env_int_clamps_and_falls_back(monkeypatch):
    monkeypatch.setenv("ENUMGRID_TEST_INT", "not-a-number")
    assert security._env_int("ENUMGRID_TEST_INT", 7) == 7       # non-int → default
    monkeypatch.setenv("ENUMGRID_TEST_INT", "3")
    assert security._env_int("ENUMGRID_TEST_INT", 7) == 3       # parsed
    monkeypatch.setenv("ENUMGRID_TEST_INT", "0")
    assert security._env_int("ENUMGRID_TEST_INT", 7) == 1       # floored to >= 1


# --- concurrency slot (fork-bomb guard) ------------------------------------ #
def test_scan_slot_acquires_and_releases():
    import asyncio

    async def go():
        async with security.scan_slot() as ok:
            assert ok is True                                   # a free slot is granted
        # After release the semaphore is back to full capacity.
        return security.scan_semaphore._value

    value_after = asyncio.run(go())
    assert value_after == security.MAX_CONCURRENT_SCANS


def test_scan_slot_rejects_when_at_capacity(monkeypatch):
    import asyncio

    # No permits available → the slot must refuse fast (returns False) instead of
    # queueing an unbounded backlog of nmap processes.
    monkeypatch.setattr(security, "scan_semaphore", asyncio.Semaphore(0))

    async def go():
        async with security.scan_slot() as ok:
            return ok

    assert asyncio.run(go()) is False


# --- auth brute-force throttle (deterministic via injected `now`) ----------- #
def test_auth_failures_below_threshold_do_not_lock(monkeypatch):
    security.reset_auth_throttle()
    monkeypatch.setattr(security, "AUTH_MAX_FAILURES", 3)
    ip = "203.0.113.7"
    assert security.register_auth_failure(ip, now=0.0) is False
    assert security.register_auth_failure(ip, now=1.0) is False
    assert security.is_locked_out(ip, now=1.0) is False
    assert security.lockout_remaining(ip, now=1.0) == 0          # has failures but no lockout yet


def test_auth_failures_trip_lockout_at_threshold(monkeypatch):
    security.reset_auth_throttle()
    monkeypatch.setattr(security, "AUTH_MAX_FAILURES", 3)
    monkeypatch.setattr(security, "AUTH_LOCKOUT_S", 100)
    ip = "203.0.113.8"
    assert security.register_auth_failure(ip, now=0.0) is False
    assert security.register_auth_failure(ip, now=0.0) is False
    assert security.register_auth_failure(ip, now=0.0) is True    # the 3rd trips the lock
    assert security.is_locked_out(ip, now=1.0) is True
    assert security.lockout_remaining(ip, now=1.0) == 99


def test_lockout_expires_after_cooldown(monkeypatch):
    security.reset_auth_throttle()
    monkeypatch.setattr(security, "AUTH_MAX_FAILURES", 2)
    monkeypatch.setattr(security, "AUTH_LOCKOUT_S", 100)
    ip = "203.0.113.9"
    security.register_auth_failure(ip, now=0.0)
    security.register_auth_failure(ip, now=0.0)                   # locked until t=100
    assert security.is_locked_out(ip, now=50.0) is True
    assert security.is_locked_out(ip, now=100.0) is False         # cooldown elapsed → cleared
    assert security.lockout_remaining(ip, now=100.0) == 0


def test_old_failures_age_out_of_window(monkeypatch):
    security.reset_auth_throttle()
    monkeypatch.setattr(security, "AUTH_MAX_FAILURES", 3)
    monkeypatch.setattr(security, "AUTH_WINDOW_S", 100)
    ip = "203.0.113.10"
    security.register_auth_failure(ip, now=0.0)
    security.register_auth_failure(ip, now=1.0)
    # 200s later the first two are outside the window, so the count restarts.
    assert security.register_auth_failure(ip, now=200.0) is False
    assert security.register_auth_failure(ip, now=200.0) is False
    assert security.is_locked_out(ip, now=200.0) is False


def test_success_clears_failure_streak(monkeypatch):
    security.reset_auth_throttle()
    monkeypatch.setattr(security, "AUTH_MAX_FAILURES", 3)
    ip = "203.0.113.11"
    security.register_auth_failure(ip, now=0.0)
    security.register_auth_failure(ip, now=0.0)
    security.register_auth_success(ip)                            # valid auth wipes the streak
    assert security.register_auth_failure(ip, now=0.0) is False   # count restarts from 1
    assert security.is_locked_out(ip, now=0.0) is False


def test_throttle_ignores_empty_ip():
    security.reset_auth_throttle()
    assert security.register_auth_failure(None) is False
    assert security.is_locked_out(None) is False
    assert security.lockout_remaining(None) == 0
