"""
test_osfp.py — TTL → OS-family mapping (the unprivileged OS signal).

The live ping is not unit-tested (needs a host); this pins the bucketing and the
"ambiguous/none -> empty" contract so the UI never shows a fabricated OS.
"""

from __future__ import annotations

import types

import osfp
import pytest
from osfp import os_from_ttl, refine_os


@pytest.mark.parametrize(
    "ttl,expected",
    [
        (64, "Linux / macOS / Unix"),
        (60, "Linux / macOS / Unix"),   # a few hops below 64
        (128, "Windows"),
        (120, "Windows"),
        (255, "Network device / IoT"),
        (250, "Network device / IoT"),
        (300, ""),   # above any real initial TTL (a byte maxes at 255) → honest empty
        (None, ""),
        (0, ""),
        (-1, ""),
    ],
)
def test_os_from_ttl(ttl, expected):
    assert os_from_ttl(ttl) == expected


# --- refine_os: sharpen the coarse TTL family with vendor/hostname/type ----- #
def test_refine_hostname_macbook_wins():
    out = refine_os("Linux / macOS / Unix", hostname="Santhas-MacBook-Air")
    assert out == "macOS (Apple)"


def test_refine_hostname_iphone():
    assert refine_os("Linux / macOS / Unix", hostname="someones-iPhone") == "iOS (Apple)"


def test_refine_apple_vendor_without_hostname():
    out = refine_os("Linux / macOS / Unix", vendor="Apple, Inc.")
    assert out == "macOS / iOS (Apple)"


def test_refine_apple_laptop_hostname_is_macos():
    # Apple makes no non-Mac computers, so an Apple-OUI "laptop" is a Mac.
    assert refine_os("Linux / macOS / Unix", vendor="Apple, Inc.", hostname="NISARGS-LAPTOP") == "macOS (Apple)"


def test_refine_android_vendor():
    assert refine_os("Linux / macOS / Unix", vendor="Samsung Electronics") == "Android"


def test_refine_router_device_type():
    out = refine_os("Network device / IoT", vendor="Sagemcom", device_type="Router / Gateway")
    assert out == "Router firmware (Linux)"


def test_refine_mikrotik_routeros():
    out = refine_os("Network device / IoT", vendor="MikroTik", device_type="Router / Gateway")
    assert out == "MikroTik RouterOS"
    # MikroTik's OUI is registered as "Routerboard.com" — must also map to RouterOS.
    assert refine_os("Linux / macOS / Unix", vendor="Routerboard.com",
                     device_type="Router / Gateway") == "MikroTik RouterOS"
    assert refine_os("Linux / macOS / Unix", vendor="Fortinet Inc",
                     device_type="Router / Gateway") == "FortiOS"


def test_refine_printer():
    assert refine_os("Network device / IoT", device_type="Printer") == "Printer firmware"


def test_refine_media_tv():
    out = refine_os("Linux / macOS / Unix", device_type="Media / TV")
    assert out == "Smart TV OS (Linux-based)"


def test_refine_windows_stays_windows():
    assert refine_os("Windows", vendor="Dell Inc.") == "Windows"


def test_refine_windows_hostname():
    # A Windows "DESKTOP-…" / "W11N-…" name is a strong Windows signal even if the
    # TTL family came back as the generic 64-bucket.
    assert refine_os("Linux / macOS / Unix", hostname="DESKTOP-SC8BRDS") == "Windows"
    assert refine_os("Linux / macOS / Unix", hostname="W11N-ITR34321") == "Windows"


def test_refine_random_mac_does_not_fake_mobile_os():
    # "Phone / Laptop" is the randomized-MAC fallback (no real vendor/hostname).
    # We must report only the honest TTL family — never a fabricated "Android / iOS".
    assert refine_os("Linux / macOS / Unix", vendor="(private/random)",
                     device_type="Phone / Laptop") == "Linux / macOS / Unix"
    assert refine_os("Windows", vendor="(private/random)",
                     device_type="Phone / Laptop") == "Windows"
    # No TTL reply at all → honestly unknown (empty), not a guess.
    assert refine_os("", vendor="(private/random)", device_type="Phone / Laptop") == ""


def test_refine_no_signal_keeps_family():
    # No vendor/hostname/type → unchanged honest family (never degraded).
    assert refine_os("Linux / macOS / Unix") == "Linux / macOS / Unix"


def test_refine_empty_family_with_apple_type():
    # Even with no TTL reply, a known Apple device still gets a label.
    assert refine_os("", device_type="Apple device") == "macOS / iOS (Apple)"


# --- ping command + TTL probe (subprocess mocked) --------------------------- #
def test_ping_command_per_platform(monkeypatch):
    monkeypatch.setattr(osfp.platform, "system", lambda: "Windows")
    assert osfp._ping_command("1.2.3.4", 2.0)[:2] == ["ping", "-n"]
    monkeypatch.setattr(osfp.platform, "system", lambda: "Darwin")
    assert "-t" in osfp._ping_command("1.2.3.4", 2.0)
    monkeypatch.setattr(osfp.platform, "system", lambda: "Linux")
    assert "-W" in osfp._ping_command("1.2.3.4", 2.0)


def test_ping_ttl_parses_reply(monkeypatch):
    monkeypatch.setattr(osfp.subprocess, "run",
                        lambda *a, **k: types.SimpleNamespace(stdout="64 bytes from x: ttl=57 time=1 ms"))
    assert osfp.ping_ttl("1.2.3.4") == 57


def test_ping_ttl_no_ttl_or_error(monkeypatch):
    monkeypatch.setattr(osfp.subprocess, "run",
                        lambda *a, **k: types.SimpleNamespace(stdout="Request timed out"))
    assert osfp.ping_ttl("1.2.3.4") is None                 # no TTL in output

    def _boom(*a, **k):
        raise OSError("ping missing")

    monkeypatch.setattr(osfp.subprocess, "run", _boom)
    assert osfp.ping_ttl("1.2.3.4") is None                 # subprocess failure → None


def test_os_hint_maps_ttl(monkeypatch):
    monkeypatch.setattr(osfp, "ping_ttl", lambda ip, timeout_s=2.0: 128)
    assert osfp.os_hint("1.2.3.4") == "Windows"


# --- direct helper + remaining refine branches ------------------------------ #
def test_apple_os_from_hostname_direct():
    assert osfp._apple_os_from_hostname("my-iPhone") == "iOS (Apple)"
    assert osfp._apple_os_from_hostname("work-iPad") == "iPadOS (Apple)"
    assert osfp._apple_os_from_hostname("MacBookPro") == "macOS (Apple)"
    assert osfp._apple_os_from_hostname("mystery-box") == "macOS / iOS (Apple)"


def test_refine_firewall_families():
    for vendor, expected in (("SonicWall Inc", "SonicOS"),
                             ("Palo Alto Networks", "PAN-OS"),
                             ("Sophos Ltd", "Sophos Firewall OS")):
        assert refine_os("Network device / IoT", vendor=vendor,
                         device_type="Router / Gateway") == expected


def test_refine_embedded_device_types():
    assert refine_os("", device_type="Camera") == "Embedded Linux (camera)"
    assert refine_os("", device_type="IoT / Embedded") == "Embedded / RTOS"
    assert refine_os("", device_type="NAS / Storage") == "Linux (NAS)"
