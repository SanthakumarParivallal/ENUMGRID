"""
test_osfp.py — TTL → OS-family mapping (the unprivileged OS signal).

The live ping is not unit-tested (needs a host); this pins the bucketing and the
"ambiguous/none -> empty" contract so the UI never shows a fabricated OS.
"""

from __future__ import annotations

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


def test_refine_android_vendor():
    assert refine_os("Linux / macOS / Unix", vendor="Samsung Electronics") == "Android"


def test_refine_router_device_type():
    out = refine_os("Network device / IoT", vendor="Sagemcom", device_type="Router / Gateway")
    assert out == "Router firmware (Linux)"


def test_refine_mikrotik_routeros():
    out = refine_os("Network device / IoT", vendor="MikroTik", device_type="Router / Gateway")
    assert out == "MikroTik RouterOS"


def test_refine_printer():
    assert refine_os("Network device / IoT", device_type="Printer") == "Printer firmware"


def test_refine_media_tv():
    out = refine_os("Linux / macOS / Unix", device_type="Media / TV")
    assert out == "Smart TV OS (Linux-based)"


def test_refine_windows_stays_windows():
    assert refine_os("Windows", vendor="Dell Inc.") == "Windows"


def test_refine_no_signal_keeps_family():
    # No vendor/hostname/type → unchanged honest family (never degraded).
    assert refine_os("Linux / macOS / Unix") == "Linux / macOS / Unix"


def test_refine_empty_family_with_apple_type():
    # Even with no TTL reply, a known Apple device still gets a label.
    assert refine_os("", device_type="Apple device") == "macOS / iOS (Apple)"
