"""
test_fingerprint.py — device-type heuristic classification.

Pins the priority order (open ports > services > vendor > hostname) and the
"no signal -> empty string" contract so the UI never shows a guessed label
without evidence.
"""

from __future__ import annotations

import pytest
from fingerprint import guess_device_type


# --- open-port signatures (strongest) -------------------------------------- #
@pytest.mark.parametrize(
    "ports,expected",
    [
        ([9100], "Printer"),
        ([631, 80], "Printer"),
        ([554], "Camera"),
        ([32400], "Media / TV"),
        ([445, 139], "Computer"),
        ([53, 80, 443], "Router / Gateway"),
    ],
)
def test_port_signatures(ports, expected):
    assert guess_device_type(ports=ports) == expected


def test_ports_outrank_vendor():
    # A printer plugged in behind an "Intel" NIC is still a printer by its ports.
    assert guess_device_type(vendor="Intel", ports=[9100]) == "Printer"


# --- service names --------------------------------------------------------- #
def test_service_hint():
    assert guess_device_type(services=["rtsp"]) == "Camera"
    assert guess_device_type(services=["ipp"]) == "Printer"


# --- vendor hints ---------------------------------------------------------- #
@pytest.mark.parametrize(
    "vendor,expected",
    [
        ("Sagemcom Broadband SAS", "Router / Gateway"),
        ("Hangzhou Hikvision", "Camera"),
        ("Brother Industries", "Printer"),
        ("Synology", "NAS / Storage"),
        ("Apple, Inc.", "Apple device"),
        ("Samsung Electronics", "Phone / Tablet"),
        ("Hive", "Smart-home"),
        ("Espressif Inc.", "IoT / Embedded"),
    ],
)
def test_vendor_hints(vendor, expected):
    assert guess_device_type(vendor=vendor) == expected


# --- hostname fallback ----------------------------------------------------- #
def test_hostname_hint():
    assert guess_device_type(hostname="Nandhus-iPad") == "Phone / Tablet"
    assert guess_device_type(hostname="office-laserjet") == "Printer"


# --- randomized MAC -> phone/laptop hint ----------------------------------- #
def test_random_mac_is_phone_laptop():
    assert guess_device_type(vendor="(private/random)") == "Phone / Laptop"


def test_random_mac_ports_still_win():
    assert guess_device_type(vendor="(private/random)", ports=[9100]) == "Printer"


# --- no signal -> empty (never hallucinate a label) ------------------------ #
def test_no_signal_returns_empty():
    assert guess_device_type() == ""
    assert guess_device_type(vendor="Totally Unknown Co", hostname=None, ports=[12345]) == ""
