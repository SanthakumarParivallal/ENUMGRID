"""
test_fingerprint.py — device-type heuristic classification.

Pins the priority order (open ports > services > hostname > vendor) and the
"no signal -> empty string" contract so the UI never shows a guessed label
without evidence. Hostname outranks the OUI vendor on purpose: a device's own
name (e.g. "DESKTOP-…") is a stronger identity than the vendor of its Wi-Fi chip.
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
        ("Routerboard.com", "Router / Gateway"),    # MikroTik's older OUI name
        ("MikroTikls SIA", "Router / Gateway"),     # MikroTik's newer OUI name
        ("Fortinet Inc", "Router / Gateway"),
        ("Hangzhou Hikvision", "Camera"),
        ("Brother Industries", "Printer"),
        ("Synology", "NAS / Storage"),
        ("Apple, Inc.", "Apple device"),
        ("Samsung Electronics", "Phone / Tablet"),
        ("Hive", "Smart-home"),
        ("Espressif Inc.", "IoT / Embedded"),
        ("AltoBeam Inc.", "IoT / Embedded"),
    ],
)
def test_vendor_hints(vendor, expected):
    assert guess_device_type(vendor=vendor) == expected


# --- hostname fallback ----------------------------------------------------- #
def test_hostname_hint():
    assert guess_device_type(hostname="Nandhus-iPad") == "Phone / Tablet"
    assert guess_device_type(hostname="office-laserjet") == "Printer"


def test_hostname_outranks_oui_vendor():
    # Regression: a Windows "DESKTOP-…" / "W11N-…" machine whose Wi-Fi module OUI
    # is an IoT-adjacent vendor must be classified by its self-assigned name
    # (Computer), NOT by the chip vendor (previously mislabelled "IoT / Embedded").
    assert guess_device_type(hostname="DESKTOP-SC8BRDS", vendor="AzureWave Technologies") == "Computer"
    assert guess_device_type(hostname="W11N-ITR34321", vendor="Intel Corporate") == "Computer"
    # But with no telling hostname, the vendor still classifies it.
    assert guess_device_type(hostname="node-42", vendor="AzureWave Technologies") == "IoT / Embedded"


# --- randomized MAC -> phone/laptop hint ----------------------------------- #
def test_random_mac_is_phone_laptop():
    assert guess_device_type(vendor="(private/random)") == "Phone / Laptop"


def test_random_mac_ports_still_win():
    assert guess_device_type(vendor="(private/random)", ports=[9100]) == "Printer"


# --- no signal -> empty (never hallucinate a label) ------------------------ #
def test_no_signal_returns_empty():
    assert guess_device_type() == ""
    assert guess_device_type(vendor="Totally Unknown Co", hostname=None, ports=[12345]) == ""
