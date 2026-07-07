"""
test_mdns.py — mDNS service → device-type mapping.

Pins the priority order so a Mac advertising AirPlay + Bonjour-companion is
labelled an Apple device (not a TV), while dedicated cast/printer/home devices
get their specific type. The network browse itself isn't unit-tested (it needs a
live LAN); this covers the pure classification logic.
"""

from __future__ import annotations

import pytest
from mdns import _txt_get, device_type_from_mdns, os_from_model, product_from_model


@pytest.mark.parametrize(
    "services,expected",
    [
        ({"_ipp"}, "Printer"),
        ({"_printer", "_http"}, "Printer"),
        ({"_googlecast"}, "Media / TV"),
        ({"_sonos"}, "Media / TV"),
        ({"_homekit"}, "Smart-home"),
        ({"_hap", "_http"}, "Smart-home"),
        ({"_workstation", "_smb"}, "Computer"),
        # A Mac: AirPlay receiver + Bonjour companion -> Apple device, not TV.
        ({"_airplay", "_raop", "_companion-link"}, "Apple device"),
        # Standalone AirPlay (Apple TV / HomePod) without companion -> Media.
        ({"_airplay", "_raop"}, "Media / TV"),
        # Printer signal beats everything else present.
        ({"_ipp", "_http", "_workstation"}, "Printer"),
        (set(), ""),
        ({"_http"}, ""),
    ],
)
def test_device_type_from_mdns(services, expected):
    assert device_type_from_mdns(services) == expected


# --- os_from_model: Apple `model=` TXT → exact OS class (authoritative) ------ #
@pytest.mark.parametrize(
    "model,expected",
    [
        ("MacBookPro18,3", "macOS (Apple)"),
        ("iMac21,1", "macOS (Apple)"),
        ("Macmini9,1", "macOS (Apple)"),
        ("iPhone14,5", "iOS (Apple)"),
        ("iPad13,4", "iPadOS (Apple)"),
        ("Watch6,1", "watchOS (Apple)"),
        ("AudioAccessory5,1", "audioOS (HomePod)"),
        ("J413AP", ""),     # opaque board code → no claim
        ("", ""),
        (None, ""),
    ],
)
def test_os_from_model(model, expected):
    assert os_from_model(model) == expected


def test_txt_get_handles_bytes_keys():
    props = {b"model": b"MacBookPro18,3", b"osxvers": b"22"}
    assert _txt_get(props, "model") == "MacBookPro18,3"
    assert _txt_get(props, "missing") is None
    assert _txt_get(None, "model") is None


# --- product_from_model: exact Apple product line --------------------------- #
@pytest.mark.parametrize(
    "model,expected",
    [
        ("MacBookPro18,3", "MacBook Pro"),
        ("MacBookAir10,1", "MacBook Air"),
        ("iMac21,1", "iMac"),
        ("Macmini9,1", "Mac mini"),
        ("iPhone14,5", "iPhone"),
        ("iPad13,4", "iPad"),
        ("Watch6,1", "Apple Watch"),
        ("AudioAccessory5,1", "HomePod"),
        ("J413AP", ""),
        ("", ""),
    ],
)
def test_product_from_model(model, expected):
    assert product_from_model(model) == expected


# --- os_from_model: exact macOS version when osxvers is present -------------- #
def test_os_from_model_with_osxvers_resolves_exact_macos():
    assert os_from_model("MacBookPro18,3", "23") == "macOS 14 (Sonoma) (Apple)"
    assert os_from_model("MacBookAir10,1", "22") == "macOS 13 (Ventura) (Apple)"


def test_os_from_model_without_osxvers_falls_back_to_family():
    assert os_from_model("MacBookPro18,3") == "macOS (Apple)"
    # osxvers only sharpens Macs, never iPhones/iPads.
    assert os_from_model("iPhone14,5", "23") == "iOS (Apple)"
