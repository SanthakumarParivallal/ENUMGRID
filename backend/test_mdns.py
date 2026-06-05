"""
test_mdns.py — mDNS service → device-type mapping.

Pins the priority order so a Mac advertising AirPlay + Bonjour-companion is
labelled an Apple device (not a TV), while dedicated cast/printer/home devices
get their specific type. The network browse itself isn't unit-tested (it needs a
live LAN); this covers the pure classification logic.
"""

from __future__ import annotations

import pytest
from mdns import device_type_from_mdns


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
