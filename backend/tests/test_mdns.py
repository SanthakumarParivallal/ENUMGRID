"""
test_mdns.py — mDNS service → device-type mapping.

Pins the priority order so a Mac advertising AirPlay + Bonjour-companion is
labelled an Apple device (not a TV), while dedicated cast/printer/home devices
get their specific type. The network browse itself isn't unit-tested (it needs a
live LAN); this covers the pure classification logic.
"""

from __future__ import annotations

import mdns
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


# --- hostname cleaning + the live browse (zeroconf mocked, no network) ------- #
def test_clean_hostname():
    assert mdns._clean_hostname("Living-Room.local.") == "Living-Room"
    assert mdns._clean_hostname("host.") == "host"
    assert mdns._clean_hostname(None) is None
    assert mdns._clean_hostname(".local") is None       # empty after stripping → None


def test_discover_mdns_without_zeroconf(monkeypatch):
    monkeypatch.setattr(mdns, "_HAVE_ZEROCONF", False)
    assert mdns.discover_mdns(1) == {}


class _FakeInfo:
    def __init__(self, server, addrs, properties=None):
        self.server = server
        self._addrs = addrs
        self.properties = properties or {}

    def parsed_addresses(self):
        return self._addrs


def _discover_with(monkeypatch, info, stype="_device-info._tcp.local."):
    monkeypatch.setattr(mdns, "_HAVE_ZEROCONF", True)

    class _ZC:
        def get_service_info(self, type_, name, timeout=None): return info
        def close(self): pass

    def _browser(zc, s, listener):
        listener.add_service(zc, s, "n")
        listener.update_service(zc, s, "n")     # exercise the interface no-ops
        listener.remove_service(zc, s, "n")
        return object()

    monkeypatch.setattr(mdns, "Zeroconf", _ZC)
    monkeypatch.setattr(mdns, "_SERVICE_TYPES", (stype,))
    monkeypatch.setattr(mdns, "ServiceBrowser", _browser)
    monkeypatch.setattr(mdns.time, "sleep", lambda s: None)
    return mdns.discover_mdns(timeout=1)


def test_discover_mdns_resolves_apple_product_and_os(monkeypatch):
    info = _FakeInfo("Studio.local.", ["10.0.0.30"],
                     {b"model": b"MacBookPro18,3", b"osxvers": b"23"})
    out = _discover_with(monkeypatch, info)
    assert out["10.0.0.30"]["hostname"] == "Studio"
    assert out["10.0.0.30"]["device_type"] == "MacBook Pro"      # exact product beats generic type
    assert "Sonoma" in out["10.0.0.30"]["os"]


def test_discover_mdns_skips_ipv6_and_classifies_by_service(monkeypatch):
    info = _FakeInfo("printer.local.", ["fe80::1", "10.0.0.31"], {})
    out = _discover_with(monkeypatch, info, stype="_ipp._tcp.local.")
    assert list(out) == ["10.0.0.31"]                            # IPv6 skipped, IPv4 kept
    assert out["10.0.0.31"]["device_type"] == "Printer" and out["10.0.0.31"]["hostname"] == "printer"


def test_discover_mdns_handles_missing_service_info(monkeypatch):
    assert _discover_with(monkeypatch, None) == {}               # get_service_info None → nothing
