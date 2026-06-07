"""Tests for the SSDP/UPnP helpers (parsing + the SSRF guard)."""

from __future__ import annotations

import ssdp

_SAMPLE_XML = """<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>Living Room Router</friendlyName>
    <manufacturer>Acme Networks</manufacturer>
    <modelName>AC-9000</modelName>
  </device>
</root>"""


def test_device_type_from_upnp_known_urns():
    assert ssdp._device_type_from_upnp(
        "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
    ) == "Router / Gateway"
    assert ssdp._device_type_from_upnp(
        "urn:schemas-upnp-org:device:MediaRenderer:1"
    ) == "Media / TV"
    assert ssdp._device_type_from_upnp("urn:schemas-upnp-org:device:Basic:1") == ""


def test_scrape_pulls_each_field():
    assert ssdp._scrape(ssdp._FRIENDLY_RE, _SAMPLE_XML) == "Living Room Router"
    assert ssdp._scrape(ssdp._MANUF_RE, _SAMPLE_XML) == "Acme Networks"
    assert ssdp._scrape(ssdp._MODEL_RE, _SAMPLE_XML) == "AC-9000"
    assert ssdp._device_type_from_upnp(ssdp._scrape(ssdp._DEVTYPE_RE, _SAMPLE_XML)) == "Router / Gateway"


def test_location_safe_only_when_host_matches_responder():
    # LOCATION on the same host that answered → safe to fetch.
    assert ssdp._location_is_safe("http://192.168.1.1:5000/desc.xml", "192.168.1.1") is True
    # LOCATION pointing at a *different* internal host → SSRF, refuse.
    assert ssdp._location_is_safe("http://10.0.0.5:80/x.xml", "192.168.1.1") is False
    # Non-http(s) scheme → refuse (no file:// etc.).
    assert ssdp._location_is_safe("file:///etc/passwd", "192.168.1.1") is False
    assert ssdp._location_is_safe("ftp://192.168.1.1/x", "192.168.1.1") is False


def test_os_from_server_header():
    assert ssdp._os_from_server("Linux/3.14.0 UPnP/1.0 MiniDLNA/1.2") == "Embedded Linux"
    assert ssdp._os_from_server("Microsoft-Windows/10.0 UPnP/1.0") == "Windows"
    assert ssdp._os_from_server("") == ""


def test_collect_responses_returns_dict_on_no_replies(monkeypatch):
    # A very short window with nothing answering must yield an empty dict, not raise.
    out = ssdp.discover_ssdp(timeout=0.5, fetch_timeout=0.5)
    assert isinstance(out, dict)
