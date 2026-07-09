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


def test_location_safe_handles_unparseable_url():
    # A malformed URL (unbalanced IPv6 brackets) makes urlparse raise → treated unsafe.
    assert ssdp._location_is_safe("http://[oops", "1.2.3.4") is False


def test_fetch_description_scrapes_xml(monkeypatch):
    class _Resp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self, n=None): return _SAMPLE_XML.encode()

    monkeypatch.setattr(ssdp.urllib.request, "urlopen", lambda *a, **k: _Resp())
    desc = ssdp._fetch_description("http://192.168.1.1/desc.xml", 1.0)
    assert desc["friendly"] == "Living Room Router" and desc["device_type"] == "Router / Gateway"


def test_fetch_description_returns_empty_on_error(monkeypatch):
    def _boom(*a, **k):
        raise OSError("timeout")

    monkeypatch.setattr(ssdp.urllib.request, "urlopen", _boom)
    assert ssdp._fetch_description("http://192.168.1.1/desc.xml", 1.0) == {}


def test_collect_responses_parses_a_reply(monkeypatch):
    reply = (b"HTTP/1.1 200 OK\r\n"
             b"LOCATION: http://192.168.1.50:80/desc.xml\r\n"
             b"SERVER: Linux/3.14 UPnP/1.0\r\n\r\n")
    state = {"n": 0}

    class _Sock:
        def setsockopt(self, *a): pass
        def settimeout(self, t): pass
        def sendto(self, *a): pass

        def recvfrom(self, n):
            state["n"] += 1
            if state["n"] == 1:
                return reply, ("192.168.1.50", 1900)
            raise OSError("done")          # end the receive loop on the 2nd read

        def close(self): pass

    monkeypatch.setattr(ssdp.socket, "socket", lambda *a, **k: _Sock())
    out = ssdp._collect_responses(0.5)
    assert out["192.168.1.50"]["location"] == "http://192.168.1.50:80/desc.xml"
    assert "Linux" in out["192.168.1.50"]["server"]


def test_collect_responses_breaks_on_send_error(monkeypatch):
    class _Sock:
        def setsockopt(self, *a): pass
        def settimeout(self, t): pass
        def sendto(self, *a): raise OSError("no multicast route")
        def recvfrom(self, n): raise OSError("closed")
        def close(self): pass

    monkeypatch.setattr(ssdp.socket, "socket", lambda *a, **k: _Sock())
    assert ssdp._collect_responses(0.5) == {}


def test_discover_ssdp_empty_when_no_responses(monkeypatch):
    monkeypatch.setattr(ssdp, "_collect_responses", lambda timeout: {})
    assert ssdp.discover_ssdp() == {}


def test_discover_ssdp_fetches_only_safe_locations(monkeypatch):
    # Deterministic end-to-end of discover_ssdp: a responder whose LOCATION points
    # back at itself is fetched + scraped; one pointing elsewhere (SSRF) is not.
    monkeypatch.setattr(ssdp, "_collect_responses", lambda timeout: {
        "192.168.1.50": {"location": "http://192.168.1.50:80/desc.xml", "server": "Linux/3.14 UPnP/1.0"},
        "192.168.1.51": {"location": "http://10.0.0.9/evil.xml", "server": ""},   # host mismatch → skip
    })
    monkeypatch.setattr(ssdp, "_fetch_description", lambda loc, t: {
        "friendly": "Router", "manufacturer": "Acme", "model": "X1", "device_type": "Router / Gateway"})
    out = ssdp.discover_ssdp(timeout=0.5, fetch_timeout=0.5)
    assert out["192.168.1.50"]["hostname"] == "Router"          # fetched (LOCATION matches responder)
    assert out["192.168.1.50"]["device_type"] == "Router / Gateway"
    assert out["192.168.1.50"]["os"] == "Embedded Linux"        # from the SERVER header
    assert out["192.168.1.51"]["hostname"] is None              # SSRF-guarded → not fetched
    assert out["192.168.1.51"]["os"] == ""
