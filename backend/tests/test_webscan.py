"""test_webscan.py — web-posture audit parsers (no network)."""

from __future__ import annotations

import datetime

import webscan
from models import Severity


def test_missing_security_headers_flagged():
    vulns = webscan.audit_headers({"Server": "nginx"}, is_https=True)
    ids = {v.id for v in vulns}
    assert "web-missing-strict-transport-security" in ids
    assert "web-missing-content-security-policy" in ids
    assert "web-missing-x-frame-options" in ids


def test_present_headers_not_flagged():
    headers = {
        "Strict-Transport-Security": "max-age=63072000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
    }
    assert webscan.audit_headers(headers, is_https=True) == []


def test_hsts_not_flagged_over_plain_http():
    ids = {v.id for v in webscan.audit_headers({}, is_https=False)}
    assert "web-missing-strict-transport-security" not in ids


def test_insecure_cookie_flags():
    vulns = webscan.audit_headers({"Set-Cookie": "id=abc; Path=/"}, is_https=True)
    ids = {v.id for v in vulns}
    assert "web-cookie-insecure" in ids and "web-cookie-nohttponly" in ids


def test_expired_cert_is_high():
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    past = (now - datetime.timedelta(days=10)).strftime("%b %d %H:%M:%S %Y GMT")
    vulns = webscan.cert_findings({"notAfter": past, "issuer": (), "subject": ()})
    assert any(v.id == "tls-cert-expired" and v.severity == Severity.HIGH for v in vulns)


def test_self_signed_cert_flagged():
    issuer = ((("commonName", "self"),),)
    vulns = webscan.cert_findings({"notAfter": "Jan 1 00:00:00 2099 GMT", "issuer": issuer, "subject": issuer})
    assert any(v.id == "tls-cert-selfsigned" for v in vulns)


def test_valid_cert_no_findings():
    issuer = ((("commonName", "Let's Encrypt"),),)
    subject = ((("commonName", "example.com"),),)
    vulns = webscan.cert_findings({"notAfter": "Jan 1 00:00:00 2099 GMT", "issuer": issuer, "subject": subject})
    assert vulns == []


def test_cert_findings_none():
    assert webscan.cert_findings(None) == []


def test_expiring_soon_cert_is_low():
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    soon = (now + datetime.timedelta(days=10)).strftime("%b %d %H:%M:%S %Y GMT")
    vulns = webscan.cert_findings({"notAfter": soon, "issuer": (), "subject": ()})
    assert any(v.id == "tls-cert-expiring" and v.severity == Severity.LOW for v in vulns)


def test_unparseable_cert_date_is_ignored():
    vulns = webscan.cert_findings({"notAfter": "not a date", "issuer": (), "subject": ()})
    assert all(not v.id.startswith("tls-cert-exp") for v in vulns)   # bad date → no expiry finding


def _self_signed_der(cn: str = "router.local", days: int = 30) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)          # issuer == subject → self-signed
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_peercert_dict_parses_a_real_der():
    d = webscan._peercert_dict(_self_signed_der())
    assert d and "notAfter" in d and d["issuer"] == d["subject"]   # round-trips to the parser shape


def test_peercert_dict_none_and_garbage():
    assert webscan._peercert_dict(None) is None
    assert webscan._peercert_dict(b"not-a-certificate") is None


def test_peercert_dict_degrades_when_cryptography_missing(monkeypatch):
    import sys
    # Simulate the optional `cryptography` dependency being absent → parse returns None.
    monkeypatch.setitem(sys.modules, "cryptography", None)
    assert webscan._peercert_dict(b"anything") is None


def test_fetch_over_http_reads_headers(monkeypatch):
    class _Resp:
        def getheaders(self): return [("Server", "nginx"), ("X-Frame-Options", "DENY")]

    class _Conn:
        def __init__(self, *a, **k): pass
        def request(self, *a, **k): pass
        def getresponse(self): return _Resp()
        def close(self): pass

    monkeypatch.setattr(webscan.http.client, "HTTPConnection", _Conn)
    headers, server, cert = webscan._fetch("10.0.0.1", 80, is_https=False)
    assert server == "nginx" and cert is None


def test_fetch_over_https_reads_cert(monkeypatch):
    class _Resp:
        def getheaders(self): return [("Server", "Apache")]

    class _Sock:
        def getpeercert(self, binary_form=False): return b"DER-BYTES"

    class _Conn:
        def __init__(self, *a, **k): self.sock = _Sock()
        def request(self, *a, **k): pass
        def getresponse(self): return _Resp()
        def close(self): pass

    monkeypatch.setattr(webscan.http.client, "HTTPSConnection", _Conn)
    monkeypatch.setattr(webscan, "_peercert_dict", lambda der: {"notAfter": "Jan 1 00:00:00 2099 GMT"})
    headers, server, cert = webscan._fetch("10.0.0.1", 443, is_https=True)
    assert server == "Apache" and cert == {"notAfter": "Jan 1 00:00:00 2099 GMT"}


def test_fetch_https_cert_read_error_is_tolerated(monkeypatch):
    class _Resp:
        def getheaders(self): return [("Server", "x")]

    class _Sock:
        def getpeercert(self, binary_form=False): raise OSError("tls read failed")

    class _Conn:
        def __init__(self, *a, **k): self.sock = _Sock()
        def request(self, *a, **k): pass
        def getresponse(self): return _Resp()
        def close(self): pass

    monkeypatch.setattr(webscan.http.client, "HTTPSConnection", _Conn)
    _headers, _server, cert = webscan._fetch("10.0.0.1", 443, is_https=True)
    assert cert is None                               # cert read failed → tolerated, no crash


def test_scan_orchestrates_fetch_and_findings(monkeypatch):
    monkeypatch.setattr(webscan, "_fetch",
                        lambda ip, port, https: ({"Server": "nginx"}, "nginx", None))
    out = webscan.scan("10.0.0.1", 80, is_https=False)
    assert out["ok"] is True and out["server"] == "nginx"
    assert any(v["id"].startswith("web-missing") for v in out["vulns"])


def test_scan_defaults_https_by_port_and_reports_fetch_error(monkeypatch):
    def _boom(ip, port, https):
        assert https is True                      # port 443 → https auto-selected
        raise OSError("connection refused")

    monkeypatch.setattr(webscan, "_fetch", _boom)
    out = webscan.scan("10.0.0.1", 443)
    assert out["ok"] is False and "error" in out
