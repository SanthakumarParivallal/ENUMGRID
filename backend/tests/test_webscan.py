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
