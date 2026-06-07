"""
webscan.py — lightweight web-posture audit (DAST-lite) for HTTP(S) services.

Not a full crawler/fuzzer, but a real, safe passive check of the most common
web-security hygiene issues on a discovered web port: missing security response
headers (HSTS / CSP / X-Frame-Options / …), insecure cookies, the server banner,
and — for HTTPS — the TLS certificate (issuer, expiry, self-signed). It performs
a single GET of the root path; it never crawls, fuzzes, or sends payloads.

Pure parsers (header/cert → findings) are fully tested; the live fetch is
best-effort and bounded. Authorized use only.
"""

from __future__ import annotations

import datetime
import http.client
import socket
import ssl

from models import Severity, Vuln

_TIMEOUT = 6

# Recommended security headers → (severity if missing, short explanation).
_SECURITY_HEADERS = {
    "strict-transport-security": (Severity.MEDIUM, "No HSTS — connections can be downgraded to HTTP"),
    "content-security-policy": (Severity.MEDIUM, "No Content-Security-Policy — weaker XSS mitigation"),
    "x-frame-options": (Severity.LOW, "No X-Frame-Options — clickjacking risk"),
    "x-content-type-options": (Severity.LOW, "No X-Content-Type-Options — MIME-sniffing risk"),
    "referrer-policy": (Severity.LOW, "No Referrer-Policy"),
}


def audit_headers(headers: dict, is_https: bool) -> list[Vuln]:
    """Findings for missing security headers + insecure cookies."""
    low = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    out: list[Vuln] = []
    for name, (sev, why) in _SECURITY_HEADERS.items():
        if name == "strict-transport-security" and not is_https:
            continue  # HSTS only meaningful over HTTPS
        if name not in low:
            out.append(Vuln(
                id=f"web-missing-{name}", title=f"Missing {name}", severity=sev,
                output=why, confidence="confirmed",
            ))
    cookie = low.get("set-cookie", "")
    if cookie:
        cl = cookie.lower()
        if "secure" not in cl and is_https:
            out.append(Vuln(id="web-cookie-insecure", title="Cookie without Secure flag",
                            severity=Severity.LOW, output="Set-Cookie lacks the Secure flag",
                            confidence="confirmed"))
        if "httponly" not in cl:
            out.append(Vuln(id="web-cookie-nohttponly", title="Cookie without HttpOnly",
                            severity=Severity.LOW, output="Set-Cookie lacks HttpOnly (JS-readable)",
                            confidence="confirmed"))
    return out


def cert_findings(cert: dict | None) -> list[Vuln]:
    """Findings from a TLS peer certificate dict (expiry / self-signed)."""
    if not cert:
        return []
    out: list[Vuln] = []
    not_after = cert.get("notAfter")
    if not_after:
        try:
            exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
            days = (exp - now).days
            if days < 0:
                out.append(Vuln(id="tls-cert-expired", title="TLS certificate expired",
                                severity=Severity.HIGH, output=f"Expired {-days} days ago",
                                confidence="confirmed"))
            elif days < 21:
                out.append(Vuln(id="tls-cert-expiring", title="TLS certificate expiring soon",
                                severity=Severity.LOW, output=f"Expires in {days} days",
                                confidence="confirmed"))
        except (ValueError, TypeError):
            pass
    issuer = {k: v for t in cert.get("issuer", ()) for k, v in t}
    subject = {k: v for t in cert.get("subject", ()) for k, v in t}
    if issuer and issuer == subject:
        out.append(Vuln(id="tls-cert-selfsigned", title="Self-signed TLS certificate",
                        severity=Severity.MEDIUM, output="Issuer == subject (not CA-signed)",
                        confidence="confirmed"))
    return out


def _peercert_dict(der: bytes | None) -> dict | None:
    """Parse a DER certificate into the dict shape `cert_findings` expects.

    We connect with ``verify_mode = CERT_NONE`` (we *inspect* the cert, we don't
    trust-gate the connection). Under CERT_NONE, ``ssl.getpeercert()`` returns an
    empty dict — so the only way to read the cert is its binary (DER) form, which
    we decode here. Returns ``notAfter`` + ``issuer``/``subject`` in the same
    nested-tuple layout the stdlib produces, so the pure `cert_findings` parser
    (and its tests) work unchanged. Best-effort: ``None`` on any parse failure.
    """
    if not der:
        return None
    try:
        from cryptography import x509  # available via the TLS/credscan deps
    except Exception:  # noqa: BLE001 - optional dep; degrade gracefully
        return None
    try:
        cert = x509.load_der_x509_certificate(der)
        try:
            not_after = cert.not_valid_after_utc  # tz-aware UTC (cryptography ≥42)
        except AttributeError:  # pragma: no cover - older cryptography
            not_after = cert.not_valid_after
        # Match ssl.getpeercert()'s "%b %d %H:%M:%S %Y GMT" so cert_findings parses it.
        not_after_str = not_after.strftime("%b %d %H:%M:%S %Y GMT")

        def _name(name) -> tuple:
            # ((attr, value),) per RDN — issuer == subject ⇒ self-signed.
            return tuple(((attr.rfc4514_attribute_name, attr.value),) for attr in name)

        return {
            "notAfter": not_after_str,
            "issuer": _name(cert.issuer),
            "subject": _name(cert.subject),
        }
    except Exception:  # noqa: BLE001 - malformed cert must never break the scan
        return None


def _fetch(ip: str, port: int, is_https: bool) -> tuple[dict, str, dict | None]:
    """Return (response headers, server banner, peer cert|None). Best-effort."""
    if is_https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # we inspect the cert, not trust-gate it
        conn = http.client.HTTPSConnection(ip, port, timeout=_TIMEOUT, context=ctx)
    else:
        conn = http.client.HTTPConnection(ip, port, timeout=_TIMEOUT)
    try:
        conn.request("GET", "/", headers={"User-Agent": "EnumGrid/1.0"})
        resp = conn.getresponse()
        headers = dict(resp.getheaders())
        cert = None
        sock = getattr(conn, "sock", None)
        if is_https and sock is not None:
            try:
                # Under CERT_NONE the dict form is empty; read the DER and parse it.
                cert = _peercert_dict(sock.getpeercert(binary_form=True))
            except (OSError, ValueError):
                cert = None
        return headers, headers.get("Server", ""), cert
    finally:
        conn.close()


def scan(ip: str, port: int = 80, is_https: bool | None = None) -> dict:
    """Audit one web service → {ok, server, vulns:[...]} (never raises)."""
    if is_https is None:
        is_https = port in (443, 8443)
    try:
        headers, server, cert = _fetch(ip, port, is_https)
    except (OSError, socket.timeout, http.client.HTTPException, ssl.SSLError) as exc:
        return {"ok": False, "error": f"web fetch failed ({type(exc).__name__})"}
    vulns = audit_headers(headers, is_https) + cert_findings(cert)
    return {
        "ok": True,
        "server": server,
        "https": is_https,
        "vulns": [v.model_dump() for v in vulns],
    }
