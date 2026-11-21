"""tlsinspect.py: read the X.509 certificate a TLS service presents.

A device with no DNS, mDNS or NetBIOS name often still presents a certificate
whose subject or subjectAltName names it (a NAS admin page, a router, a camera,
an IoT hub). Reading that cert fills the name, and an expired or self-signed
certificate is a real, reportable fact that belongs in an enumeration report.

We deliberately do NOT verify the chain or the hostname: a self-signed cert is
the norm on a LAN, and the point is to read what the server actually presents,
not to decide whether a browser would trust it. The TLS handshake uses the
standard library; the certificate is parsed with `cryptography` (already a
dependency). Best-effort and bounded: any failure yields None, and no field is
ever inferred or fabricated.
"""

from __future__ import annotations

import datetime
import ipaddress
import socket
import ssl

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

# TLS-speaking ports worth a certificate read. Intersected with the ports a host
# is actually found listening on, so nothing is probed speculatively.
TLS_PORTS: frozenset[int] = frozenset({443, 465, 636, 853, 990, 993, 995, 5986, 8443})

# Warn when a still-valid certificate is this close to expiry (days).
EXPIRY_WARN_DAYS = 30


def fetch_der(ip: str, port: int, timeout: float = 2.0,
              server_name: str | None = None) -> bytes | None:
    """The DER-encoded certificate a TLS service presents, or None.

    The chain and hostname are not verified on purpose (self-signed is normal on
    a LAN); we just complete a handshake and read the leaf certificate.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False               # must precede verify_mode = CERT_NONE
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            raw.settimeout(timeout)
            with ctx.wrap_socket(raw, server_hostname=server_name) as tls:
                return tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError, ValueError):
        return None


def _common_name(name: x509.Name) -> str:
    """The first common-name attribute of a subject/issuer, or ''."""
    try:
        attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    except Exception:
        return ""
    return str(attrs[0].value) if attrs else ""


def _subject_alt_names(cert: x509.Certificate) -> list[str]:
    """DNS names and IP addresses from the subjectAltName extension."""
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        return []
    san = ext.value
    out: list[str] = [str(n) for n in san.get_values_for_type(x509.DNSName)]
    out += [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
    return out


def summarize(der: bytes, now: datetime.datetime | None = None) -> dict | None:
    """Parse a DER certificate into a plain dict, or None if it will not parse.

    `issues` collects honest, cert-derived facts: not-yet-valid, expired,
    expiring soon, and self-signed.
    """
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:
        return None
    now = now or datetime.datetime.now(datetime.timezone.utc)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    self_signed = cert.subject == cert.issuer
    issues: list[str] = []
    if now < not_before:
        issues.append("not yet valid")
    elif now > not_after:
        issues.append("expired")
    else:
        days_left = (not_after - now).days
        if days_left <= EXPIRY_WARN_DAYS:
            issues.append(f"expires in {days_left} days")
    if self_signed:
        issues.append("self-signed")
    return {
        "subject": _common_name(cert.subject),
        "issuer": _common_name(cert.issuer),
        "sans": _subject_alt_names(cert),
        "not_before": not_before.date().isoformat(),
        "not_after": not_after.date().isoformat(),
        "self_signed": self_signed,
        "issues": issues,
    }


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def preferred_name(summary: dict) -> str | None:
    """A usable hostname from the certificate, or None.

    Prefers a real subjectAltName / subject CN; skips wildcards, IP literals and
    the placeholder ``localhost`` that appliances ship by default.
    """
    for candidate in list(summary.get("sans", [])) + [summary.get("subject", "")]:
        name = (candidate or "").strip().rstrip(".")
        if not name or name.startswith("*") or _is_ip(name) or name.lower() == "localhost":
            continue
        return name
    return None


def inspect(ip: str, port: int, timeout: float = 2.0,
            server_name: str | None = None,
            now: datetime.datetime | None = None) -> dict | None:
    """Fetch and summarize the certificate on ``ip:port``; adds ``port``.

    Returns None when the port is not TLS, is unreachable, or presents no
    parseable certificate.
    """
    der = fetch_der(ip, port, timeout, server_name)
    if der is None:
        return None
    summary = summarize(der, now)
    if summary is None:
        return None
    summary["port"] = port
    return summary
