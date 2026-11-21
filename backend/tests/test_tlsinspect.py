"""Tests for tlsinspect: reading the certificate a TLS service presents.

Certificates are generated in-process with `cryptography` (EC keys, fast), so
the parsing, naming and validity logic is exercised against real DER, and a
short-lived local TLS server exercises the real handshake in `fetch_der`.
"""

from __future__ import annotations

import contextlib
import datetime
import os
import socket
import ssl
import tempfile
import threading

import tlsinspect as t
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

_UTC = datetime.timezone.utc


def _make_cert(cn, sans=(), issuer_cn=None, not_before=None, not_after=None):
    now = datetime.datetime.now(_UTC)
    nb = (not_before or now - datetime.timedelta(days=1)).astimezone(_UTC).replace(tzinfo=None)
    na = (not_after or now + datetime.timedelta(days=365)).astimezone(_UTC).replace(tzinfo=None)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]) if cn else x509.Name([])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or cn)])
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(nb).not_valid_after(na))
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
    return builder.sign(key, hashes.SHA256()), key


@contextlib.contextmanager
def _tls_server(cert, key):
    cdir = tempfile.mkdtemp()
    cpath, kpath = os.path.join(cdir, "c.pem"), os.path.join(cdir, "k.pem")
    with open(cpath, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(kpath, "wb") as fh:
        fh.write(key.private_bytes(serialization.Encoding.PEM,
                                   serialization.PrivateFormat.TraditionalOpenSSL,
                                   serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cpath, kpath)
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def _serve():
        with contextlib.suppress(Exception):
            conn, _ = srv.accept()
            with ctx.wrap_socket(conn, server_side=True) as s:
                s.recv(16)

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        srv.close()
        thread.join(timeout=2)


def _der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


# --- certificate parsing ---------------------------------------------------- #
def test_summarize_valid_self_signed():
    now = datetime.datetime.now(_UTC)
    cert, _ = _make_cert("nas.home", sans=["nas.home", "storage.home"],
                         not_before=now - datetime.timedelta(days=5),
                         not_after=now + datetime.timedelta(days=200))
    s = t.summarize(_der(cert), now=now)
    assert s["subject"] == "nas.home"
    assert s["sans"] == ["nas.home", "storage.home"]
    assert s["self_signed"] is True
    assert s["issues"] == ["self-signed"]              # valid, only self-signed noted


def test_summarize_expired_and_not_yet_valid():
    now = datetime.datetime.now(_UTC)
    expired, _ = _make_cert("old", not_before=now - datetime.timedelta(days=400),
                            not_after=now - datetime.timedelta(days=2))
    assert "expired" in t.summarize(_der(expired), now=now)["issues"]
    future, _ = _make_cert("new", not_before=now + datetime.timedelta(days=2),
                           not_after=now + datetime.timedelta(days=400))
    assert "not yet valid" in t.summarize(_der(future), now=now)["issues"]


def test_summarize_expiring_soon_and_ca_signed():
    now = datetime.datetime.now(_UTC)
    cert, _ = _make_cert("web", issuer_cn="Real CA",
                         not_after=now + datetime.timedelta(days=10))
    s = t.summarize(_der(cert), now=now)
    assert s["self_signed"] is False                   # subject != issuer
    assert any(i.startswith("expires in") for i in s["issues"])
    assert "self-signed" not in s["issues"]


def test_summarize_rejects_garbage():
    assert t.summarize(b"not a certificate") is None


def test_common_name_variants():
    assert t._common_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")])) == "x"
    assert t._common_name(x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Acme")])) == ""

    class _Raises:
        def get_attributes_for_oid(self, oid):
            raise RuntimeError("boom")

    assert t._common_name(_Raises()) == ""             # defensive: never raises


def test_subject_alt_names_absent():
    cert, _ = _make_cert("plain")                      # no SAN extension
    assert t._subject_alt_names(cert) == []


def test_is_ip():
    assert t._is_ip("192.168.1.1") is True
    assert t._is_ip("nas.home") is False


def test_preferred_name_rules():
    assert t.preferred_name({"sans": ["nas.home"], "subject": "x"}) == "nas.home"
    assert t.preferred_name({"sans": [], "subject": "router.lan"}) == "router.lan"
    assert t.preferred_name(
        {"sans": ["*.wild.com", "10.0.0.1", "localhost", "real.host"], "subject": ""}
    ) == "real.host"                                    # wildcard / IP / localhost skipped
    assert t.preferred_name({"sans": ["*.only.com"], "subject": ""}) is None


# --- live handshake --------------------------------------------------------- #
def test_fetch_and_inspect_over_real_tls():
    now = datetime.datetime.now(_UTC)
    cert, key = _make_cert("camera.home", sans=["camera.home"],
                           not_after=now + datetime.timedelta(days=90))
    with _tls_server(cert, key) as port:
        info = t.inspect("127.0.0.1", port, timeout=3.0, now=now)
    assert info["subject"] == "camera.home"
    assert info["port"] == port
    assert t.preferred_name(info) == "camera.home"


def test_fetch_der_handles_unreachable_port():
    # Nothing listening -> connection refused -> None, no exception.
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    assert t.fetch_der("127.0.0.1", port, timeout=0.5) is None


def test_inspect_none_when_no_cert(monkeypatch):
    monkeypatch.setattr(t, "fetch_der", lambda ip, port, timeout=2.0, server_name=None: None)
    assert t.inspect("127.0.0.1", 443) is None


def test_inspect_none_when_cert_unparseable(monkeypatch):
    monkeypatch.setattr(t, "fetch_der",
                        lambda ip, port, timeout=2.0, server_name=None: b"garbage-der")
    assert t.inspect("127.0.0.1", 443) is None
