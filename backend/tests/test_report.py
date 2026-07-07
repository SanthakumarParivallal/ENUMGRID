"""
test_report.py — PDF report generation.

We don't parse the PDF binary; we assert it's a well-formed, non-trivial PDF and
that the generator is total (never throws) across empty, partial and rich
snapshots — the property that matters for a one-click "download report" button.
"""

from __future__ import annotations

from report import build_pdf


def _is_pdf(data: bytes) -> bool:
    return isinstance(data, bytes) and data[:5] == b"%PDF-" and b"%%EOF" in data[-1024:]


def test_empty_snapshot_still_renders():
    pdf = build_pdf({"target": "192.168.0.0/24", "hosts": []})
    assert _is_pdf(pdf)
    assert len(pdf) > 800  # a real page, not a stub


def test_missing_fields_do_not_crash():
    # Deliberately partial host records.
    pdf = build_pdf({"hosts": [{"ip": "10.0.0.1"}, {}]})
    assert _is_pdf(pdf)


def test_rich_snapshot_renders():
    payload = {
        "target": "192.168.0.0/24",
        "hosts": [
            {
                "ip": "192.168.0.1",
                "hostname": None,
                "vendor": "Sagemcom Broadband SAS",
                "device_type": "Router / Gateway",
                "os": "Linux",
                "status": "up",
                "ports": [
                    {"port": 53, "protocol": "tcp", "state": "open", "service": "domain", "version": "dnsmasq 2.87"},
                    {"port": 443, "protocol": "tcp", "state": "open", "service": "http", "version": "lighttpd 1.4.63",
                     "critical": True, "vulns": [{"id": "CVE-2020-9999", "severity": "high", "cvss": 7.5, "title": "x"}]},
                ],
                "vulns": [],
            },
            {"ip": "192.168.0.52", "vendor": "Hive", "device_type": "Smart-home", "status": "up", "ports": []},
        ],
    }
    pdf = build_pdf(payload)
    assert _is_pdf(pdf)
    assert len(pdf) > 2000  # inventory + per-host detail => larger doc


def test_markup_in_scan_data_does_not_crash():
    # Service/version banners (and hostnames, vuln output, the target string) are
    # device/attacker-controlled and routinely contain <, > and &. These must be
    # escaped, not fed raw into reportlab's Paragraph parser (which would crash or
    # let a banner inject markup). This is a regression guard for that fix.
    payload = {
        "target": "192.168.0.0/24 <script>alert(1)</script> & more",
        "hosts": [
            {
                "ip": "192.168.0.1",
                "hostname": "host<a>&<b>",
                "vendor": "Acme & Co <Ltd>",
                "device_type": "Router & Gateway",
                "os": "Linux <3.14> & busybox",
                "status": "up",
                "ports": [
                    {
                        "port": 80, "protocol": "tcp", "state": "open", "service": "http",
                        "version": "Apache/2.4 (Ubuntu) & <mod_ssl>",
                        "vulns": [{
                            "id": "CVE-2021-0001", "severity": "high", "cvss": 7.5,
                            "output": "VULNERABLE <details> & notes",
                            "url": "http://evil'><b>injected", "confidence": "version",
                        }],
                    },
                ],
                "vulns": [{"id": "<script>", "severity": "info", "output": "& raw <tag>"}],
            },
        ],
    }
    pdf = build_pdf(payload)
    assert _is_pdf(pdf)
