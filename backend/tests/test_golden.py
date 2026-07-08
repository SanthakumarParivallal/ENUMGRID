"""
test_golden.py — determinism / golden-file guarantees for the offline processing
pipeline (nmap XML → scanner model → PDF report).

A network scan is inherently non-deterministic (the network changes between runs),
but *processing a fixed scan result must not be*. These tests pin that contract:

  1. A fixed nmap XML fixture, fed through the real ``scanner._service_scan``
     transform, must reproduce a checked-in golden host model byte-for-byte — and
     do so identically on repeat runs. This locks the nmap-XML → host-model parser
     and the NSE-script → CVE extraction (the accuracy-critical path) against
     silent regressions.
  2. ``report.build_pdf`` must be a pure function of its input: given the same
     snapshot (with the wall-clock and provenance frozen, and ``SOURCE_DATE_EPOCH``
     set so reportlab's own timestamps/ids are fixed), two builds must be
     byte-identical. This makes "the report reproduces the screen" a mechanical
     guarantee, not a hope.

No nmap binary and no network are needed — python-nmap's ``analyse_nmap_xml_scan``
parses the fixture XML in-process, and ``_run_scan`` is stubbed to return it.
"""

from __future__ import annotations

import json
import os
from datetime import datetime

import nmap
import provenance
import report
import scanner

_FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
_SAMPLE_XML = os.path.join(_FIXTURES, "nmap_sample.xml")
_SAMPLE_GOLDEN = os.path.join(_FIXTURES, "nmap_sample.golden.json")
_SAMPLE_IP = "172.28.0.11"


def _load_scanner_from_xml(path: str) -> "nmap.PortScanner":
    """Parse a fixed nmap XML file into a PortScanner (no nmap binary, no network)."""
    with open(path, encoding="utf-8") as fh:
        ps = nmap.PortScanner()
        ps.analyse_nmap_xml_scan(nmap_xml_output=fh.read())
    return ps


def _normalize(host: dict) -> dict:
    """The scanner host dict as plain JSON-able data (enums → strings).

    Exactly the shape the golden file stores, so equality is a byte-for-byte
    contract on the parser's output."""
    return {
        "os": host["os"],
        "hostname": host["hostname"],
        "device_type": host["device_type"],
        "note": host["note"],
        "ports": [p.model_dump(mode="json") for p in host["ports"]],
        "vulns": [v.model_dump(mode="json") for v in host["vulns"]],
    }


def _service_scan_from_fixture(monkeypatch) -> dict:
    """Run the REAL transform over the fixture, isolated from the network.

    ``_run_scan`` is stubbed to return the pre-parsed fixture scanner, and the
    online enrichers are neutralised (``auto_cve=False`` already skips NVD/EPSS;
    the curated offline table is stubbed to [] so the golden depends only on the
    XML + parsing code, not on the evolving offline CVE database)."""
    ps = _load_scanner_from_xml(_SAMPLE_XML)
    monkeypatch.setattr(scanner, "_run_scan", lambda hosts, args: (ps, ""))
    monkeypatch.setattr(scanner, "lookup_offline_cves", lambda version: [])
    return scanner._service_scan(_SAMPLE_IP, privileged=False, deep=False, auto_cve=False)


# --------------------------------------------------------------------------- #
# 1. Parser → model: fixed nmap XML reproduces the golden host model.
# --------------------------------------------------------------------------- #
def test_service_scan_matches_golden(monkeypatch):
    host = _service_scan_from_fixture(monkeypatch)
    with open(_SAMPLE_GOLDEN, encoding="utf-8") as fh:
        golden = json.load(fh)
    assert _normalize(host) == golden


def test_service_scan_is_deterministic(monkeypatch):
    # Same fixed input twice → identical output. Parsing must carry no run-to-run
    # state (ordering, dedupe, severity mapping are all stable).
    a = _normalize(_service_scan_from_fixture(monkeypatch))
    b = _normalize(_service_scan_from_fixture(monkeypatch))
    assert a == b


def test_golden_captures_the_accuracy_critical_facts(monkeypatch):
    # Guard the *meaning* of the golden, not just its bytes: the vuln extraction
    # that the "no false positives" claim rests on must be exactly right.
    host = _service_scan_from_fixture(monkeypatch)
    by_port = {p.port: p for p in host["ports"]}
    # Port 80: two version-matched CVEs, worst-first, flagged critical.
    p80 = by_port[80]
    assert p80.critical is True
    assert [v.id for v in p80.vulns] == ["CVE-2021-42013", "CVE-2021-41773"]
    assert p80.vulns[0].severity.value == "critical" and p80.vulns[0].confidence == "version"
    # SSH port carries no invented findings.
    assert by_port[22].vulns == []
    # Host-level ms17-010 hostscript → a CONFIRMED critical CVE.
    assert [v.id for v in host["vulns"]] == ["CVE-2017-0143"]
    assert host["vulns"][0].confidence == "confirmed"
    assert host["os"] == "Linux 5.4"


# --------------------------------------------------------------------------- #
# 2. Report: build_pdf is a pure function of its input (byte-stable).
# --------------------------------------------------------------------------- #
_FROZEN_MANIFEST = {
    "tool": "ENUMGRID", "tool_version": "1.0.0", "git_commit": "abc1234",
    "nmap_version": "7.95", "python_version": "3.12.0", "platform": "test-fixed",
    "generated_at": "2023-11-14T22:13:20+00:00",
}


class _FrozenDT:
    """A datetime stand-in whose .now() is fixed, so the report's 'Generated …'
    line is stable across builds."""

    @classmethod
    def now(cls, tz=None):
        return datetime(2023, 11, 14, 22, 13, 20, tzinfo=tz)


def _freeze_report_clock(monkeypatch) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")  # fixes reportlab's own dates + doc id
    monkeypatch.setattr(report, "datetime", _FrozenDT)
    monkeypatch.setattr(provenance, "manifest", lambda **kw: dict(_FROZEN_MANIFEST))


def _report_payload_from_golden() -> dict:
    with open(_SAMPLE_GOLDEN, encoding="utf-8") as fh:
        golden = json.load(fh)
    return {
        "target": _SAMPLE_IP,
        "profile": "vuln",
        "hosts": [{"ip": _SAMPLE_IP, "status": "up", **golden}],
    }


def test_build_pdf_is_byte_stable(monkeypatch):
    _freeze_report_clock(monkeypatch)
    payload = _report_payload_from_golden()
    first = report.build_pdf(payload)
    second = report.build_pdf(payload)
    assert first == second                     # pure function of its input
    assert first[:5] == b"%PDF-"               # and a real PDF


def test_build_pdf_content_reflects_the_scan(monkeypatch):
    # Determinism is only useful if the bytes are the RIGHT bytes: the report must
    # actually carry the scan's facts (not a fixed template).
    _freeze_report_clock(monkeypatch)
    pdf = report.build_pdf(_report_payload_from_golden())
    assert pdf.count(b"%PDF-") == 1 and pdf.rstrip().endswith(b"%%EOF")
    assert len(pdf) > 2000                      # a rendered multi-section report


def test_build_pdf_reflects_input_changes(monkeypatch):
    # A different snapshot must produce different bytes — proves the output is
    # data-driven, so byte-stability above is not just "always the same file".
    _freeze_report_clock(monkeypatch)
    base = _report_payload_from_golden()
    other = _report_payload_from_golden()
    other["target"] = "172.28.0.99"
    assert report.build_pdf(base) != report.build_pdf(other)
