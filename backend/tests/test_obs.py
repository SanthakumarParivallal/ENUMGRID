"""
test_obs.py — structured logging + request/scan correlation ids.

Verifies the JSON/text formatters embed the context-var correlation ids and any
extra fields, that configuration is idempotent (no duplicate handlers), and that
the log helpers actually emit a record carrying the attached fields.
"""

from __future__ import annotations

import json
import logging

import obs


def test_new_id_is_short_and_unique():
    a, b = obs.new_id(), obs.new_id()
    assert len(a) == 12 and a != b


def test_request_and_scan_id_roundtrip():
    assert obs.set_request_id("abc") == "abc" and obs.get_request_id() == "abc"
    generated = obs.set_request_id(None)                 # blank/None → generated
    assert generated != "abc" and len(generated) == 12
    assert obs.set_scan_id("scan1") == "scan1" and obs.get_scan_id() == "scan1"
    assert obs.set_scan_id(None) == "-"                  # cleared


def test_json_formatter_includes_ids_and_fields():
    obs.set_request_id("req-1")
    obs.set_scan_id("scan-1")
    rec = logging.LogRecord("enumgrid", logging.INFO, __file__, 1, "hello", None, None)
    rec.fields = {"status": 200, "path": "/api/x"}
    out = json.loads(obs._JsonFormatter().format(rec))
    assert out["msg"] == "hello" and out["level"] == "INFO"
    assert out["request_id"] == "req-1" and out["scan_id"] == "scan-1"
    assert out["status"] == 200 and out["path"] == "/api/x"


def test_json_formatter_includes_exception():
    import sys
    try:
        raise ValueError("boom")
    except ValueError:
        rec = logging.LogRecord("enumgrid", logging.ERROR, __file__, 1, "failed", None, sys.exc_info())
    out = json.loads(obs._JsonFormatter().format(rec))
    assert "exc" in out and "ValueError" in out["exc"]


def test_text_formatter_is_human_readable():
    obs.set_request_id("req-2")
    rec = logging.LogRecord("enumgrid", logging.WARNING, __file__, 1, "watch out", None, None)
    rec.fields = {"n": 3}
    line = obs._TextFormatter().format(rec)
    assert "[req-2]" in line and "watch out" in line and "n=3" in line


def test_configure_is_idempotent():
    obs.configure()
    obs.configure()
    tagged = [h for h in logging.getLogger("enumgrid").handlers if getattr(h, "_enumgrid", False)]
    assert len(tagged) == 1                              # re-config replaces, never duplicates


def test_log_helpers_emit_records_with_fields():
    logger = obs.get_logger()
    captured: list[logging.LogRecord] = []

    class _Cap(logging.Handler):
        def emit(self, record): captured.append(record)

    handler = _Cap()
    logger.addHandler(handler)
    try:
        obs.set_request_id("emit-1")
        obs.info("did a thing", count=5)
        obs.warning("careful", code="x")
        obs.error("nope")
    finally:
        logger.removeHandler(handler)

    assert [r.getMessage() for r in captured] == ["did a thing", "careful", "nope"]
    assert captured[0].fields == {"count": 5}
    assert captured[0].levelno == logging.INFO and captured[2].levelno == logging.ERROR
