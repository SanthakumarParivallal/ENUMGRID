"""
obs.py — structured (JSON) logging with request / scan correlation ids.

The per-report *provenance* manifest answers "what produced this artifact?". This
is its runtime companion: every API request is given a short **request id**
(accepted from an inbound ``X-Request-Id`` header if the caller sets one, else
generated), stamped on the response, and attached — via context variables — to
every log line emitted while the request is handled. Scan pipelines additionally
run under a **scan id**. So a finding on screen can be traced from the browser's
``X-Request-Id`` back through the structured log to the exact request and scan
that produced it.

Design:
  * one JSON object per line on stderr (parseable by any log pipeline), or a
    human-readable line when ``ENUMGRID_LOG_FORMAT=text``;
  * correlation ids come from context vars, so they attach automatically without
    every call site having to pass them;
  * level via ``ENUMGRID_LOG_LEVEL`` (default INFO). No secrets are ever logged —
    callers pass explicit fields, never tokens/passwords.
"""

from __future__ import annotations

import contextvars
import json
import logging
import os
import sys
import time
import uuid

# Correlation ids for the current request / scan (default "-" = none in scope).
_request_id: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")
_scan_id: contextvars.ContextVar[str] = contextvars.ContextVar("scan_id", default="-")

_LOGGER_NAME = "enumgrid"
_configured = False


def new_id() -> str:
    """A short, unique correlation id (12 hex chars — enough to be unambiguous)."""
    return uuid.uuid4().hex[:12]


def set_request_id(rid: str | None) -> str:
    """Set (or generate) the current request id; returns the effective value."""
    rid = (rid or "").strip() or new_id()
    _request_id.set(rid)
    return rid


def get_request_id() -> str:
    return _request_id.get()


def set_scan_id(sid: str | None) -> str:
    sid = (sid or "").strip() or "-"
    _scan_id.set(sid)
    return sid


def get_scan_id() -> str:
    return _scan_id.get()


def _ts(created: float, msecs: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(created)) + f".{int(msecs):03d}Z"


class _JsonFormatter(logging.Formatter):
    """One JSON object per line, with correlation ids pulled from context vars."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": _ts(record.created, record.msecs),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "request_id": _request_id.get(),
            "scan_id": _scan_id.get(),
        }
        extra = getattr(record, "fields", None)
        if isinstance(extra, dict):
            payload.update(extra)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class _TextFormatter(logging.Formatter):
    """Human-readable single line for local dev (ENUMGRID_LOG_FORMAT=text)."""

    def format(self, record: logging.LogRecord) -> str:
        extra = getattr(record, "fields", None)
        tail = ""
        if isinstance(extra, dict) and extra:
            tail = "  " + " ".join(f"{k}={v}" for k, v in extra.items())
        rid = _request_id.get()
        line = f"{_ts(record.created, record.msecs)} {record.levelname:<5} " \
               f"[{rid}] {record.name}: {record.getMessage()}{tail}"
        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        return line


def configure(level: str | None = None, fmt: str | None = None) -> None:
    """Install the structured handler on the ``enumgrid`` logger (idempotent)."""
    global _configured
    logger = logging.getLogger(_LOGGER_NAME)
    level = (level or os.environ.get("ENUMGRID_LOG_LEVEL", "INFO")).upper()
    logger.setLevel(getattr(logging, level, logging.INFO))
    fmt = (fmt or os.environ.get("ENUMGRID_LOG_FORMAT", "json")).lower()
    formatter = _TextFormatter() if fmt == "text" else _JsonFormatter()
    # Replace our own handlers so re-configuring (e.g. in tests) never double-logs.
    for h in list(logger.handlers):
        if getattr(h, "_enumgrid", False):
            logger.removeHandler(h)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(formatter)
    handler._enumgrid = True  # type: ignore[attr-defined]  # tag so we can find/replace it
    logger.addHandler(handler)
    logger.propagate = False  # don't double-emit through the root logger
    _configured = True


def get_logger() -> logging.Logger:
    """The shared app logger (configuring on first use so imports are safe)."""
    if not _configured:
        configure()
    return logging.getLogger(_LOGGER_NAME)


def log(level: int, msg: str, **fields) -> None:
    """Emit a structured record with arbitrary key/value ``fields`` attached.

    Fields must be non-sensitive (paths/counts/status — never tokens/passwords).
    """
    get_logger().log(level, msg, extra={"fields": fields})


def info(msg: str, **fields) -> None:
    log(logging.INFO, msg, **fields)


def warning(msg: str, **fields) -> None:
    log(logging.WARNING, msg, **fields)


def error(msg: str, **fields) -> None:
    log(logging.ERROR, msg, **fields)
