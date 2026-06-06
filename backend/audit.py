"""
audit.py — append-only audit trail for accountability.

Every scan request (and refusal) is recorded as one JSON line: when, what, the
client, the mode, and a result summary. This is the minimum an authorized-use
tool needs so activity is attributable and reviewable after the fact. The log is
append-only JSONL (easy to ship to a SIEM/`tail -f`), best-effort, and never
blocks or breaks a scan.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone

_DIR = os.path.dirname(os.path.abspath(__file__))
AUDIT_LOG = os.environ.get("ENUMGRID_AUDIT_LOG", os.path.join(_DIR, "enumgrid_audit.log"))
_lock = threading.Lock()


def record(event: str, **fields) -> None:
    """Append one structured audit entry (best-effort)."""
    entry = {"ts": datetime.now(timezone.utc).isoformat(), "event": event, **fields}
    line = json.dumps(entry, default=str)
    try:
        with _lock, open(AUDIT_LOG, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass  # auditing must never break a scan


def tail(limit: int = 100) -> list[dict]:
    """Most recent audit entries (newest first) — powers an audit view/endpoint."""
    limit = max(1, min(int(limit), 1000))
    try:
        with open(AUDIT_LOG, encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return []
    out: list[dict] = []
    for line in reversed(lines[-limit:]):
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out
