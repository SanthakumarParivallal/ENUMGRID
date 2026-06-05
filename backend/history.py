"""
history.py — lightweight SQLite persistence for scan history + drift.

Every completed scan is stored as a row (with its full `ScanState` snapshot as
JSON), so the dashboard can show a real timeline and answer "what changed since
last time?" — new/gone devices and opened/closed ports — instead of treating
each scan as a blank slate.

Drift is computed by reusing the CLI's already-tested `diff_reports()`
(`purple_recon.py`), so the comparison logic lives in exactly one place. The
stored snapshot shape (`hosts[].ip / os / ports[].port/service/version`) is a
superset of what `diff_reports` needs, so it feeds straight in.

The store is intentionally tiny and dependency-free (stdlib `sqlite3`); the DB
path is `PURPLERECON_DB` (defaults next to this file). Best-effort throughout:
persistence never breaks a scan.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys

# Reuse the CLI's diff engine (single source of truth for drift).
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
import purple_recon as pr  # noqa: E402

DB_PATH = os.environ.get(
    "PURPLERECON_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "purplerecon_history.db")
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      TEXT,
    target       TEXT NOT NULL,
    mode         TEXT NOT NULL DEFAULT 'discover',
    started_at   REAL,
    finished_at  REAL,
    host_count   INTEGER NOT NULL DEFAULT 0,
    up_count     INTEGER NOT NULL DEFAULT 0,
    open_ports   INTEGER NOT NULL DEFAULT 0,
    snapshot     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target, id);
"""

# Columns returned for list/summary views (everything except the heavy snapshot).
_SUMMARY_COLS = (
    "id, scan_id, target, mode, started_at, finished_at, "
    "host_count, up_count, open_ports"
)


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create the schema if it doesn't exist (idempotent)."""
    with _connect() as conn:
        conn.executescript(_SCHEMA)


def _counts(snapshot: dict) -> tuple[int, int, int]:
    hosts = snapshot.get("hosts") or []
    up = sum(1 for h in hosts if h.get("status") == "up")
    open_ports = sum(
        1
        for h in hosts
        for p in (h.get("ports") or [])
        if p.get("state") in ("open", "open|filtered")
    )
    return len(hosts), up, open_ports


def save_scan(snapshot: dict, mode: str = "discover") -> int:
    """Persist a completed scan snapshot (dict). Returns the new row id."""
    host_count, up_count, open_ports = _counts(snapshot)
    init_db()
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO scans "
            "(scan_id, target, mode, started_at, finished_at, host_count, up_count, open_ports, snapshot) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                snapshot.get("scan_id"),
                snapshot.get("target", ""),
                mode,
                snapshot.get("started_at"),
                snapshot.get("finished_at"),
                host_count,
                up_count,
                open_ports,
                json.dumps(snapshot),
            ),
        )
        return int(cur.lastrowid)


def list_scans(target: str | None = None, limit: int = 50) -> list[dict]:
    """Recent scan summaries (newest first), optionally filtered by target."""
    init_db()
    limit = max(1, min(int(limit), 500))
    with _connect() as conn:
        # NB: the only interpolated value (`_SUMMARY_COLS`) is a hardcoded module
        # constant — never user input. All user-supplied values (target, limit)
        # are bound via `?` placeholders, so this is not an injection vector.
        if target:
            rows = conn.execute(
                f"SELECT {_SUMMARY_COLS} FROM scans WHERE target = ? ORDER BY id DESC LIMIT ?",  # nosec B608
                (target, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                f"SELECT {_SUMMARY_COLS} FROM scans ORDER BY id DESC LIMIT ?",  # nosec B608
                (limit,),
            ).fetchall()
    return [dict(r) for r in rows]


def get_scan(row_id: int) -> dict | None:
    """Full stored row (including the parsed snapshot) for one scan, or None."""
    init_db()
    with _connect() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (int(row_id),)).fetchone()
    if row is None:
        return None
    data = dict(row)
    try:
        data["snapshot"] = json.loads(data["snapshot"])
    except (TypeError, ValueError):
        data["snapshot"] = {}
    return data


def _enrich(ips: list[str], snapshot: dict) -> list[dict]:
    """Attach vendor/hostname/mac to a list of IPs from a snapshot's hosts."""
    by_ip = {h.get("ip"): h for h in (snapshot.get("hosts") or [])}
    out = []
    for ip in ips:
        h = by_ip.get(ip, {})
        out.append(
            {
                "ip": ip,
                "vendor": h.get("vendor"),
                "hostname": h.get("hostname"),
                "mac": h.get("mac"),
            }
        )
    return out


def drift_for_target(target: str) -> dict:
    """Compare the two most recent scans for `target` and describe the change.

    Returns a structured drift report. `available` is False when there aren't yet
    two scans to compare (the first scan establishes the baseline).
    """
    scans = list_scans(target, limit=2)
    if len(scans) < 2:
        return {
            "available": False,
            "target": target,
            "scan_count": len(scans),
            "has_changes": False,
        }

    new_row = get_scan(scans[0]["id"]) or {}
    old_row = get_scan(scans[1]["id"]) or {}
    new_snap = new_row.get("snapshot") or {}
    old_snap = old_row.get("snapshot") or {}

    diff = pr.diff_reports(old_snap, new_snap)
    return {
        "available": True,
        "target": target,
        "baseline_finished_at": old_snap.get("finished_at"),
        "current_finished_at": new_snap.get("finished_at"),
        "has_changes": diff["has_changes"],
        # Enrich bare IP lists with vendor/hostname so the UI can label devices.
        "appeared_hosts": _enrich(diff["appeared_hosts"], new_snap),
        "disappeared_hosts": _enrich(diff["disappeared_hosts"], old_snap),
        "changed_hosts": diff["changed_hosts"],
    }
