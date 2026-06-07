"""
jobs.py — a persistent scan-job queue with a bounded worker pool.

The synchronous request → scan model doesn't scale: a big sweep ties up the
request, and there's no way to queue work or survive a restart. This adds a real
job queue — submit a scan, get a job id, poll for the result — backed by SQLite
and drained by a fixed pool of background workers (so load is bounded, not a
fork-bomb). Jobs persist across restarts.

This is the architecture for scale: it scales *vertically* now (more workers per
host) and the SQLite queue is deliberately swappable for Redis/SQS to scale
*horizontally* across machines — the worker logic is unchanged. The persistence
and atomic-claim logic are fully unit-tested.
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import time
from collections.abc import Callable
from contextlib import contextmanager

_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("ENUMGRID_JOBS_DB", os.path.join(_DIR, "enumgrid_jobs.db"))
WORKERS = max(1, int(os.environ.get("ENUMGRID_JOB_WORKERS", "2")))

STATUS_QUEUED, STATUS_RUNNING, STATUS_DONE, STATUS_ERROR = "queued", "running", "done", "error"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL,
    params      TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'queued',
    result      TEXT,
    error       TEXT,
    created_at  REAL NOT NULL,
    started_at  REAL,
    finished_at REAL
);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status, id);
"""


@contextmanager
def _conn():
    """Queue connection that commits, rolls back on error, and always closes.

    Preserves the existing ``with _conn() as conn:`` commit semantics (so
    ``claim_next``'s explicit BEGIN IMMEDIATE/COMMIT still works) while ensuring
    the handle is released instead of leaking until GC."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def enqueue(kind: str, params: dict | None = None) -> int:
    """Add a job to the queue; returns its id."""
    with _conn() as conn:
        cur = conn.execute(
            "INSERT INTO jobs (kind, params, status, created_at) VALUES (?, ?, ?, ?)",
            (kind, json.dumps(params or {}), STATUS_QUEUED, time.time()),
        )
        return int(cur.lastrowid)


def _row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    for k in ("params", "result"):
        if d.get(k):
            try:
                d[k] = json.loads(d[k])
            except (TypeError, ValueError):
                pass
    return d


def get(job_id: int) -> dict | None:
    with _conn() as conn:
        row = conn.execute("SELECT * FROM jobs WHERE id = ?", (int(job_id),)).fetchone()
    return _row_to_dict(row) if row else None


def list_jobs(limit: int = 50) -> list[dict]:
    limit = max(1, min(int(limit), 500))
    with _conn() as conn:
        rows = conn.execute(
            "SELECT id, kind, status, created_at, started_at, finished_at, error "
            "FROM jobs ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def claim_next() -> dict | None:
    """Atomically take the oldest queued job and mark it running (or None)."""
    with _conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM jobs WHERE status = ? ORDER BY id LIMIT 1", (STATUS_QUEUED,)
        ).fetchone()
        if not row:
            conn.execute("COMMIT")
            return None
        started = time.time()
        conn.execute(
            "UPDATE jobs SET status = ?, started_at = ? WHERE id = ?",
            (STATUS_RUNNING, started, row["id"]),
        )
        conn.execute("COMMIT")
    job = _row_to_dict(row)
    job["status"] = STATUS_RUNNING  # reflect the claim in the returned record
    job["started_at"] = started
    return job


def complete(job_id: int, result: dict) -> None:
    with _conn() as conn:
        conn.execute(
            "UPDATE jobs SET status = ?, result = ?, finished_at = ? WHERE id = ?",
            (STATUS_DONE, json.dumps(result), time.time(), int(job_id)),
        )


def fail(job_id: int, error: str) -> None:
    with _conn() as conn:
        conn.execute(
            "UPDATE jobs SET status = ?, error = ?, finished_at = ? WHERE id = ?",
            (STATUS_ERROR, str(error)[:500], time.time(), int(job_id)),
        )


def process_one(handlers: dict[str, Callable[[dict], dict]]) -> bool:
    """Claim and run one queued job with the matching handler.

    Returns True if a job was processed, False if the queue was empty. Sync and
    deterministic — this is the unit-tested core of the worker.
    """
    job = claim_next()
    if not job:
        return False
    handler = handlers.get(job["kind"])
    if handler is None:
        fail(job["id"], f"no handler for kind '{job['kind']}'")
        return True
    try:
        result = handler(job.get("params") or {})
        complete(job["id"], result if isinstance(result, dict) else {"result": result})
    except Exception as exc:  # noqa: BLE001 - a failed job must not kill the worker
        fail(job["id"], f"{type(exc).__name__}: {exc}")
    return True


async def run_workers(handlers: dict[str, Callable[[dict], dict]], stop: asyncio.Event) -> None:
    """Drain the queue with `WORKERS` background coroutines until `stop` is set.

    Handlers run in a thread (via the default executor) so a blocking nmap scan
    never stalls the event loop.
    """
    loop = asyncio.get_running_loop()

    async def worker() -> None:
        while not stop.is_set():
            did = await loop.run_in_executor(None, process_one, handlers)
            await asyncio.sleep(0.05 if did else 0.5)

    await asyncio.gather(*(worker() for _ in range(WORKERS)))
