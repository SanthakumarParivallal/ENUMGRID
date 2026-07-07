"""
schedule.py — cron-style recurring scans.

The dashboard's monitor mode re-scans on a fixed *interval* while a tab is open.
This adds the other half: **unattended, time-of-day schedules** that fire even
with no browser connected — "sweep 192.168.0.0/24 every weekday at 02:00". When a
rule is due the backend enqueues a headless `network_scan` job (the same tested
pipeline the UI drives), so results land in history/drift automatically.

Design
------
* The recurrence math (`due`, `next_run`) and the spec parsers (`parse_days`,
  `parse_time`) are pure and fully unit-tested — deterministic given an injected
  ``now``. No clock, no threads, no I/O.
* `ScheduleStore` is a small thread-safe, JSON-persisted registry (add / list /
  remove / toggle) so rules survive a restart. The firing itself lives in app.py's
  background ticker, which just asks the store `due_now(now)` and enqueues a job.
"""

from __future__ import annotations

import json
import os
import re
import threading
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta

_DAY_NAMES = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}
_DAY_ABBR = {v: k for k, v in _DAY_NAMES.items()}
_VALID_MODES = ("discover", "full")


def default_path() -> str:
    """Where schedule rules persist (next to the history DB by default)."""
    return os.environ.get(
        "ENUMGRID_SCHEDULE_PATH",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "schedules.json"),
    )


def parse_days(spec) -> frozenset[int]:
    """`"mon,wed,fri"` / `"1,3,5"` / `["mon","wed"]` / `"*"` / `""` / `None` →
    weekday set (0=Mon). Empty or `"*"` = every day.

    Accepts either a comma-separated string (what the cockpit UI sends and what we
    persist) or a list/tuple of tokens (the natural JSON-array shape an API client
    may send), so neither form can 500 the schedule endpoint."""
    if spec is None:
        return frozenset()
    if isinstance(spec, (list, tuple, set, frozenset)):
        tokens = [str(t) for t in spec]
    else:
        text = str(spec).strip()
        if text in ("*", ""):
            return frozenset()
        tokens = text.split(",")
    out: set[int] = set()
    for token in tokens:
        tok = token.strip().lower()
        if tok in ("", "*"):          # skip padding / a stray "*" inside a list
            continue
        if tok in _DAY_NAMES:
            out.add(_DAY_NAMES[tok])
        elif tok.isdigit() and 0 <= int(tok) <= 6:
            out.add(int(tok))
        else:
            raise ValueError(f"invalid day '{token}' (use mon..sun or 0..6)")
    return frozenset(out)


def parse_time(spec: str) -> tuple[int, int]:
    """`"HH:MM"` (24h) → (hour, minute). Raises ValueError on a bad shape."""
    match = re.fullmatch(r"\s*([01]?\d|2[0-3]):([0-5]\d)\s*", spec or "")
    if not match:
        raise ValueError(f"invalid time '{spec}' (use HH:MM, 24-hour)")
    return int(match.group(1)), int(match.group(2))


def format_days(days: frozenset[int]) -> str:
    """Human/round-trippable rendering of a weekday set."""
    if not days:
        return "*"
    return ",".join(_DAY_ABBR[d] for d in sorted(days))


@dataclass(frozen=True)
class Schedule:
    """One recurring scan rule."""

    id: str
    target: str
    mode: str = "discover"            # "discover" (fast) or "full" (nmap -sV)
    deep: bool = False                # NSE vuln scripts (full mode only)
    days: frozenset[int] = field(default_factory=frozenset)  # empty = every day
    hour: int = 0
    minute: int = 0
    enabled: bool = True

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "target": self.target,
            "mode": self.mode,
            "deep": self.deep,
            "days": format_days(self.days),
            "at": f"{self.hour:02d}:{self.minute:02d}",
            "enabled": self.enabled,
        }

    @staticmethod
    def from_dict(data: dict) -> "Schedule":
        hour, minute = parse_time(data.get("at", "00:00"))
        return Schedule(
            id=str(data["id"]),
            target=str(data["target"]),
            mode=str(data.get("mode", "discover")),
            deep=bool(data.get("deep", False)),
            days=parse_days(data.get("days")),
            hour=hour,
            minute=minute,
            enabled=bool(data.get("enabled", True)),
        )


def due(sched: Schedule, now: datetime, last_run: datetime | None = None) -> bool:
    """True when ``sched`` should fire at ``now`` and hasn't already this minute."""
    if not sched.enabled:
        return False
    if sched.days and now.weekday() not in sched.days:
        return False
    if now.hour != sched.hour or now.minute != sched.minute:
        return False
    if last_run is not None and _same_minute(last_run, now):
        return False  # de-dupe: a 30s ticker can see the same minute twice
    return True


def next_run(sched: Schedule, now: datetime) -> datetime | None:
    """The next datetime (strictly after ``now``) this rule will fire."""
    base = now.replace(second=0, microsecond=0)
    for add in range(0, 8):
        candidate = (base + timedelta(days=add)).replace(hour=sched.hour, minute=sched.minute)
        if candidate <= now:
            continue
        if not sched.days or candidate.weekday() in sched.days:
            return candidate
    return None


def _same_minute(a: datetime, b: datetime) -> bool:
    return (a.year, a.month, a.day, a.hour, a.minute) == (b.year, b.month, b.day, b.hour, b.minute)


class ScheduleStore:
    """Thread-safe, JSON-persisted registry of `Schedule` rules."""

    def __init__(self, path: str | None = None) -> None:
        self._path = path
        self._lock = threading.RLock()
        self._rules: dict[str, Schedule] = {}
        self._last_run: dict[str, datetime] = {}
        if path and os.path.exists(path):
            self._load()

    # -- persistence -------------------------------------------------------- #
    def _load(self) -> None:
        try:
            with open(self._path, encoding="utf-8") as fh:
                raw = json.load(fh)
        except (OSError, ValueError):
            return
        for item in raw.get("schedules", []):
            try:
                sched = Schedule.from_dict(item)
                self._rules[sched.id] = sched
            except (KeyError, ValueError):
                continue  # skip a corrupt entry rather than fail the whole load

    def _save(self) -> None:
        if not self._path:
            return
        data = {"schedules": [s.to_dict() for s in self._rules.values()]}
        tmp = f"{self._path}.tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self._path)
        except OSError:
            pass  # best-effort persistence; the in-memory store stays authoritative

    # -- CRUD --------------------------------------------------------------- #
    def add(self, *, target: str, at: str, days: str | None = None,
            mode: str = "discover", deep: bool = False, enabled: bool = True) -> Schedule:
        hour, minute = parse_time(at)
        day_set = parse_days(days)
        if mode not in _VALID_MODES:
            raise ValueError(f"invalid mode '{mode}' (use {' or '.join(_VALID_MODES)})")
        sched = Schedule(
            id=uuid.uuid4().hex[:12], target=target, mode=mode, deep=bool(deep),
            days=day_set, hour=hour, minute=minute, enabled=bool(enabled),
        )
        with self._lock:
            self._rules[sched.id] = sched
            self._save()
        return sched

    def remove(self, sched_id: str) -> bool:
        with self._lock:
            existed = self._rules.pop(sched_id, None) is not None
            self._last_run.pop(sched_id, None)
            if existed:
                self._save()
        return existed

    def toggle(self, sched_id: str, enabled: bool) -> Schedule | None:
        with self._lock:
            sched = self._rules.get(sched_id)
            if sched is None:
                return None
            updated = replace(sched, enabled=bool(enabled))
            self._rules[sched_id] = updated
            self._save()
        return updated

    def list(self) -> list[Schedule]:
        with self._lock:
            return sorted(self._rules.values(), key=lambda s: (s.hour, s.minute, s.target))

    # -- firing ------------------------------------------------------------- #
    def due_now(self, now: datetime) -> list[Schedule]:
        """Rules that should fire at ``now``; marks each as run to avoid repeats."""
        fired: list[Schedule] = []
        with self._lock:
            for sched in self._rules.values():
                if due(sched, now, self._last_run.get(sched.id)):
                    self._last_run[sched.id] = now
                    fired.append(sched)
        return fired
