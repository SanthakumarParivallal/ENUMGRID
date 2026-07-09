"""
test_schedule.py — cron-style recurrence math + the persisted rule store.

All timing is deterministic (an explicit `now` is injected), so these verify the
firing decision, next-run computation, spec parsing, and JSON persistence without
any clock or real scan.
"""

from __future__ import annotations

from datetime import datetime

import pytest
import schedule as sch


# --- spec parsing ----------------------------------------------------------- #
def test_parse_days_names_digits_and_wildcard():
    assert sch.parse_days("mon,wed,fri") == frozenset({0, 2, 4})
    assert sch.parse_days("1,3,5") == frozenset({1, 3, 5})
    assert sch.parse_days("*") == frozenset()
    assert sch.parse_days("") == frozenset()
    assert sch.parse_days(None) == frozenset()


def test_parse_days_accepts_list_form():
    # An API client may send `days` as a JSON array rather than a comma-string;
    # both must parse identically (regression: a list used to raise AttributeError).
    assert sch.parse_days(["mon", "wed"]) == frozenset({0, 2})
    assert sch.parse_days([1, 3, 5]) == frozenset({1, 3, 5})   # ints too
    assert sch.parse_days([]) == frozenset()                   # empty list = daily
    assert sch.parse_days(["*"]) == frozenset()                # stray wildcard token
    with pytest.raises(ValueError):
        sch.parse_days(["mon", "funday"])                      # junk in a list still rejected


def test_store_add_accepts_list_days(tmp_path):
    # The exact 500 path: POST /api/schedules forwards `days` from JSON as a list.
    store = sch.ScheduleStore(str(tmp_path / "s.json"))
    r = store.add(target="192.168.0.0/24", at="03:30", days=["mon", "wed"], mode="discover")
    assert r.days == frozenset({0, 2})
    assert r.to_dict()["days"] == "mon,wed"


def test_parse_days_rejects_junk():
    with pytest.raises(ValueError):
        sch.parse_days("funday")
    with pytest.raises(ValueError):
        sch.parse_days("9")


def test_parse_time_valid_and_invalid():
    assert sch.parse_time("02:00") == (2, 0)
    assert sch.parse_time("23:59") == (23, 59)
    for bad in ("24:00", "9:99", "noon", "", "2am"):
        with pytest.raises(ValueError):
            sch.parse_time(bad)


def test_schedule_roundtrips_through_dict():
    s = sch.Schedule(id="abc", target="192.168.0.0/24", mode="full", deep=True,
                     days=frozenset({0, 4}), hour=2, minute=30)
    d = s.to_dict()
    assert d["at"] == "02:30" and d["days"] == "mon,fri" and d["mode"] == "full"
    assert sch.Schedule.from_dict(d) == s


# --- due / next_run --------------------------------------------------------- #
def _rule(**kw):
    base = dict(id="r1", target="192.168.0.0/24", hour=2, minute=0)
    base.update(kw)
    return sch.Schedule(**base)


def test_due_only_on_matching_minute():
    r = _rule()
    assert sch.due(r, datetime(2026, 7, 6, 2, 0)) is True     # Monday 02:00
    assert sch.due(r, datetime(2026, 7, 6, 2, 1)) is False    # wrong minute
    assert sch.due(r, datetime(2026, 7, 6, 3, 0)) is False    # wrong hour


def test_due_respects_days_and_enabled():
    weekday_rule = _rule(days=frozenset({0, 1, 2, 3, 4}))     # Mon-Fri
    assert sch.due(weekday_rule, datetime(2026, 7, 6, 2, 0)) is True    # Monday
    assert sch.due(weekday_rule, datetime(2026, 7, 5, 2, 0)) is False   # Sunday
    assert sch.due(_rule(enabled=False), datetime(2026, 7, 6, 2, 0)) is False


def test_due_dedupes_within_the_same_minute():
    r = _rule()
    now = datetime(2026, 7, 6, 2, 0, 15)
    assert sch.due(r, now, last_run=None) is True
    assert sch.due(r, now, last_run=datetime(2026, 7, 6, 2, 0, 5)) is False  # already ran


def test_next_run_daily_and_weekly():
    daily = _rule()
    # 01:00 Monday → next fire is 02:00 the same day.
    assert sch.next_run(daily, datetime(2026, 7, 6, 1, 0)) == datetime(2026, 7, 6, 2, 0)
    # 03:00 Monday (past today's 02:00) → 02:00 Tuesday.
    assert sch.next_run(daily, datetime(2026, 7, 6, 3, 0)) == datetime(2026, 7, 7, 2, 0)
    # Weekly Fri-only from a Monday → the coming Friday.
    fri = _rule(days=frozenset({4}))
    assert sch.next_run(fri, datetime(2026, 7, 6, 3, 0)) == datetime(2026, 7, 10, 2, 0)


# --- store: CRUD + persistence --------------------------------------------- #
def test_store_add_list_remove_toggle(tmp_path):
    store = sch.ScheduleStore(str(tmp_path / "s.json"))
    r = store.add(target="192.168.0.0/24", at="02:00", days="mon,fri", mode="full")
    assert [s.id for s in store.list()] == [r.id]
    toggled = store.toggle(r.id, enabled=False)
    assert toggled.enabled is False
    assert store.toggle("nope", enabled=True) is None
    assert store.remove(r.id) is True
    assert store.remove(r.id) is False
    assert store.list() == []


def test_store_persists_across_reload(tmp_path):
    path = str(tmp_path / "s.json")
    store = sch.ScheduleStore(path)
    store.add(target="10.0.0.0/24", at="03:15", days="*")
    # A fresh store on the same path recovers the rule.
    reopened = sch.ScheduleStore(path)
    rules = reopened.list()
    assert len(rules) == 1
    assert rules[0].target == "10.0.0.0/24" and rules[0].hour == 3 and rules[0].minute == 15


def test_store_add_rejects_bad_mode(tmp_path):
    store = sch.ScheduleStore(str(tmp_path / "s.json"))
    with pytest.raises(ValueError):
        store.add(target="10.0.0.0/24", at="02:00", mode="bogus")


def test_due_now_fires_once_per_minute(tmp_path):
    store = sch.ScheduleStore(str(tmp_path / "s.json"))
    store.add(target="10.0.0.0/24", at="02:00", days="*")
    now = datetime(2026, 7, 6, 2, 0, 10)
    assert len(store.due_now(now)) == 1          # first tick fires it
    assert store.due_now(datetime(2026, 7, 6, 2, 0, 40)) == []  # second tick, same minute


def test_default_path_points_at_a_json_file():
    assert sch.default_path().endswith("schedules.json")


def test_next_run_none_when_no_weekday_ever_matches():
    # Defensive fallback: a rule whose day-set can't match any real weekday (0..6)
    # has no next fire, and next_run reports that honestly instead of looping forever.
    s = sch.Schedule(id="x", target="t", days=frozenset({99}), hour=3, minute=0)
    assert sch.next_run(s, datetime(2026, 7, 8, 12, 0)) is None


def test_store_load_ignores_missing_and_corrupt_files(tmp_path):
    corrupt = tmp_path / "bad.json"
    corrupt.write_text("{ not json", encoding="utf-8")
    assert sch.ScheduleStore(str(corrupt)).list() == []         # corrupt file → empty, no raise


def test_store_load_skips_corrupt_entries(tmp_path):
    import json
    path = tmp_path / "s.json"
    good = {"id": "a", "target": "10.0.0.0/24", "at": "02:00", "mode": "discover",
            "deep": False, "days": "*", "enabled": True}
    path.write_text(json.dumps({"schedules": [good, {"id": "b"}]}), encoding="utf-8")  # 2nd lacks 'target'
    rules = sch.ScheduleStore(str(path)).list()
    assert [r.id for r in rules] == ["a"]                       # corrupt entry skipped, good kept


def test_store_without_path_does_not_persist():
    store = sch.ScheduleStore(None)                             # in-memory only
    rule = store.add(target="10.0.0.0/24", at="02:00")         # _save early-returns (no path)
    assert store.list() == [rule]


def test_store_save_swallows_write_errors(tmp_path):
    # Point the store at a path whose parent is a file, not a dir → the atomic write
    # fails; persistence is best-effort so the in-memory store stays authoritative.
    blocker = tmp_path / "blocker"
    blocker.write_text("x", encoding="utf-8")
    store = sch.ScheduleStore(str(blocker / "s.json"))
    rule = store.add(target="10.0.0.0/24", at="02:00")         # write fails, no raise
    assert store.list() == [rule]
