"""test_jobs.py — persistent job queue + atomic claim + worker core."""

from __future__ import annotations

import jobs
import pytest


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(jobs, "DB_PATH", str(tmp_path / "jobs.db"))


def test_enqueue_get_list():
    jid = jobs.enqueue("scan", {"target": "10.0.0.0/24"})
    job = jobs.get(jid)
    assert job["kind"] == "scan" and job["status"] == jobs.STATUS_QUEUED
    assert job["params"]["target"] == "10.0.0.0/24"
    assert len(jobs.list_jobs()) == 1


def test_claim_is_atomic_and_fifo():
    a = jobs.enqueue("scan", {"n": 1})
    jobs.enqueue("scan", {"n": 2})
    claimed = jobs.claim_next()
    assert claimed["id"] == a and claimed["status"] == jobs.STATUS_RUNNING
    # the claimed job is no longer queued (won't be handed out twice)
    again = jobs.claim_next()
    assert again["id"] != a


def test_claim_empty_returns_none():
    assert jobs.claim_next() is None


def test_complete_and_fail():
    j1 = jobs.enqueue("scan")
    jobs.claim_next()
    jobs.complete(j1, {"hosts_up": 5})
    done = jobs.get(j1)
    assert done["status"] == jobs.STATUS_DONE and done["result"]["hosts_up"] == 5

    j2 = jobs.enqueue("scan")
    jobs.claim_next()
    jobs.fail(j2, "boom")
    assert jobs.get(j2)["status"] == jobs.STATUS_ERROR


def test_process_one_runs_handler():
    seen = {}
    jobs.enqueue("scan", {"target": "x"})
    handled = jobs.process_one({"scan": lambda p: seen.update(p) or {"ok": True}})
    assert handled is True
    assert seen == {"target": "x"}
    assert jobs.process_one({"scan": lambda p: {}}) is False  # queue now empty


def test_process_one_unknown_kind_fails_job():
    jid = jobs.enqueue("weird")
    assert jobs.process_one({"scan": lambda p: {}}) is True
    assert jobs.get(jid)["status"] == jobs.STATUS_ERROR


def test_process_one_handler_exception_is_caught():
    jid = jobs.enqueue("scan")

    def boom(_):
        raise RuntimeError("kaboom")

    assert jobs.process_one({"scan": boom}) is True
    job = jobs.get(jid)
    assert job["status"] == jobs.STATUS_ERROR and "kaboom" in job["error"]
