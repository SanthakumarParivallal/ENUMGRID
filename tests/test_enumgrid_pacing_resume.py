"""test_enumgrid_pacing_resume.py: rate limiting (--max-rate/--timing) and --resume.

Two publication gaps closed here:
  * a packet-per-second ceiling (RateLimiter) so ENUMGRID can run on fragile
    networks that permit a scan only under a hard rate cap, and
  * a crash-recoverable checkpoint (--resume) so a long scan that dies part way
    continues instead of starting over.

Everything is deterministic and offline: pacing is asserted with the monotonic
clock, and the resume path is driven through fake engines (no sockets, no nmap).
"""

from __future__ import annotations

import json
import time
from types import SimpleNamespace

import pytest

import purple_recon as pr


# --------------------------------------------------------------------------- #
# RateLimiter
# --------------------------------------------------------------------------- #
def test_rate_limiter_disabled_is_noop():
    lim = pr.RateLimiter(None)
    t0 = time.monotonic()
    for _ in range(2000):
        lim.acquire()
    assert time.monotonic() - t0 < 0.1  # no sleeping when disabled


def test_rate_limiter_zero_or_negative_disables():
    assert pr.RateLimiter(0).max_rate is None
    assert pr.RateLimiter(-5).max_rate is None


def test_rate_limiter_paces_to_ceiling():
    # 10 pps: an initial burst up to the capacity, then paced. 25 acquisitions
    # take roughly (25 - 10) / 10 = 1.5s. Bound loosely to avoid CI flakiness.
    lim = pr.RateLimiter(10)
    t0 = time.monotonic()
    for _ in range(25):
        lim.acquire()
    dt = time.monotonic() - t0
    assert 1.0 <= dt <= 2.5, dt


def test_rate_limiter_thread_safe():
    import threading
    lim = pr.RateLimiter(50)
    errors = []

    def worker():
        try:
            for _ in range(10):
                lim.acquire()
        except Exception as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert not errors


# --------------------------------------------------------------------------- #
# build_nmap_args: timing + rate flags
# --------------------------------------------------------------------------- #
def _args(**kw):
    base = dict(full=False, ports=None, top_ports=100, host_timeout="120s",
                timing=4, max_rate=None, min_rate=None)
    base.update(kw)
    return SimpleNamespace(**base)


def test_build_nmap_args_default_timing():
    assert "-T4" in pr.build_nmap_args(_args(), privileged=False)


def test_build_nmap_args_custom_timing():
    assert "-T2" in pr.build_nmap_args(_args(timing=2), privileged=False)


def test_build_nmap_args_rate_flags():
    a = pr.build_nmap_args(_args(max_rate=50, min_rate=10), privileged=False)
    assert "--max-rate 50" in a and "--min-rate 10" in a


def test_build_nmap_args_no_rate_flags_by_default():
    a = pr.build_nmap_args(_args(), privileged=False)
    assert "--max-rate" not in a and "--min-rate" not in a


# --------------------------------------------------------------------------- #
# validate_scan_options: timing + rate validation
# --------------------------------------------------------------------------- #
def _full_args(**kw):
    base = dict(top_ports=100, ports=None, host_timeout="120s", sweep_workers=128,
                scan_workers=8, max_hosts=4096, timing=4, max_rate=None, min_rate=None)
    base.update(kw)
    return SimpleNamespace(**base)


@pytest.mark.parametrize("timing", [-1, 6, 10])
def test_validate_rejects_bad_timing(timing):
    with pytest.raises(pr.ScopeError):
        pr.validate_scan_options(_full_args(timing=timing))


@pytest.mark.parametrize("timing", [0, 3, 5])
def test_validate_accepts_good_timing(timing):
    pr.validate_scan_options(_full_args(timing=timing))  # no raise


@pytest.mark.parametrize("field", ["max_rate", "min_rate"])
def test_validate_rejects_rate_below_one(field):
    with pytest.raises(pr.ScopeError):
        pr.validate_scan_options(_full_args(**{field: 0}))


def test_validate_rejects_min_rate_above_max_rate():
    with pytest.raises(pr.ScopeError):
        pr.validate_scan_options(_full_args(max_rate=10, min_rate=50))


def test_validate_accepts_min_le_max():
    pr.validate_scan_options(_full_args(max_rate=100, min_rate=10))  # no raise


# --------------------------------------------------------------------------- #
# Checkpoint / ResumeState
# --------------------------------------------------------------------------- #
def _state_with(target, records):
    st = pr.SharedState(target=target, privileged=False, engine_label="socket-scan")
    for r in records:
        st.load_record(r)
    return st


def test_checkpoint_save_load_roundtrip(tmp_path):
    cp_path = str(tmp_path / "scan.state")
    st = _state_with("192.168.0.1-4", [
        pr.HostRecord(ip="192.168.0.1", state="DONE", status="up",
                      ports=[pr.PortRecord(port=80, service="http", product="nginx")],
                      open_count=1),
        pr.HostRecord(ip="192.168.0.2", state="DONE", status="up"),
        pr.HostRecord(ip="192.168.0.3", state="SCANNING", status="up"),
    ])
    cp = pr.Checkpoint(cp_path)
    cp.save(st, ["192.168.0.1", "192.168.0.2", "192.168.0.3", "192.168.0.4"], swept=True)

    import os
    assert oct(os.stat(cp_path).st_mode & 0o777) == "0o600"  # least-privilege

    loaded = pr.Checkpoint.load(cp_path)
    assert loaded.target == "192.168.0.1-4"
    assert loaded.swept is True
    assert loaded.live == ["192.168.0.1", "192.168.0.2", "192.168.0.3"]
    # DONE hosts are enumerated; the SCANNING (crashed mid-scan) host is not.
    assert loaded.enumerated == {"192.168.0.1", "192.168.0.2"}
    rec = {r.ip: r for r in loaded.records}
    assert rec["192.168.0.1"].ports[0].service == "http"  # port survives reload


def test_checkpoint_load_rejects_foreign_file(tmp_path):
    p = tmp_path / "not.json"
    p.write_text(json.dumps({"kind": "something-else", "hosts": []}))
    with pytest.raises(ValueError):
        pr.Checkpoint.load(str(p))


def test_checkpoint_load_tolerates_extra_and_missing_keys(tmp_path):
    p = tmp_path / "cp.json"
    p.write_text(json.dumps({
        "kind": "enumgrid-checkpoint",
        "target": "10.0.0.0/30",
        "hosts": [{"ip": "10.0.0.1", "state": "DONE", "unknown_field": "ignored",
                   "ports": [{"port": 22, "service": "ssh", "bogus": 1}]}],
    }))
    loaded = pr.Checkpoint.load(str(p))
    assert loaded.swept is False  # missing key defaults
    assert loaded.records[0].ip == "10.0.0.1"
    assert loaded.records[0].ports[0].port == 22  # bogus field dropped, port kept


def test_checkpoint_discard_removes_and_tolerates_absent(tmp_path):
    p = tmp_path / "cp.json"
    p.write_text("{}")
    cp = pr.Checkpoint(str(p))
    cp.discard()
    assert not p.exists()
    cp.discard()  # second discard is a no-op, no raise


# --------------------------------------------------------------------------- #
# Orchestrator resume behaviour (fake engines)
# --------------------------------------------------------------------------- #
class _FakeDiscovery:
    def __init__(self, live=()):
        self.live = live
        self.swept = False

    def sweep(self, hosts, state):
        self.swept = True
        for ip in self.live:
            state.add_live_host(ip, "icmp", [], "strong")


class _RecordingEnum:
    def __init__(self):
        self.ran_with = None
        self.progress_calls = 0

    def run(self, ips, state, on_progress=None):
        self.ran_with = list(ips)
        for ip in ips:
            state.update_host_record(pr.HostRecord(ip=ip, state="DONE", status="up"))
            state.mark_enum_done()
            if on_progress is not None:
                on_progress()
                self.progress_calls += 1


def test_resume_skips_sweep_and_only_scans_pending(tmp_path):
    # Build a checkpoint: .1 DONE, .2 and .3 discovered-but-pending.
    st0 = _state_with("t", [
        pr.HostRecord(ip="10.0.0.1", state="DONE", status="up"),
        pr.HostRecord(ip="10.0.0.2", state="DISCOVERED", status="up"),
        pr.HostRecord(ip="10.0.0.3", state="SCANNING", status="up"),
    ])
    cp_path = str(tmp_path / "r.state")
    pr.Checkpoint(cp_path).save(st0, ["10.0.0.1", "10.0.0.2", "10.0.0.3"], swept=True)
    resume = pr.Checkpoint.load(cp_path)

    disc = _FakeDiscovery(live=["should-not-run"])
    enum = _RecordingEnum()
    st = pr.SharedState("t", False, "socket-scan")
    orch = pr.Orchestrator(st, ["10.0.0.1", "10.0.0.2", "10.0.0.3"], disc, enum,
                           checkpoint=pr.Checkpoint(cp_path), resume=resume)
    orch.execute()

    assert disc.swept is False                       # Phase 1 skipped on resume
    # Only the two non-DONE hosts are re-enumerated (.3 was mid-scan, so redone).
    assert sorted(enum.ran_with) == ["10.0.0.2", "10.0.0.3"]
    assert st.snapshot().phase == "COMPLETE"


def test_resume_all_done_scans_nothing(tmp_path):
    st0 = _state_with("t", [pr.HostRecord(ip="10.0.0.1", state="DONE", status="up")])
    cp_path = str(tmp_path / "r.state")
    pr.Checkpoint(cp_path).save(st0, ["10.0.0.1"], swept=True)
    resume = pr.Checkpoint.load(cp_path)

    enum = _RecordingEnum()
    st = pr.SharedState("t", False, "socket-scan")
    orch = pr.Orchestrator(st, ["10.0.0.1"], _FakeDiscovery(), enum, resume=resume)
    orch.execute()
    assert enum.ran_with is None  # run() never called: nothing pending
    assert any("already enumerated" in ln for ln in st.snapshot().log)
    assert st.snapshot().phase == "COMPLETE"


def test_fresh_scan_writes_checkpoint_after_sweep(tmp_path):
    cp_path = str(tmp_path / "fresh.state")
    disc = _FakeDiscovery(live=["10.0.0.1", "10.0.0.2"])
    enum = _RecordingEnum()
    st = pr.SharedState("t", False, "socket-scan")
    orch = pr.Orchestrator(st, ["10.0.0.1", "10.0.0.2"], disc, enum,
                           checkpoint=pr.Checkpoint(cp_path))
    orch.execute()

    assert disc.swept is True
    # A checkpoint was journalled and progress fired once per host.
    assert enum.progress_calls == 2
    loaded = pr.Checkpoint.load(cp_path)
    assert set(loaded.enumerated) == {"10.0.0.1", "10.0.0.2"}


def test_no_checkpoint_means_no_file(tmp_path):
    # Without a checkpoint the on_progress callback is a harmless no-op.
    disc = _FakeDiscovery(live=["10.0.0.1"])
    enum = _RecordingEnum()
    st = pr.SharedState("t", False, "socket-scan")
    orch = pr.Orchestrator(st, ["10.0.0.1"], disc, enum)
    orch.execute()
    assert st.snapshot().phase == "COMPLETE"
    assert enum.ran_with == ["10.0.0.1"]
