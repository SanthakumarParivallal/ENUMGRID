"""
test_provenance.py — the reproducibility manifest is honest and deterministic.

Verifies injected values pass through unchanged (deterministic under test), that
unknown probes are labelled rather than fabricated, and that build_info carries
no timestamp while manifest does.
"""

from __future__ import annotations

import provenance


def test_build_info_injected_values_are_deterministic():
    info = provenance.build_info(commit="cafe123", nmap="7.95")
    assert info["tool"] == "ENUMGRID"
    assert info["tool_version"] == provenance.VERSION
    assert info["git_commit"] == "cafe123"      # injected, not probed
    assert info["nmap_version"] == "7.95"
    assert info["python_version"]               # real runtime, always present
    assert info["platform"]
    assert "generated_at" not in info           # static build info carries no clock


def test_manifest_adds_generation_timestamp():
    m = provenance.manifest(commit="c", nmap="n")
    assert m["git_commit"] == "c" and m["nmap_version"] == "n"
    assert m["generated_at"].endswith("+00:00")  # UTC ISO-8601


def test_git_commit_returns_none_when_git_missing(monkeypatch):
    def boom(*_a, **_k):
        raise FileNotFoundError("git not installed")

    monkeypatch.setattr(provenance.subprocess, "run", boom)
    assert provenance.git_commit() is None


def test_nmap_version_parses_version_string(monkeypatch):
    class _Proc:
        stdout = "Nmap version 7.95 ( https://nmap.org )\nPlatform: ...\n"

    monkeypatch.setattr(provenance.subprocess, "run", lambda *_a, **_k: _Proc())
    assert provenance.nmap_version() == "7.95"


def test_nmap_version_none_when_absent(monkeypatch):
    def boom(*_a, **_k):
        raise FileNotFoundError("nmap not installed")

    monkeypatch.setattr(provenance.subprocess, "run", boom)
    assert provenance.nmap_version() is None
