"""test_credscan.py — credentialed-scan parsers (no SSH/network)."""

from __future__ import annotations

import credscan


def test_parse_os_release_prefers_pretty_name():
    text = (
        'NAME="Ubuntu"\n'
        'VERSION="22.04.4 LTS (Jammy Jellyfish)"\n'
        'PRETTY_NAME="Ubuntu 22.04.4 LTS"\n'
        'VERSION_ID="22.04"\n'
    )
    assert credscan.parse_os_release(text) == "Ubuntu 22.04.4 LTS"


def test_parse_os_release_falls_back_to_name_version():
    text = 'NAME="Alpine Linux"\nVERSION_ID="3.19.1"\n'
    assert credscan.parse_os_release(text) == "Alpine Linux 3.19.1"


def test_parse_os_release_empty():
    assert credscan.parse_os_release("") == ""


def test_parse_uname():
    info = credscan.parse_uname("Linux 5.15.0-105-generic x86_64")
    assert info["kernel_name"] == "Linux"
    assert info["kernel_release"] == "5.15.0-105-generic"
    assert info["arch"] == "x86_64"


def test_count_packages_dpkg():
    text = (
        "Desired=Unknown/Install\n"
        "| Status=Not/Inst\n"
        "+++-====-====\n"
        "ii  bash  5.1\n"
        "ii  curl  7.81\n"
        "rc  oldpkg 1.0\n"  # removed-but-config — not counted
    )
    assert credscan.count_packages(text) == 2


def test_count_packages_rpm():
    text = "bash-5.1.8-6.el9.x86_64\ncurl-7.76.1-23.el9.x86_64\nopenssl-3.0.7-1.el9.x86_64\n"
    assert credscan.count_packages(text) == 3


def test_ssh_facts_without_paramiko_is_clean(monkeypatch):
    monkeypatch.setattr(credscan, "_HAVE_PARAMIKO", False)
    out = credscan.ssh_facts("10.0.0.1", "user", "pass")
    assert out["ok"] is False and "paramiko" in out["error"]
