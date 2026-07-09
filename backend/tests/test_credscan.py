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


def test_parse_packages_dpkg_query():
    text = "bash 5.1-6ubuntu1.1\nopenssl 3.0.2-0ubuntu1.15\ncurl 7.81.0-1ubuntu1.16\n"
    pkgs = credscan.parse_packages(text)
    assert ("openssl", "3.0.2-0ubuntu1.15") in pkgs
    assert len(pkgs) == 3


def test_parse_packages_ignores_headers():
    text = "Desired=Unknown\n|/ Err\n+++-===\nbash 5.1\n"
    assert credscan.parse_packages(text) == [("bash", "5.1")]


def test_ssh_facts_without_paramiko_is_clean(monkeypatch):
    monkeypatch.setattr(credscan, "_HAVE_PARAMIKO", False)
    out = credscan.ssh_facts("10.0.0.1", "user", "pass")
    assert out["ok"] is False and "paramiko" in out["error"]


def test_available_reports_paramiko(monkeypatch):
    monkeypatch.setattr(credscan, "_HAVE_PARAMIKO", True)
    assert credscan.available() is True
    monkeypatch.setattr(credscan, "_HAVE_PARAMIKO", False)
    assert credscan.available() is False


class _FakeStd:
    def __init__(self, data: bytes = b""):
        self._d = data

    def read(self):
        return self._d


class _FakeSSH:
    """A stand-in paramiko.SSHClient: no sockets, canned command output."""

    def load_system_host_keys(self): pass
    def set_missing_host_key_policy(self, policy): self.policy = policy
    def connect(self, *a, **k): self.connected = True
    def close(self): self.closed = True

    def exec_command(self, cmd, timeout=None):
        if "os-release" in cmd:
            out = b'PRETTY_NAME="Ubuntu 22.04.4 LTS"\n'
        elif "uname" in cmd:
            out = b"Linux 5.15.0-105-generic x86_64"
        else:  # the dpkg-query || rpm inventory
            out = b"bash 5.1-6ubuntu1\ncurl 7.81.0-1ubuntu1\n"
        return None, _FakeStd(out), _FakeStd()


def test_ssh_facts_reads_authoritative_host_facts(monkeypatch):
    monkeypatch.setattr(credscan, "_HAVE_PARAMIKO", True)
    monkeypatch.setattr(credscan.paramiko, "SSHClient", _FakeSSH)
    out = credscan.ssh_facts("10.0.0.1", "admin", password="pw")  # nosec B106 - test fixture, not a real secret
    assert out["ok"] is True
    assert out["os"] == "Ubuntu 22.04.4 LTS"
    assert out["kernel"] == "Linux 5.15.0-105-generic" and out["arch"] == "x86_64"
    assert out["packages"] == 2 and ("bash", "5.1-6ubuntu1") in out["package_list"]
    assert out["method"] == "ssh-credentialed"


def test_ssh_facts_connect_failure_is_clean(monkeypatch):
    monkeypatch.setattr(credscan, "_HAVE_PARAMIKO", True)

    class _NoKnownHostsThenRefused(_FakeSSH):
        def load_system_host_keys(self): raise OSError("no known_hosts")  # tolerated
        def connect(self, *a, **k): raise OSError("connection refused")

    monkeypatch.setattr(credscan.paramiko, "SSHClient", _NoKnownHostsThenRefused)
    out = credscan.ssh_facts("10.0.0.1", "admin", password="pw")  # nosec B106 - test fixture, not a real secret
    assert out["ok"] is False and "ssh connect failed" in out["error"]


def test_ssh_facts_autoadd_and_exec_errors_degrade(monkeypatch):
    monkeypatch.setattr(credscan, "_HAVE_PARAMIKO", True)
    monkeypatch.setattr(credscan, "_SSH_AUTOADD", True)          # exercise AutoAddPolicy branch

    class _ExecBoom(_FakeSSH):
        def exec_command(self, cmd, timeout=None): raise RuntimeError("channel failed")

    monkeypatch.setattr(credscan.paramiko, "SSHClient", _ExecBoom)
    out = credscan.ssh_facts("10.0.0.1", "admin", key_filename="/tmp/k")  # nosec B108 - test fixture path
    assert out["ok"] is True and out["os"] == "Unknown"         # commands failed → honest Unknown
