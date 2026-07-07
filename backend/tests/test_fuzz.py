"""
test_fuzz.py — property-based fuzzing of the parsing / classification layer.

Every value these functions see can originate from a hostile network (banners,
ARP/NDP/mDNS replies, nmap script output) or an untrusted API request. The
property under test is simple but important for a security tool: **they must
never raise on arbitrary input** — only return a well-typed result (or, for the
scope validator, the one expected `ScopeRejected`).
"""

from __future__ import annotations

import string

import scanner
from fingerprint import guess_device_type
from hypothesis import given
from hypothesis import strategies as st
from mdns import device_type_from_mdns
from models import Severity
from osfp import os_from_ttl
from security import ScopeRejected, vet_target

# A character set that includes the metacharacters an attacker would try.
_HOSTILE = st.text(alphabet=string.printable, max_size=80)


@given(
    vendor=st.none() | _HOSTILE,
    hostname=st.none() | _HOSTILE,
    ports=st.lists(st.integers(min_value=-5, max_value=70000), max_size=12),
    services=st.lists(_HOSTILE, max_size=8),
)
def test_guess_device_type_never_crashes(vendor, hostname, ports, services):
    result = guess_device_type(vendor=vendor, hostname=hostname, ports=ports, services=services)
    assert isinstance(result, str)


@given(services=st.sets(_HOSTILE, max_size=10))
def test_device_type_from_mdns_never_crashes(services):
    assert isinstance(device_type_from_mdns(services), str)


@given(ttl=st.integers(min_value=-1000, max_value=100000))
def test_os_from_ttl_never_crashes(ttl):
    assert isinstance(os_from_ttl(ttl), str)


@given(ttl=st.none())
def test_os_from_ttl_handles_none(ttl):
    assert os_from_ttl(ttl) == ""


@given(output=_HOSTILE | st.text(max_size=400))
def test_parse_vulners_never_crashes(output):
    out = scanner._parse_vulners(output)
    assert isinstance(out, list)


@given(score=st.floats(allow_nan=True, allow_infinity=True, width=32))
def test_severity_from_cvss_never_crashes(score):
    assert scanner._severity_from_cvss(score) in set(Severity)


@given(name=_HOSTILE, output=_HOSTILE)
def test_script_to_vuln_never_crashes(name, output):
    v = scanner._script_to_vuln(name, output)
    assert v is None or v.id  # either no finding, or a well-formed Vuln


@given(target=_HOSTILE)
def test_vet_target_only_rejects_cleanly(target):
    # The contract: validate either returns None or raises *ScopeRejected* —
    # never any other exception, no matter how hostile the string.
    try:
        vet_target(target)
    except ScopeRejected:
        pass
