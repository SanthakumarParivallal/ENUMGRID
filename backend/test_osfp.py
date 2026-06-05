"""
test_osfp.py — TTL → OS-family mapping (the unprivileged OS signal).

The live ping is not unit-tested (needs a host); this pins the bucketing and the
"ambiguous/none -> empty" contract so the UI never shows a fabricated OS.
"""

from __future__ import annotations

import pytest
from osfp import os_from_ttl


@pytest.mark.parametrize(
    "ttl,expected",
    [
        (64, "Linux / macOS / Unix"),
        (60, "Linux / macOS / Unix"),   # a few hops below 64
        (128, "Windows"),
        (120, "Windows"),
        (255, "Network device / IoT"),
        (250, "Network device / IoT"),
        (None, ""),
        (0, ""),
        (-1, ""),
    ],
)
def test_os_from_ttl(ttl, expected):
    assert os_from_ttl(ttl) == expected
