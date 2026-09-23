"""conftest.py: shared test-session setup for the backend suite.

Keeps the tests from writing into the *operator's* real state. The audit trail
is the one piece of backend state an endpoint touches as a side effect (every
scan/refusal/credscan/schedule call appends a line), so without this the suite
would interleave synthetic fixture events (`192.168.50.0/24`, `corp.local`)
into `backend/enumgrid_audit.log`, the file `/api/audit` serves and an operator
reads to reconstruct what was actually scanned. For a tool whose contract is
"every recorded result is real", a test-polluted audit log is a correctness bug,
not just untidiness.
"""

from __future__ import annotations

import audit
import pytest


@pytest.fixture(autouse=True, scope="session")
def _isolate_audit_log(tmp_path_factory):
    """Point the audit trail at a throwaway file for the whole session.

    Session-scoped so it costs one temp file rather than one per test; tests that
    need their own log (``test_audit.py``) still monkeypatch ``audit.AUDIT_LOG``
    per-test and pytest restores it to this value afterwards.
    """
    original = audit.AUDIT_LOG
    audit.AUDIT_LOG = str(tmp_path_factory.mktemp("audit") / "enumgrid_audit.log")
    yield
    audit.AUDIT_LOG = original
