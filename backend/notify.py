"""
notify.py — outbound alerting (webhook / Slack / syslog).

Monitoring is only useful if it can reach you. When a scan completes with
findings — or the network drifts — EnumGrid can push an alert to the channels you
already watch:

  * a generic JSON **webhook** (`ENUMGRID_WEBHOOK_URL`) for SIEM/automation;
  * a **Slack** incoming webhook (`ENUMGRID_SLACK_WEBHOOK`);
  * **syslog** over UDP (`ENUMGRID_SYSLOG=host:port`) for central logging.

All are opt-in via env and best-effort: a delivery failure is swallowed so it
never affects a scan. Nothing is sent unless at least one sink is configured.
"""

from __future__ import annotations

import json
import os
import socket
import urllib.error
import urllib.request

WEBHOOK_URL = os.environ.get("ENUMGRID_WEBHOOK_URL") or None
SLACK_WEBHOOK = os.environ.get("ENUMGRID_SLACK_WEBHOOK") or None
SYSLOG = os.environ.get("ENUMGRID_SYSLOG") or None  # "host:port"
_HTTP_TIMEOUT = 8


def configured() -> bool:
    """True if any outbound sink is set (so callers can skip building payloads)."""
    return bool(WEBHOOK_URL or SLACK_WEBHOOK or SYSLOG)


def _post_json(url: str, payload: dict) -> None:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json", "User-Agent": "EnumGrid/1.0"}
    )
    # URL is operator-configured (env); only http/https are accepted.
    if not url.lower().startswith(("http://", "https://")):
        return
    with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT):  # nosec B310 - scheme checked above
        pass


def _send_syslog(message: str) -> None:
    try:
        host, _, port = SYSLOG.partition(":")
        addr = (host or "127.0.0.1", int(port or "514"))
    except (ValueError, AttributeError):
        return
    # Severity 4 (warning), facility 1 (user) -> PRI 12.
    packet = f"<12>EnumGrid: {message}".encode("utf-8", "replace")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3)
            sock.sendto(packet, addr)
    except OSError:
        pass


def _slack_text(summary: dict) -> str:
    t = summary.get("target", "?")
    up = summary.get("hosts_up", summary.get("hosts", 0))
    findings = summary.get("findings", 0)
    kev = summary.get("kev", 0)
    bits = [f":satellite: *EnumGrid scan complete* — `{t}`", f"{up} hosts up"]
    if findings:
        bits.append(f"*{findings} vuln findings*")
    if kev:
        bits.append(f":rotating_light: *{kev} actively-exploited (KEV)*")
    return " · ".join(bits)


def scan_complete(summary: dict) -> None:
    """Fan a scan-completion summary out to every configured sink (best-effort)."""
    if not configured():
        return
    if WEBHOOK_URL:
        try:
            _post_json(WEBHOOK_URL, {"type": "scan_complete", **summary})
        except (urllib.error.URLError, OSError, ValueError):
            pass
    if SLACK_WEBHOOK:
        try:
            _post_json(SLACK_WEBHOOK, {"text": _slack_text(summary)})
        except (urllib.error.URLError, OSError, ValueError):
            pass
    if SYSLOG:
        _send_syslog(
            f"scan_complete target={summary.get('target')} "
            f"hosts_up={summary.get('hosts_up')} findings={summary.get('findings')} "
            f"kev={summary.get('kev')}"
        )


def summarize(snapshot: dict) -> dict:
    """Build a compact alert summary from a finished ScanState dict."""
    hosts = snapshot.get("hosts") or []
    up = sum(1 for h in hosts if h.get("status") == "up")
    findings = 0
    kev = 0
    for h in hosts:
        all_v = list(h.get("vulns") or [])
        for p in h.get("ports") or []:
            all_v += p.get("vulns") or []
        findings += len(all_v)
        kev += sum(1 for v in all_v if v.get("kev"))
    return {
        "target": snapshot.get("target", ""),
        "hosts": len(hosts),
        "hosts_up": up,
        "findings": findings,
        "kev": kev,
    }
