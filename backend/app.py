"""
app.py — FastAPI service for the Industrial Network Enumeration Platform.

Endpoints
---------
GET /api/health         -> { status, nmap, privileged }
GET /api/scan/stream    -> Server-Sent Events stream of ScanState snapshots

Run (from the backend/ directory, using the project's venv):

    ../.venv/bin/python -m uvicorn app:app --host 127.0.0.1 --port 8011 --reload

⚠️  Authorization: only scan IP ranges you own or are explicitly permitted to
    test. Network scanning without consent may be illegal in your jurisdiction.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime

import adscan
import audit
import campaign
import cloudscan
import copilot
import credscan
import cve
import history
import jobs
import notify
import osv
import passive
import provenance
import schedule
import security
import threatintel
import webscan
from discovery import run_discovery
from fastapi import Body, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response, StreamingResponse
from models import ScanPhase, ScanState
from report import build_pdf
from scanner import (
    PROFILE_META,
    SCAN_PROFILES,
    can_raw_scan,
    drop_privileges,
    elevate_sudo,
    is_privileged,
    nmap_available,
    privilege_status,
    run_pipeline,
    scan_capability,
    scan_single_host,
)
from security import (
    ALLOW_PUBLIC,
    MAX_CONCURRENT_SCANS,
    ScopeRejected,
    admin_ok,
    scan_slot,
    token_ok,
    vet_target,
)

app = FastAPI(title="Enumeration Platform API", version="1.0.0")

# The Vite proxy makes calls same-origin in dev, but allow direct localhost
# access too (e.g. hitting :8000 from a browser or curl).
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Headers that keep SSE flowing through dev proxies (no buffering/caching).
_SSE_HEADERS = {
    "Cache-Control": "no-cache, no-transform",
    "Connection": "keep-alive",
    "X-Accel-Buffering": "no",
}


@app.middleware("http")
async def _local_only_in_open_mode(request, call_next):
    """Fail-closed guard for the zero-config (no-token) deployment.

    When no auth token is configured the API grants admin to every caller, which
    is only acceptable for a *local* operator. This guard therefore restricts open
    mode to loopback peers whose `Host` header is also local — so binding to
    `0.0.0.0` (e.g. Docker `--network host`), a LAN client, or a DNS-rebinding /
    drive-by request from a browser on another origin cannot drive the scanner
    without an explicit `ENUMGRID_ADMIN_TOKEN`. When a token *is* configured the
    per-endpoint RBAC checks govern access and this guard steps aside.
    """
    path = request.url.path
    if path.startswith("/api/") and security.open_mode():
        client_host = request.client.host if request.client else None
        if not (
            security.client_is_local(client_host)
            and security.host_header_local(request.headers.get("host"))
        ):
            return JSONResponse(
                {
                    "error": (
                        "API is in open (no-token) mode and serves local clients only. "
                        "Set ENUMGRID_ADMIN_TOKEN to enable authenticated remote access."
                    )
                },
                status_code=401,
            )
    return await call_next(request)


# Baseline security response headers (defence-in-depth). Cheap and standard:
# stop MIME sniffing of the JSON/PDF responses, forbid framing (clickjacking) and
# referrer leakage, and scope resources to same-origin. Applied to every response.
_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "frame-ancestors 'none'",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Resource-Policy": "same-origin",
}


@app.middleware("http")
async def _security_headers(request, call_next):
    response = await call_next(request)
    for name, value in _SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    return response


@app.get("/api/health")
def health() -> dict:
    return {
        "status": "ok",
        "nmap": nmap_available(),
        "privileged": is_privileged(),
        # How scans get their privilege: "root" (running as root), "sudo"
        # (passwordless sudo, elevated per scan), or "unprivileged" (root-only
        # flags auto-rewritten so scans still run). `can_raw` is true for the
        # first two — i.e. real -sS/-sU/-O are available.
        "capability": scan_capability(),
        "can_raw": can_raw_scan(),
        "can_elevate": privilege_status()["can_elevate"],
        "max_concurrent_scans": MAX_CONCURRENT_SCANS,
        "allow_public": ALLOW_PUBLIC,
        # Live CVE intelligence status (NVD feed + growing local cache).
        "cve": {
            "nvd_live": not cve.DISABLED,
            "nvd_api_key": bool(cve.API_KEY),
            "cached_services": cve.cache_count(),
        },
        # Reproducibility: tool/git/nmap/runtime build info (cached — no per-call
        # subprocess). Same manifest is embedded in exported PDF reports.
        "provenance": provenance.build_info(),
    }


def _sse_error(scan_id: str | None, target: str, reason: str) -> StreamingResponse:
    """Return a one-frame SSE stream carrying a single ERROR + reason.

    Used for refusals (bad scope, auth, capacity) so the dashboard surfaces the
    problem inline on its existing stream channel instead of a hard HTTP error.
    """

    async def one_frame():
        err = ScanState(
            scan_id=scan_id, target=target, phase=ScanPhase.ERROR,
            progress=0, message=reason,
        )
        yield f"data: {err.model_dump_json()}\n\n"

    return StreamingResponse(
        one_frame(), media_type="text/event-stream", headers=_SSE_HEADERS
    )


@app.get("/api/network")
def network() -> dict:
    """Best-effort detection of the host's primary IP + a suggested /24 target,
    so the dashboard pre-fills the network you're actually on."""
    import socket

    ip = None
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(("8.8.8.8", 80))  # no packets sent; just picks the route
        ip = probe.getsockname()[0]
        probe.close()
    except OSError:
        pass

    suggested = "192.168.1.0/24"
    if ip:
        octets = ip.split(".")
        suggested = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
    return {"primary_ip": ip, "suggested_target": suggested}


@app.get("/api/scan/stream")
async def scan_stream(
    target: str = Query(..., description="IP, CIDR, range or hostname"),
    id: str | None = Query(None, description="Client-supplied scan id"),
    deep: bool = Query(False, description="Run NSE vuln scripts (full mode only)"),
    mode: str = Query("discover", description="'discover' (fast device list) or 'full' (nmap)"),
    token: str | None = Query(None, description="API token (only if one is configured)"),
    authorization: str | None = Header(None),
):
    """Stream a scan as Server-Sent Events.

    * mode=discover (default): fast device discovery — live hosts with MAC +
      vendor + hostname, no nmap. The deep service/vuln scan is on-demand per
      device via /api/host/scan.
    * mode=full: the original two-tiered nmap pipeline (sweep -> -sV).

    Every request is authorized (optional token) and its target is vetted
    through the *same* `ScopeValidator` the CLI uses — loopback, multicast,
    broadcast, reserved space, oversized scopes and (by default) public targets
    are refused. Each `data:` frame is a JSON-serialized `ScanState`.
    """
    if not admin_ok(token, authorization):
        raise HTTPException(status_code=401, detail="admin token required")

    try:
        vet_target(target)
    except ScopeRejected as exc:
        audit.record("scan_refused", mode=mode, target=target, reason=exc.reason)
        return _sse_error(id, target, exc.reason)

    async def event_source():
        # Hold one concurrency slot for the whole stream; refuse fast if the
        # host is already at capacity (prevents an nmap fork-bomb).
        async with scan_slot() as ok:
            if not ok:
                err = ScanState(
                    scan_id=id, target=target, phase=ScanPhase.ERROR, progress=0,
                    message="server busy — too many concurrent scans, retry shortly",
                )
                yield f"data: {err.model_dump_json()}\n\n"
                return
            stream = (
                run_pipeline(target, id, deep)
                if mode == "full"
                else run_discovery(target, id)
            )
            async for snapshot in stream:
                data = snapshot.model_dump(mode="json")
                # Persist the final snapshot *before* the client sees COMPLETE,
                # so a follow-up drift query is guaranteed to find it.
                if data.get("phase") == ScanPhase.COMPLETE.value:
                    try:
                        history.save_scan(data, mode=mode)
                    except Exception:  # noqa: BLE001 - history is best-effort
                        pass
                    # Audit + outbound alerting (both best-effort, never block).
                    summary = notify.summarize(data)
                    audit.record("scan_complete", mode=mode, **summary)
                    try:
                        notify.scan_complete(summary)
                    except Exception:  # noqa: BLE001 - alerting is best-effort
                        pass
                yield f"data: {json.dumps(data)}\n\n"

    return StreamingResponse(
        event_source(), media_type="text/event-stream", headers=_SSE_HEADERS
    )


@app.get("/api/profiles")
def profiles() -> dict:
    """The available nmap scan profiles (Zenmap-style) + whether we have root.

    Each profile includes the *real* nmap arguments it runs, so the UI can show
    the exact command — proof the scan genuinely differs per profile (not faked).
    """
    merged = {}
    for key, meta in PROFILE_META.items():
        spec = SCAN_PROFILES.get(key, {})
        scripts = spec.get("scripts", "")
        args = spec.get("args", "")
        if scripts:
            args = f"{args} --script {scripts}"
        merged[key] = {**meta, "args": args.strip()}
    # `capability`/`can_raw` let the UI explain that root-only profiles still run
    # (auto-adapted) rather than blocking them.
    return {
        "profiles": merged,
        "privileged": is_privileged(),
        "capability": scan_capability(),
        "can_raw": can_raw_scan(),
        # Lets the dashboard offer one-click elevation (enter sudo password) when
        # we're unprivileged but could raise to real -sS/-sU/-O.
        **privilege_status(),
    }


@app.get("/api/privilege")
def privilege() -> dict:
    """Current scan-privilege state for the dashboard's elevation control.

    Lets the UI show whether real raw-socket scans (-sS/-sU/-O) are available and
    whether the operator could elevate to them by entering a sudo password (see
    POST /api/privilege/elevate) — no restart required.
    """
    return privilege_status()


@app.post("/api/privilege/elevate")
def privilege_elevate(
    payload: dict = Body(...),
    token: str | None = Query(None),
    authorization: str | None = Header(None),
) -> dict:
    """Elevate this session to real raw-socket scans using a sudo password.

    The password is validated against `sudo` and then held only in memory for
    the process lifetime (never persisted, never logged, never returned). This
    endpoint is reachable only by a local operator (open-mode guard) or an admin
    token when RBAC is enabled. The password itself is deliberately kept out of
    the audit log.
    """
    if not admin_ok(token, authorization):
        raise HTTPException(status_code=401, detail="admin token required")
    password = payload.get("password") or ""
    if not isinstance(password, str):
        raise HTTPException(status_code=422, detail="password must be a string")
    ok, message = elevate_sudo(password)
    audit.record("privilege_elevate", ok=ok)  # note the attempt, never the secret
    status = privilege_status()
    status.update({"ok": ok, "message": message})
    return status


@app.post("/api/privilege/drop")
def privilege_drop(
    token: str | None = Query(None),
    authorization: str | None = Header(None),
) -> dict:
    """Drop any runtime-elevated privilege (forget the primed sudo credential)."""
    if not admin_ok(token, authorization):
        raise HTTPException(status_code=401, detail="admin token required")
    drop_privileges()
    audit.record("privilege_drop")
    status = privilege_status()
    status.update({"ok": True, "message": "dropped — scans run unprivileged again"})
    return status


@app.get("/api/settings/nvd")
def nvd_settings() -> dict:
    """Current NVD/CVE intelligence status, for the dashboard's settings panel."""
    return {
        "live": not cve.DISABLED,
        "key_active": cve.key_active(),
        "rate_limit": "50 req / 30s" if cve.key_active() else "5 req / 30s",
        "cached_services": cve.cache_count(),
        "get_key_url": "https://nvd.nist.gov/developers/request-an-api-key",
        # The exact line to make the key permanent across restarts.
        "env_hint": "ENUMGRID_NVD_API_KEY=<your-key>",
    }


@app.post("/api/settings/nvd-key")
def set_nvd_key(
    payload: dict = Body(...),
    token: str | None = Query(None),
    authorization: str | None = Header(None),
) -> JSONResponse:
    """Set (or clear) the NVD API key at runtime — in memory only, never logged.

    This is the user-friendly alternative to editing the environment: paste the
    free key from nvd.nist.gov in the dashboard and live CVE lookups immediately
    use the higher rate limit. For a permanent setup, also add
    ``ENUMGRID_NVD_API_KEY`` to your ``.env`` (so it survives a restart).
    Admin-gated; the key value is never echoed back.
    """
    if not admin_ok(token, authorization):
        raise HTTPException(status_code=401, detail="admin token required")
    key = str(payload.get("key") or "")
    active = cve.set_api_key(key)
    audit.record("nvd_key_set", active=active)  # records the action, never the key
    return JSONResponse({
        "ok": True,
        "key_active": active,
        "rate_limit": "50 req / 30s" if active else "5 req / 30s",
    })


# --- AI copilot: status, in-dashboard key upload, provider switch, chat ------- #
@app.get("/api/copilot")
def copilot_status(
    token: str | None = Query(None),
    authorization: str | None = Header(None),
) -> dict:
    """Copilot availability for the dashboard: which providers have an SDK + key,
    which is active, and whether it's ready. Never returns key values."""
    if not token_ok(token, authorization):
        raise HTTPException(status_code=401, detail="unauthorized")
    return copilot.status()


@app.post("/api/copilot/key")
def copilot_set_key(
    payload: dict = Body(...),
    token: str | None = Query(None),
    authorization: str | None = Header(None),
) -> JSONResponse:
    """Save (or clear) a provider API key from the dashboard — persisted 0600,
    gitignored, never logged. Admin-gated; the key value is never echoed back."""
    if not admin_ok(token, authorization):
        raise HTTPException(status_code=401, detail="admin token required")
    provider = str(payload.get("provider") or "").strip()
    if not copilot.valid_provider(provider):
        return JSONResponse({"error": "unknown provider"}, status_code=400)
    key_set = copilot.save_key(provider, str(payload.get("key") or ""))
    audit.record("copilot_key_set", provider=provider, active=key_set)  # never the key
    return JSONResponse({"ok": True, "provider": provider, "key_set": key_set,
                         "status": copilot.status()})


@app.post("/api/copilot/provider")
def copilot_set_provider(
    payload: dict = Body(...),
    token: str | None = Query(None),
    authorization: str | None = Header(None),
) -> JSONResponse:
    """Choose the active copilot provider (anthropic | openai). Admin-gated."""
    if not admin_ok(token, authorization):
        raise HTTPException(status_code=401, detail="admin token required")
    try:
        copilot.set_active_provider(str(payload.get("provider") or "").strip())
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    audit.record("copilot_provider_set", provider=payload.get("provider"))
    return JSONResponse({"ok": True, "status": copilot.status()})


@app.post("/api/copilot/chat")
def copilot_chat(
    payload: dict = Body(...),
    token: str | None = Query(None),
    authorization: str | None = Header(None),
):
    """Stream one copilot turn as Server-Sent Events. Grounded in the posted scan
    ``context``; may emit an ``action`` event proposing a scan the operator can
    confirm and run. Read-gated (it spends the operator's own key). Provider/SDK/
    key problems arrive as honest ``error`` events, never a fabricated answer."""
    if not token_ok(token, authorization):
        raise HTTPException(status_code=401, detail="unauthorized")
    messages = payload.get("messages")
    context = payload.get("context") if isinstance(payload.get("context"), dict) else None
    provider = payload.get("provider") if copilot.valid_provider(payload.get("provider")) else None

    def event_source():
        for event in copilot.stream_reply(messages, context, provider=provider):
            yield f"data: {json.dumps(event)}\n\n"

    return StreamingResponse(event_source(), media_type="text/event-stream", headers=_SSE_HEADERS)


@app.get("/api/host/scan")
async def host_scan(
    ip: str = Query(..., description="IP of an already-discovered host"),
    deep: bool = Query(True, description="Force the NSE vuln/vulners pass"),
    profile: str | None = Query(None, description="scan profile (quick/intense/aggressive/vuln/...)"),
    scripts: str | None = Query(None, description="extra NSE scripts/categories (comma list)"),
    ports: str | None = Query(None, description="explicit port spec, e.g. 1-1024,3389"),
    adaptive: bool = Query(False, description="default profile only: if the top-1000 scan finds an open port, sweep all 65535"),
    token: str | None = Query(None, description="API token (only if one is configured)"),
    authorization: str | None = Header(None),
):
    """Scan a single host with the chosen nmap profile and return its Host record.

    Powers the per-row "Nmap Scan" button + "Scan All" — the client merges the
    result back into the grid without disturbing the other hosts. `profile`,
    `scripts` and `ports` are validated server-side (no nmap-arg injection).
    Subject to the same auth, scope and concurrency policy as the stream.
    """
    if not admin_ok(token, authorization):
        raise HTTPException(status_code=401, detail="admin token required")
    try:
        vet_target(ip)
    except ScopeRejected as exc:
        return JSONResponse({"error": exc.reason}, status_code=400)

    async with scan_slot() as ok:
        if not ok:
            return JSONResponse(
                {"error": "server busy — too many concurrent scans, retry shortly"},
                status_code=429,
            )
        try:
            host = await scan_single_host(ip, deep, profile, scripts, ports, adaptive=adaptive)
        except (TimeoutError, asyncio.TimeoutError):
            return JSONResponse(
                {"error": "scan timed out — try a faster profile or a narrower port range"},
                status_code=504,
            )
        except Exception as exc:  # noqa: BLE001 - surface a clean error, never hang
            return JSONResponse(
                {"error": f"scan failed ({type(exc).__name__})"}, status_code=502
            )
    return JSONResponse(host.model_dump())


@app.post("/api/host/credscan")
def host_credscan(
    payload: dict = Body(...),
    token: str | None = Query(None),
    authorization: str | None = Header(None),
) -> JSONResponse:
    """Authenticated (SSH) host check → exact OS / kernel / package inventory.

    Credentialed scanning reads the *truth* from the host instead of inferring it
    from banners (kills version-match false positives). Credentials are used in
    memory only — never logged or stored. Authorized use only: scan hosts you
    administer. Body: ``{ip, username, password?, key_filename?, port?}``.
    """
    if not admin_ok(token, authorization):
        raise HTTPException(status_code=401, detail="admin token required")
    ip = str(payload.get("ip") or "").strip()
    username = str(payload.get("username") or "").strip()
    if not ip or not username:
        return JSONResponse({"ok": False, "error": "ip and username are required"}, status_code=400)
    try:
        vet_target(ip)
    except ScopeRejected as exc:
        return JSONResponse({"ok": False, "error": exc.reason}, status_code=400)

    facts = credscan.ssh_facts(
        ip,
        username,
        password=payload.get("password"),
        key_filename=payload.get("key_filename"),
        port=int(payload.get("port") or 22),
    )
    # Backport-aware CVEs from the *exact* installed packages (OSV.dev): this is
    # authoritative assessment — a fix backported by the distro is not flagged.
    if facts.get("ok") and facts.get("package_list"):
        ecosystem = osv.ecosystem_from_os(facts.get("os", ""))
        findings = osv.scan_packages(facts["package_list"], ecosystem) if ecosystem else []
        findings = threatintel.enrich(findings)  # add KEV/EPSS + risk-rank
        facts["ecosystem"] = ecosystem
        facts["vulns"] = [v.model_dump() for v in findings]
        facts.pop("package_list", None)  # don't ship the full inventory to the client
    # Audit the attempt WITHOUT the credentials.
    audit.record(
        "credscan", target=ip, user=username, ok=bool(facts.get("ok")),
        findings=len(facts.get("vulns", [])),
    )
    return JSONResponse(facts)


@app.get("/api/host/webscan")
def host_webscan(
    ip: str = Query(...),
    port: int = Query(80),
    https: bool | None = Query(None),
    token: str | None = Query(None),
    authorization: str | None = Header(None),
) -> JSONResponse:
    """Passive web-posture audit (security headers / cookies / TLS cert) of one
    HTTP(S) port. Safe: a single GET of '/', no crawling or payloads."""
    if not admin_ok(token, authorization):
        raise HTTPException(status_code=401, detail="admin token required")
    try:
        vet_target(ip)
    except ScopeRejected as exc:
        return JSONResponse({"ok": False, "error": exc.reason}, status_code=400)
    result = webscan.scan(ip, port, https)
    audit.record("webscan", target=ip, port=port, findings=len(result.get("vulns", [])))
    return JSONResponse(result)


@app.post("/api/report/pdf")
def report_pdf(payload: dict = Body(...)) -> Response:
    """Render the supplied ScanState snapshot into a downloadable PDF report.

    The dashboard POSTs exactly what it's showing, so the report can never drift
    from the screen. Stateless: the server holds no scan, it just formats.
    """
    pdf = build_pdf(payload)
    raw = str(payload.get("target") or "scan")
    safe = "".join(c if c.isalnum() else "-" for c in raw).strip("-")[:40] or "scan"
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = f"enumgrid_{safe}_{stamp}.pdf"
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/history")
def history_list(
    target: str | None = Query(None, description="filter to one target"),
    limit: int = Query(50, description="max rows (newest first)"),
    token: str | None = Query(None),
    authorization: str | None = Header(None),
) -> dict:
    """Recent scan summaries — powers the dashboard's history timeline.

    Read access (viewer or admin); open when no tokens are configured. The scan
    history is operator data (device inventory + open ports), so it is gated by
    the same RBAC as the audit log rather than served unauthenticated.
    """
    if not token_ok(token, authorization):
        raise HTTPException(status_code=401, detail="unauthorized")
    return {"scans": history.list_scans(target, limit)}


def _latest_snapshot(target: str) -> tuple[dict | None, str | None]:
    """The newest stored snapshot for ``target`` (and when it finished), or None."""
    scans = history.list_scans(target, limit=1)
    if not scans:
        return None, None
    row = history.get_scan(scans[0]["id"])
    if not row:
        return None, None
    return (row.get("snapshot") or {}), scans[0].get("finished_at")


@app.get("/api/campaign")
def campaign_view(
    targets: str = Query(..., description="comma-separated subnet targets to aggregate"),
    token: str | None = Query(None),
    authorization: str | None = Header(None),
) -> dict:
    """Roll up the latest stored scan of each subnet into one campaign view.

    Read-gated like history (it exposes inventory + open ports). Unscanned subnets
    are included and flagged ``scanned: false`` rather than dropped."""
    if not token_ok(token, authorization):
        raise HTTPException(status_code=401, detail="unauthorized")
    names = [t.strip() for t in targets.split(",") if t.strip()]
    subnets = []
    for name in names[:32]:  # bounded fan-out
        snapshot, finished_at = _latest_snapshot(name)
        subnets.append({"target": name, "scanned_at": finished_at, "snapshot": snapshot})
    return campaign.aggregate_campaign(subnets)


@app.get("/api/history/diff")
def history_diff(
    target: str = Query(..., description="target to compute drift for"),
    token: str | None = Query(None),
    authorization: str | None = Header(None),
) -> dict:
    """'What changed since last time?' for `target`.

    Compares the two most recent stored scans and returns new/gone devices and
    per-host opened/closed ports. `available` is False until there are two scans
    of the same target to compare. Read-gated (viewer or admin) like the history
    list, since it discloses the same operator inventory data.
    """
    if not token_ok(token, authorization):
        raise HTTPException(status_code=401, detail="unauthorized")
    return history.drift_for_target(target)


@app.get("/api/audit")
def audit_log(
    limit: int = Query(100, description="max entries (newest first)"),
    token: str | None = Query(None),
    authorization: str | None = Header(None),
) -> dict:
    """Recent audit entries — every scan, refusal and completion is recorded.

    Read access (viewer or admin); open when no tokens are configured.
    """
    if not token_ok(token, authorization):
        raise HTTPException(status_code=401, detail="unauthorized")
    return {"entries": audit.tail(limit)}


# --------------------------------------------------------------------------- #
# Cloud (AWS) + Active Directory (LDAP) discovery — credential-gated.
# --------------------------------------------------------------------------- #
@app.get("/api/cloud/aws")
def cloud_aws(
    region: str | None = Query(None),
    token: str | None = Query(None),
    authorization: str | None = Header(None),
) -> JSONResponse:
    """AWS inventory: EC2 + world-open security groups + public S3 (read-only).

    Uses your standard AWS credential chain (env / shared config / IAM role)."""
    if not admin_ok(token, authorization):
        raise HTTPException(status_code=401, detail="admin token required")
    result = cloudscan.aws_inventory(region)
    audit.record("cloud_aws", region=region or "default", ok=bool(result.get("ok")),
                 assets=len(result.get("assets", [])), findings=len(result.get("findings", [])))
    return JSONResponse(result)


@app.post("/api/ad/enum")
def ad_enum(
    payload: dict = Body(...),
    token: str | None = Query(None),
    authorization: str | None = Header(None),
) -> JSONResponse:
    """Active Directory enumeration over LDAP (computers + users), read-only.

    Body: ``{dc_host, domain, username, password, use_ssl?}``. Credentials are
    used in memory only — never logged. Authorized use only (your own domain)."""
    if not admin_ok(token, authorization):
        raise HTTPException(status_code=401, detail="admin token required")
    required = ("dc_host", "domain", "username", "password")
    if not all(str(payload.get(k) or "").strip() for k in required):
        return JSONResponse({"ok": False, "error": "dc_host, domain, username, password required"},
                            status_code=400)
    result = adscan.enumerate_domain(
        str(payload["dc_host"]).strip(), str(payload["domain"]).strip(),
        str(payload["username"]).strip(), str(payload["password"]),
        use_ssl=bool(payload.get("use_ssl", True)),
    )
    audit.record("ad_enum", domain=payload.get("domain"), user=payload.get("username"),
                 ok=bool(result.get("ok")), computers=len(result.get("computers", [])))
    return JSONResponse(result)


@app.post("/api/passive")
def passive_discover(
    seconds: int = Query(15, ge=1, le=300, description="listen window in seconds"),
    iface: str | None = Query(None, description="capture interface (default: auto)"),
    token: str | None = Query(None),
    authorization: str | None = Header(None),
) -> dict:
    """Passive, zero-packet host discovery — listens for ARP / DHCP / mDNS / LLMNR
    / NBNS chatter and reports who announced themselves. Sends **nothing** on the
    wire (stealth). Needs scapy + raw-socket privilege; returns ``available:false``
    with a reason when either is missing (never fabricates hosts)."""
    if not admin_ok(token, authorization):
        raise HTTPException(status_code=401, detail="admin token required")
    result = passive.discover_passive(seconds, iface)
    audit.record("passive", seconds=result.get("seconds"),
                 available=result.get("available"), hosts=result.get("count", 0))
    return result


# --------------------------------------------------------------------------- #
# Job queue — submit scans as background jobs, poll for results (scale).
# --------------------------------------------------------------------------- #
def _job_host_scan(params: dict) -> dict:
    """Worker handler: run one nmap host scan and return the Host record."""
    ip = str(params.get("ip") or "")
    vet_target(ip)  # scope guard inside the worker too
    host = asyncio.run(scan_single_host(
        ip, deep=bool(params.get("deep", False)),
        profile=params.get("profile"), scripts=params.get("scripts"), ports=params.get("ports"),
        adaptive=bool(params.get("adaptive", False)),
    ))
    return host.model_dump()


def _job_network_scan(params: dict) -> dict:
    """Worker handler: run a full headless network scan and save it to history.

    Drives the *same* pipeline the SSE stream uses (discover / full), consumes it
    to completion, then persists the final snapshot so scheduled scans populate
    history + drift with no browser attached."""
    target = str(params.get("target") or "")
    vet_target(target)  # scope guard inside the worker too
    mode = "full" if params.get("mode") == "full" else "discover"
    deep = bool(params.get("deep", False))

    async def _run() -> dict | None:
        final: dict | None = None
        stream = run_pipeline(target, None, deep) if mode == "full" else run_discovery(target, None)
        async for snapshot in stream:
            final = snapshot.model_dump(mode="json")
        if final is not None and final.get("phase") == ScanPhase.COMPLETE.value:
            try:
                history.save_scan(final, mode=mode)
            except Exception:  # noqa: BLE001 - history is best-effort
                pass
        return final

    final = asyncio.run(_run())
    if not final:
        return {"ok": False, "target": target, "error": "no result"}
    return {"ok": True, "target": target, "mode": mode,
            "hosts": len(final.get("hosts", [])), "phase": final.get("phase")}


_JOB_HANDLERS = {"host_scan": _job_host_scan, "network_scan": _job_network_scan}
_job_stop = asyncio.Event()

# Cron-style scheduled scans: a persisted rule store + a background ticker that
# enqueues a `network_scan` job whenever a rule is due (see schedule.py).
_schedules = schedule.ScheduleStore(schedule.default_path())
_sched_stop = asyncio.Event()


async def _scheduler_loop() -> None:
    """Every ~30s, enqueue a job for each schedule rule that is due right now."""
    while not _sched_stop.is_set():
        try:
            for rule in _schedules.due_now(datetime.now()):
                jobs.enqueue("network_scan", {"target": rule.target, "mode": rule.mode, "deep": rule.deep})
                audit.record("schedule_fire", schedule_id=rule.id, target=rule.target, mode=rule.mode)
        except Exception:  # noqa: BLE001 - a bad rule must never kill the ticker
            pass
        try:
            await asyncio.wait_for(_sched_stop.wait(), timeout=30)
        except asyncio.TimeoutError:
            pass


@app.on_event("startup")
async def _start_workers() -> None:
    asyncio.create_task(jobs.run_workers(_JOB_HANDLERS, _job_stop))
    asyncio.create_task(_scheduler_loop())


@app.on_event("shutdown")
async def _stop_workers() -> None:
    _job_stop.set()
    _sched_stop.set()


@app.post("/api/jobs/submit")
def jobs_submit(
    payload: dict = Body(...),
    token: str | None = Query(None),
    authorization: str | None = Header(None),
) -> JSONResponse:
    """Queue a scan as a background job → returns a job id to poll.

    Body: ``{kind: "host_scan", ip, profile?, deep?, scripts?, ports?}``."""
    if not admin_ok(token, authorization):
        raise HTTPException(status_code=401, detail="admin token required")
    kind = str(payload.get("kind") or "host_scan")
    if kind not in _JOB_HANDLERS:
        return JSONResponse({"error": f"unknown job kind '{kind}'"}, status_code=400)
    params = {k: v for k, v in payload.items() if k != "kind"}
    if params.get("ip"):
        try:
            vet_target(str(params["ip"]))
        except ScopeRejected as exc:
            return JSONResponse({"error": exc.reason}, status_code=400)
    job_id = jobs.enqueue(kind, params)
    audit.record("job_submit", kind=kind, job_id=job_id, target=params.get("ip"))
    return JSONResponse({"job_id": job_id, "status": "queued"})


@app.get("/api/jobs")
def jobs_list(
    limit: int = Query(50),
    token: str | None = Query(None),
    authorization: str | None = Header(None),
) -> dict:
    """Recent jobs (newest first)."""
    if not token_ok(token, authorization):
        raise HTTPException(status_code=401, detail="unauthorized")
    return {"jobs": jobs.list_jobs(limit)}


@app.get("/api/jobs/{job_id}")
def jobs_get(
    job_id: int,
    token: str | None = Query(None),
    authorization: str | None = Header(None),
) -> JSONResponse:
    """One job's status + result."""
    if not token_ok(token, authorization):
        raise HTTPException(status_code=401, detail="unauthorized")
    job = jobs.get(job_id)
    if not job:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse(job)


# --------------------------------------------------------------------------- #
# Scheduled scans — cron-style recurring rules (fire even with no browser open).
# --------------------------------------------------------------------------- #
@app.get("/api/schedules")
def schedules_list(
    token: str | None = Query(None),
    authorization: str | None = Header(None),
) -> dict:
    """All schedule rules (read-gated like history — it exposes target scopes)."""
    if not token_ok(token, authorization):
        raise HTTPException(status_code=401, detail="unauthorized")
    return {"schedules": [s.to_dict() for s in _schedules.list()]}


@app.post("/api/schedules")
def schedules_create(
    payload: dict = Body(...),
    token: str | None = Query(None),
    authorization: str | None = Header(None),
) -> JSONResponse:
    """Create a recurring scan. Body: ``{target, at:"HH:MM", days?, mode?, deep?}``.

    The target is vetted through the same `ScopeValidator` as a live scan, so a
    rule can never be scheduled against an out-of-scope range."""
    if not admin_ok(token, authorization):
        raise HTTPException(status_code=401, detail="admin token required")
    target = str(payload.get("target") or "").strip()
    if not target:
        return JSONResponse({"error": "target required"}, status_code=400)
    try:
        vet_target(target)
    except ScopeRejected as exc:
        return JSONResponse({"error": exc.reason}, status_code=400)
    try:
        rule = _schedules.add(
            target=target, at=str(payload.get("at", "")), days=payload.get("days"),
            mode=str(payload.get("mode", "discover")), deep=bool(payload.get("deep", False)),
            enabled=bool(payload.get("enabled", True)),
        )
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    audit.record("schedule_create", schedule_id=rule.id, target=target, mode=rule.mode)
    return JSONResponse(rule.to_dict(), status_code=201)


@app.delete("/api/schedules/{sched_id}")
def schedules_delete(
    sched_id: str,
    token: str | None = Query(None),
    authorization: str | None = Header(None),
) -> JSONResponse:
    """Remove a schedule rule."""
    if not admin_ok(token, authorization):
        raise HTTPException(status_code=401, detail="admin token required")
    if not _schedules.remove(sched_id):
        return JSONResponse({"error": "not found"}, status_code=404)
    audit.record("schedule_delete", schedule_id=sched_id)
    return JSONResponse({"ok": True})


@app.post("/api/schedules/{sched_id}/toggle")
def schedules_toggle(
    sched_id: str,
    enabled: bool = Query(True),
    token: str | None = Query(None),
    authorization: str | None = Header(None),
) -> JSONResponse:
    """Enable/disable a rule without deleting it."""
    if not admin_ok(token, authorization):
        raise HTTPException(status_code=401, detail="admin token required")
    rule = _schedules.toggle(sched_id, enabled)
    if rule is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    audit.record("schedule_toggle", schedule_id=sched_id, enabled=enabled)
    return JSONResponse(rule.to_dict())


@app.get("/")
def root() -> JSONResponse:
    return JSONResponse(
        {
            "service": "Enumeration Platform API",
            "stream": "/api/scan/stream?target=127.0.0.1",
            "health": "/api/health",
        }
    )
