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

import history
from discovery import run_discovery
from fastapi import Body, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response, StreamingResponse
from models import ScanPhase, ScanState
from report import build_pdf
from scanner import (
    PROFILE_META,
    is_privileged,
    nmap_available,
    run_pipeline,
    scan_single_host,
)
from security import (
    ALLOW_PUBLIC,
    MAX_CONCURRENT_SCANS,
    ScopeRejected,
    scan_slot,
    token_ok,
    vet_target,
)

app = FastAPI(title="Enumeration Platform API", version="0.1.0")

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


@app.get("/api/health")
def health() -> dict:
    return {
        "status": "ok",
        "nmap": nmap_available(),
        "privileged": is_privileged(),
        "max_concurrent_scans": MAX_CONCURRENT_SCANS,
        "allow_public": ALLOW_PUBLIC,
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
    if not token_ok(token, authorization):
        raise HTTPException(status_code=401, detail="unauthorized")

    try:
        vet_target(target)
    except ScopeRejected as exc:
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
                yield f"data: {json.dumps(data)}\n\n"

    return StreamingResponse(
        event_source(), media_type="text/event-stream", headers=_SSE_HEADERS
    )


@app.get("/api/profiles")
def profiles() -> dict:
    """The available nmap scan profiles (Zenmap-style) + whether we have root."""
    return {"profiles": PROFILE_META, "privileged": is_privileged()}


@app.get("/api/host/scan")
async def host_scan(
    ip: str = Query(..., description="IP of an already-discovered host"),
    deep: bool = Query(True, description="Force the NSE vuln/vulners pass"),
    profile: str | None = Query(None, description="scan profile (quick/intense/aggressive/vuln/...)"),
    scripts: str | None = Query(None, description="extra NSE scripts/categories (comma list)"),
    ports: str | None = Query(None, description="explicit port spec, e.g. 1-1024,3389"),
    token: str | None = Query(None, description="API token (only if one is configured)"),
    authorization: str | None = Header(None),
):
    """Scan a single host with the chosen nmap profile and return its Host record.

    Powers the per-row "Nmap Scan" button + "Scan All" — the client merges the
    result back into the grid without disturbing the other hosts. `profile`,
    `scripts` and `ports` are validated server-side (no nmap-arg injection).
    Subject to the same auth, scope and concurrency policy as the stream.
    """
    if not token_ok(token, authorization):
        raise HTTPException(status_code=401, detail="unauthorized")
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
            host = await scan_single_host(ip, deep, profile, scripts, ports)
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
) -> dict:
    """Recent scan summaries — powers the dashboard's history timeline."""
    return {"scans": history.list_scans(target, limit)}


@app.get("/api/history/diff")
def history_diff(
    target: str = Query(..., description="target to compute drift for"),
) -> dict:
    """'What changed since last time?' for `target`.

    Compares the two most recent stored scans and returns new/gone devices and
    per-host opened/closed ports. `available` is False until there are two scans
    of the same target to compare.
    """
    return history.drift_for_target(target)


@app.get("/")
def root() -> JSONResponse:
    return JSONResponse(
        {
            "service": "Enumeration Platform API",
            "stream": "/api/scan/stream?target=127.0.0.1",
            "health": "/api/health",
        }
    )
