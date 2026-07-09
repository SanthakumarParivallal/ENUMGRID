"""
report.py — one-click PDF report generation (reportlab, pure-Python).

Turns a `ScanState` snapshot (the exact data the dashboard is showing) into a
self-contained, professional PDF: an executive summary, the full device
inventory, and per-host open-port / service / vulnerability detail. Nothing is
invented — every value comes straight from the live snapshot, so the report and
the screen always agree.

`build_pdf(payload)` returns the PDF as bytes; it is defensive about missing
fields so a partial snapshot still renders.
"""

from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO

import provenance
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# Palette echoing the cockpit (printable: ink on white, signal accents).
_INK = colors.HexColor("#0f172a")       # slate-900
_MUTED = colors.HexColor("#64748b")     # slate-500
_AMBER = colors.HexColor("#b45309")     # darker amber (legible on white)
_GREEN = colors.HexColor("#047857")     # darker matrix-green
_CRIMSON = colors.HexColor("#b91c1c")
_LINE = colors.HexColor("#cbd5e1")
_HEADER_BG = colors.HexColor("#1e293b")
_ZEBRA = colors.HexColor("#f1f5f9")

_SEV_COLOR = {
    "critical": _CRIMSON,
    "high": _CRIMSON,
    "medium": _AMBER,
    "low": _MUTED,
    "info": _MUTED,
}


def _esc(value) -> str:
    """Escape a value for safe inclusion in a reportlab Paragraph.

    Paragraphs parse a mini-XML markup, and scan results carry attacker- or
    device-controlled text (service/version banners, hostnames, vuln output, the
    target string). Without escaping, a single ``<``/``>``/``&`` would crash PDF
    generation — or let a banner inject markup. So every dynamic value is routed
    through here before it reaches a Paragraph. (Hand-rolled rather than
    ``xml.sax.saxutils`` — these are output encoders, not XML parsers; doing it
    inline keeps the blacklisted ``xml.sax`` import out of the tree entirely.)
    """
    s = "" if value is None else str(value)
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _attr(value) -> str:
    """Escaped, double-quoted attribute value for a reportlab tag (e.g. <a href=…>)."""
    return '"' + _esc(value).replace('"', "&quot;") + '"'


def _num(value) -> float | None:
    """Coerce a payload value to float for safe formatting, or None if not numeric.

    The report is rendered from a client-POSTed snapshot (``/api/report/pdf`` takes
    a raw dict, not a validated model), so a numeric field like ``cvss`` or ``port``
    can arrive as a string — or garbage. This keeps the renderer's "a partial
    snapshot still renders" promise instead of raising on a bad type."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("PRTitle", parent=ss["Title"], textColor=_INK, fontSize=20, spaceAfter=2))
    ss.add(ParagraphStyle("PRSub", parent=ss["Normal"], textColor=_MUTED, fontSize=9, spaceAfter=10))
    ss.add(ParagraphStyle("PRH2", parent=ss["Heading2"], textColor=_INK, fontSize=13, spaceBefore=12, spaceAfter=6))
    ss.add(ParagraphStyle("PRHost", parent=ss["Heading3"], textColor=_INK, fontSize=11, spaceBefore=10, spaceAfter=2))
    ss.add(ParagraphStyle("PRBody", parent=ss["Normal"], textColor=_INK, fontSize=9, leading=12))
    ss.add(ParagraphStyle("PRMutedBody", parent=ss["Normal"], textColor=_MUTED, fontSize=8.5, leading=11, alignment=TA_LEFT))
    ss.add(ParagraphStyle("PRMono", parent=ss["Normal"], fontName="Courier", textColor=_INK, fontSize=8.5, leading=11))
    return ss


def _all_vulns(host: dict) -> list[dict]:
    """Every vuln on a host (host-level + per-port), tagged with its port."""
    out = [{**v, "port": None} for v in (host.get("vulns") or [])]
    for p in host.get("ports") or []:
        for v in p.get("vulns") or []:
            out.append({**v, "port": p.get("port")})
    return out


def _summary(hosts: list[dict]) -> dict:
    from collections import Counter

    up = sum(1 for h in hosts if h.get("status") == "up")
    open_ports = 0
    services: Counter = Counter()
    devices: Counter = Counter()
    severities: Counter = Counter()
    vulns = 0
    critical = 0
    for h in hosts:
        if h.get("device_type"):
            devices[h["device_type"]] += 1
        for p in h.get("ports") or []:
            if p.get("state") in ("open", "open|filtered"):
                open_ports += 1
                svc = p.get("service")
                if svc and svc != "unknown":
                    services[svc] += 1
            if p.get("critical"):
                critical += 1
        for v in _all_vulns(h):
            vulns += 1
            severities[(v.get("severity") or "info").lower()] += 1
    return {
        "total": len(hosts),
        "up": up,
        "open_ports": open_ports,
        "services": len(services),
        "vulns": vulns,
        "critical": critical,
        "top_services": services.most_common(8),
        "device_mix": devices.most_common(),
        "severities": severities,
    }


def _ip_key(ip: str):
    try:
        return tuple(int(o) for o in str(ip).split("."))
    except ValueError:
        return (0,)


def _header_footer(canvas, doc):
    canvas.saveState()
    w, h = A4
    canvas.setFillColor(_MUTED)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(18 * mm, 10 * mm, "EnumGrid — Authorized use only. Scan assets you own or are permitted to test.")
    canvas.drawRightString(w - 18 * mm, 10 * mm, f"Page {doc.page}")
    canvas.setStrokeColor(_LINE)
    canvas.line(18 * mm, 12 * mm, w - 18 * mm, 12 * mm)
    canvas.restoreState()


def _kv_table(rows, styles):
    data = [[Paragraph(f"<b>{_esc(k)}</b>", styles["PRBody"]), Paragraph(_esc(v), styles["PRBody"])] for k, v in rows]
    t = Table(data, colWidths=[45 * mm, 120 * mm])
    t.setStyle(TableStyle([
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, _LINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def _inventory_table(hosts, styles):
    head = ["IP", "Hostname", "Vendor", "Type", "OS", "Open"]
    data = [[Paragraph(f"<b>{c}</b>", styles["PRMutedBody"]) for c in head]]
    for h in hosts:
        open_ct = sum(1 for p in (h.get("ports") or []) if p.get("state") in ("open", "open|filtered"))
        data.append([
            Paragraph(_esc(h.get("ip", "")), styles["PRMono"]),
            Paragraph(_esc(h.get("hostname") or "—"), styles["PRMutedBody"]),
            Paragraph(_esc(h.get("vendor") or "—"), styles["PRMutedBody"]),
            Paragraph(_esc(h.get("device_type") or "—"), styles["PRMutedBody"]),
            Paragraph(_esc(h.get("os") or "Unknown"), styles["PRMutedBody"]),
            Paragraph(str(open_ct), styles["PRMono"]),
        ])
    t = Table(data, colWidths=[26 * mm, 30 * mm, 34 * mm, 28 * mm, 34 * mm, 12 * mm], repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), _HEADER_BG),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.3, _LINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
    ]
    for i in range(1, len(data)):
        if i % 2 == 0:
            style.append(("BACKGROUND", (0, i), (-1, i), _ZEBRA))
    t.setStyle(TableStyle(style))
    return t


def _ports_table(ports, styles):
    head = ["Port", "Proto", "State", "Service", "Version"]
    data = [[Paragraph(f"<b>{c}</b>", styles["PRMutedBody"]) for c in head]]
    for p in sorted(ports, key=lambda x: _num(x.get("port")) if _num(x.get("port")) is not None else 0):
        data.append([
            Paragraph(_esc(p.get("port", "")), styles["PRMono"]),
            Paragraph(_esc(p.get("protocol", "tcp")), styles["PRMutedBody"]),
            Paragraph(_esc(p.get("state", "")), styles["PRMutedBody"]),
            Paragraph(_esc(p.get("service", "")), styles["PRMutedBody"]),
            Paragraph(_esc(p.get("version") or "—"), styles["PRMutedBody"]),
        ])
    t = Table(data, colWidths=[16 * mm, 14 * mm, 22 * mm, 34 * mm, 78 * mm], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _HEADER_BG),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.3, _LINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def _severity_table(severities, styles):
    """A coloured Critical→Info findings breakdown."""
    order = ["critical", "high", "medium", "low", "info"]
    rows = [[Paragraph(f"<b>{s.upper()}</b>", styles["PRMutedBody"]),
             Paragraph(str(severities.get(s, 0)), styles["PRMono"])]
            for s in order if severities.get(s)]
    if not rows:
        return None
    t = Table(rows, colWidths=[40 * mm, 18 * mm])
    style = [("GRID", (0, 0), (-1, -1), 0.3, _LINE),
             ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
             ("LEFTPADDING", (0, 0), (-1, -1), 5)]
    present = [s for s in order if severities.get(s)]
    for i, s in enumerate(present):
        style.append(("TEXTCOLOR", (0, i), (0, i), _SEV_COLOR.get(s, _MUTED)))
    t.setStyle(TableStyle(style))
    return t


def _chips(label, pairs, styles):
    """A 'label: a (n) · b (n)' one-liner for device-mix / top-services."""
    if not pairs:
        return None
    body = " · ".join(f"{_esc(name)} ({count})" for name, count in pairs)
    return Paragraph(f"<b>{_esc(label)}:</b> {body}", styles["PRMutedBody"])


# Defensive upper bound on how many hosts a single report renders. Legitimate
# scans are already bounded by the host cap (default 4096); this guards against a
# crafted/oversized POST body exhausting memory in reportlab.
MAX_REPORT_HOSTS = 10000


def build_pdf(payload: dict) -> bytes:
    """Render a ScanState-shaped dict into a PDF and return its bytes."""
    raw_hosts = payload.get("hosts")
    raw_hosts = raw_hosts if isinstance(raw_hosts, list) else []
    hosts = sorted(raw_hosts[:MAX_REPORT_HOSTS], key=lambda h: _ip_key(h.get("ip", "")))
    target = payload.get("target") or "—"
    summary = _summary(hosts)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    styles = _styles()
    story = []

    profile = payload.get("profile") or payload.get("scanProfile")
    prov = provenance.manifest()
    story.append(Paragraph("EnumGrid — Network Enumeration Report", styles["PRTitle"]))
    story.append(Paragraph(f"Generated {generated}", styles["PRSub"]))
    story.append(_kv_table(
        [
            ("Target scope", target),
            ("Live hosts", f"{summary['up']} up / {summary['total']} discovered"),
            ("Open ports", summary["open_ports"]),
            ("Distinct services", summary["services"]),
            ("Vulnerability findings", summary["vulns"]),
            ("Critical flags", summary["critical"]),
        ] + ([("Scan profile", profile)] if profile else []) + [
            # Reproducibility manifest — what produced this report.
            ("Build", f"EnumGrid v{prov['tool_version']} · commit {prov['git_commit']}"),
            ("Toolchain", f"nmap {prov['nmap_version']} · Python {prov['python_version']}"),
        ],
        styles,
    ))

    # Optional AI executive summary (generated by the copilot, grounded in this
    # scan). Rendered as escaped text — the model output never becomes markup.
    ai_summary = payload.get("ai_summary")
    if isinstance(ai_summary, str) and ai_summary.strip():
        story.append(Spacer(1, 8))
        story.append(Paragraph("Executive Summary", styles["PRH2"]))
        for para in (p.strip() for p in ai_summary.strip().split("\n") if p.strip()):
            story.append(Paragraph(_esc(para), styles["PRBody"]))
        story.append(Spacer(1, 2))
        story.append(Paragraph("AI-generated from this scan — verify before distribution.",
                               styles["PRMutedBody"]))

    # Risk + exposure breakdown (advanced summary).
    sev_table = _severity_table(summary["severities"], styles)
    if sev_table is not None:
        story.append(Spacer(1, 8))
        story.append(Paragraph("Findings by severity", styles["PRH2"]))
        story.append(sev_table)
    for line in (
        _chips("Device mix", summary["device_mix"], styles),
        _chips("Top services", summary["top_services"], styles),
    ):
        if line is not None:
            story.append(Spacer(1, 4))
            story.append(line)

    story.append(Spacer(1, 8))
    story.append(Paragraph("Device Inventory", styles["PRH2"]))
    if hosts:
        story.append(_inventory_table(hosts, styles))
    else:
        story.append(Paragraph("No live hosts discovered.", styles["PRMutedBody"]))

    # Per-host detail (only hosts that have been service-scanned).
    scanned = [h for h in hosts if (h.get("ports") or h.get("vulns"))]
    if scanned:
        story.append(PageBreak())
        story.append(Paragraph("Per-Host Detail", styles["PRH2"]))
        for h in scanned:
            label = _esc(h.get("ip", ""))
            extra = " · ".join(
                _esc(x) for x in (h.get("device_type"), h.get("vendor"), h.get("os") if h.get("os") != "Unknown" else None)
                if x
            )
            story.append(Paragraph(f"{label}{('  —  ' + extra) if extra else ''}", styles["PRHost"]))
            ports = [p for p in (h.get("ports") or []) if p.get("state") in ("open", "open|filtered")]
            if ports:
                story.append(Spacer(1, 2))
                story.append(_ports_table(ports, styles))
            else:
                story.append(Paragraph("No open ports found in scanned range.", styles["PRMutedBody"]))

            vulns = list(h.get("vulns") or [])
            for p in h.get("ports") or []:
                for v in p.get("vulns") or []:
                    vulns.append({**v, "port": p.get("port")})
            if vulns:
                story.append(Spacer(1, 3))
                for v in vulns:
                    sev = (v.get("severity") or "info").lower()
                    cv = _num(v.get("cvss"))
                    cvss = f" · CVSS {cv:.1f}" if cv is not None else ""
                    port = f" :{v['port']}" if v.get("port") else ""
                    sev_hex = _SEV_COLOR.get(sev, _MUTED).hexval()[2:]
                    # CVE id is a live link to NVD; confidence flags verify-needed.
                    # Every dynamic field is escaped — vuln output is device/banner
                    # text and the url/id come from the client payload, so an
                    # unescaped char here would crash the build or inject markup.
                    vid = _esc(v.get("id", ""))
                    url = v.get("url", "")
                    # Only emit a link for a safe http(s) URL; the attribute value
                    # is quoted/escaped so it can't break out of the <a> tag.
                    safe_link = isinstance(url, str) and url.lower().startswith(("http://", "https://"))
                    id_html = f"<a href={_attr(url)}><u>{vid}</u></a>" if safe_link else vid
                    conf = v.get("confidence")
                    conf_html = " <i>(confirmed)</i>" if conf == "confirmed" else (
                        " <i>(version — verify)</i>" if conf == "version" else "")
                    detail = _esc(v.get("title") or (v.get("output", "") or "")[:90])
                    line = (
                        f"<font color='#{sev_hex}'><b>[{_esc(sev.upper())}]</b></font> "
                        f"{id_html}{_esc(port)}{_esc(cvss)}{conf_html} — "
                        f"{detail}"
                    )
                    story.append(Paragraph(line, styles["PRMutedBody"]))
            story.append(Spacer(1, 4))

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=18 * mm,
        title="EnumGrid Report", author="EnumGrid",
    )
    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return buf.getvalue()
