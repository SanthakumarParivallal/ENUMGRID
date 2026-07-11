#!/usr/bin/env python3
"""
cve_baselines.py — compare EnumGrid's CVE detection against real vulnerability
scanners on the SAME pinned testbed host.

Why this exists
---------------
`detection_benchmark.py` scores EnumGrid's planted-CVE recall against ground
truth. A reviewer's very next question is *"compared to what?"* — self-measured
recall is weak evidence on its own. This harness adds two independent,
widely-used baselines and reports, per host and pooled:

  * **planted-CVE recall** for each tool — EnumGrid vs **nmap `vulners`** vs
    **Nuclei** (ProjectDiscovery) — on the identical, pinned host;
  * each tool's **unexpected** CVEs, surfaced for review (never auto-scored as a
    false positive: a rolling image's full CVE set is not knowable a priori);
  * pairwise **agreement** (Jaccard) between the tools' CVE sets.

The two baselines embody the two schools of vulnerability detection, which is the
point of comparing them:

  * **version-match** (nmap `vulners`, and EnumGrid's CPE→NVD path) — maps a
    detected product/version to its known CVEs. High recall, but a back-ported
    fix can make it over-report (a candidate false positive);
  * **active-PoC** (Nuclei templates) — actually sends a probe that confirms the
    bug. High precision, but only covers vulns someone wrote a template for.

Reporting both alongside EnumGrid frames its accuracy honestly instead of in a
vacuum.

Two layers, like the rest of the eval harness:
  * the parsers + comparison are **pure and unit-tested** (no network, no Docker,
    no nmap/nuclei) so the published comparison is trustworthy and runs in CI —
    see `test_cve_baselines.py`;
  * the live runner shells out to nmap/nuclei and is **operator-run**. A baseline
    that is not installed is reported as ``unavailable`` — never silently treated
    as "found nothing".

Usage (with the testbed up — `docker compose -f evaluation/docker-compose.yml up -d`):
    python evaluation/cve_baselines.py                       # uses ground_truth.json
    python evaluation/cve_baselines.py --json out.json --md out.md
    python evaluation/cve_baselines.py --tools enumgrid,nmap-vulners
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess  # nosec B404 - baselines invoke nmap/nuclei with fixed list args
import sys
import time
from collections.abc import Iterable

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_GT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ground_truth.json")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_HTTP_SERVICES = {"http", "https", "www", "http-alt", "http-proxy"}
_HTTP_TIMEOUT = 300  # per-host nuclei/nmap wall-clock cap (seconds)


# --------------------------------------------------------------------------- #
# Parsers (pure — the trustworthy core, unit-tested with captured tool output)
# --------------------------------------------------------------------------- #
def parse_cve_ids(text: str) -> set[str]:
    """Every CVE id mentioned in a blob of text, upper-cased and de-duplicated.

    Used for nmap `vulners`/`vuln` NSE output, whose CVE ids appear inline in the
    script results table regardless of the exact NSE version's formatting."""
    return {m.group(0).upper() for m in _CVE_RE.finditer(text or "")}


# nmap-vulners output is plain text; parsing it is exactly parse_cve_ids.
parse_nmap_vulners = parse_cve_ids


def parse_nuclei_jsonl(lines: Iterable[str]) -> set[str]:
    """CVE ids from Nuclei JSON-lines output (`-jsonl`).

    Nuclei emits one JSON object per finding. A CVE id can live in
    ``info.classification.cve-id`` (str or list) or be the ``template-id`` itself
    (e.g. ``CVE-2021-41773``). We read those fields when the line is valid JSON,
    and fall back to a regex over the raw line so a schema change can't silently
    zero the baseline. Non-CVE findings (misconfigs, exposures) are ignored."""
    out: set[str] = set()
    for raw in lines:
        raw = (raw or "").strip()
        if not raw:
            continue
        try:
            obj = json.loads(raw)
        except (ValueError, TypeError):
            out |= parse_cve_ids(raw)          # not JSON → best-effort regex
            continue
        info = obj.get("info") or {}
        classification = info.get("classification") or {}
        cve = classification.get("cve-id")
        if isinstance(cve, str):
            out |= parse_cve_ids(cve)
        elif isinstance(cve, list):
            for c in cve:
                out |= parse_cve_ids(str(c))
        for key in ("template-id", "templateID", "template_id"):
            if isinstance(obj.get(key), str):
                out |= parse_cve_ids(obj[key])
    return out


# --------------------------------------------------------------------------- #
# Comparison (pure — the scoring reviewers read)
# --------------------------------------------------------------------------- #
def _jaccard(a: set, b: set) -> float:
    """Jaccard overlap of two sets; two empty sets are defined as identical (1.0)."""
    union = a | b
    return (len(a & b) / len(union)) if union else 1.0


def compare_host(planted: Iterable[str], tool_cves: dict[str, set[str]]) -> dict:
    """Per-tool planted-CVE recall + unexpected set, for one host.

    ``planted`` = the CVE ids a version-accurate scanner MUST recall on this host
    (from ground_truth.json). ``tool_cves`` maps tool name → the CVE-id set it
    reported (a tool that was unavailable is simply absent from the map, so it is
    not counted as a zero — honest by omission)."""
    planted_set = {str(c).upper() for c in planted}
    per_tool: dict[str, dict] = {}
    for tool, cves in tool_cves.items():
        found = {str(c).upper() for c in cves}
        recalled = planted_set & found
        per_tool[tool] = {
            "reported": sorted(found),
            "recalled": sorted(recalled),
            "missed": sorted(planted_set - found),
            "unexpected": sorted(found - planted_set),
            "recall": (len(recalled) / len(planted_set)) if planted_set else None,
        }
    return {"planted": sorted(planted_set), "tools": per_tool}


def agreement_matrix(tool_cves: dict[str, set[str]]) -> dict:
    """Pairwise Jaccard agreement between every pair of tools' CVE sets."""
    tools = sorted(tool_cves)
    out: dict[str, dict[str, float]] = {}
    for a in tools:
        out[a] = {}
        for b in tools:
            out[a][b] = round(_jaccard(set(tool_cves[a]), set(tool_cves[b])), 4)
    return out


def aggregate(host_results: list[dict]) -> dict:
    """Pool per-host comparisons into per-tool planted-CVE recall across the testbed."""
    scored = [h for h in host_results if "error" not in h and h.get("planted")]
    tools: set[str] = set()
    for h in scored:
        tools |= set(h["tools"])
    per_tool: dict[str, dict] = {}
    for tool in sorted(tools):
        planted_total = 0
        recalled_total = 0
        unexpected_total = 0
        hosts_seen = 0
        for h in scored:
            t = h["tools"].get(tool)
            if not t:
                continue
            hosts_seen += 1
            planted_total += len(h["planted"])
            recalled_total += len(t["recalled"])
            unexpected_total += len(t["unexpected"])
        per_tool[tool] = {
            "hosts": hosts_seen,
            "planted": planted_total,
            "recalled": recalled_total,
            "unexpected": unexpected_total,
            "recall": (recalled_total / planted_total) if planted_total else None,
        }
    return {"hosts_scored": len(scored), "tools": per_tool}


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def _pct(x) -> str:
    return "—" if x is None else f"{x:.2f}"


def render_md(result: dict) -> str:
    agg = result["summary"]
    lines = [
        f"### CVE-detection baselines — `{result['subnet']}`  ({result['timestamp']})",
        "",
        "Same pinned testbed, three detectors. **Recall** is over the planted, "
        "documented CVEs; **unexpected** CVEs are surfaced for review, not scored "
        "as false positives (a rolling image's full CVE set is not knowable a priori).",
        "",
        "| Tool | Hosts | Planted-CVE recall | Recalled | Unexpected |",
        "|---|---:|---:|---:|---:|",
    ]
    for tool in sorted(agg["tools"]):
        t = agg["tools"][tool]
        lines.append(
            f"| **{tool}** | {t['hosts']} | {_pct(t['recall'])} | "
            f"{t['recalled']}/{t['planted']} | {t['unexpected']} |"
        )
    lines += ["", "| Host | Planted | " +
              " | ".join(f"{tool} recall" for tool in sorted(agg["tools"])) + " |",
              "|---|---|" + "---|" * len(agg["tools"])]
    for h in result["hosts"]:
        if "error" in h:
            lines.append(f"| `{h['ip']}` ({h.get('name', '')}) | _error_ | {h['error']} |")
            continue
        cells = []
        for tool in sorted(agg["tools"]):
            t = h["tools"].get(tool)
            cells.append(_pct(t["recall"]) if t else "n/a")
        lines.append(
            f"| `{h['ip']}` ({h.get('name', '')}) | {', '.join(h['planted']) or '—'} | "
            + " | ".join(cells) + " |"
        )
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Live runner (needs the testbed up + nmap / nuclei; operator-run)
# --------------------------------------------------------------------------- #
def _run(cmd: list[str]) -> str:
    """Run a baseline scanner, returning stdout ('' on any failure/timeout)."""
    try:
        proc = subprocess.run(  # nosec B603 - fixed args, target is operator-supplied
            cmd, capture_output=True, text=True, check=False, timeout=_HTTP_TIMEOUT,
        )
        return proc.stdout or ""
    except (OSError, subprocess.SubprocessError):
        return ""


def run_nmap_vulners(ip: str, ports_spec: str) -> set[str] | None:
    """nmap version-scan + `vulners` NSE → CVE set. None if nmap is unavailable."""
    if not shutil.which("nmap"):
        return None
    out = _run(["nmap", "-sV", "--script", "vulners", "-p", ports_spec, "-Pn", ip])
    return parse_nmap_vulners(out)


def _nuclei_targets(ip: str, host_ports: list[dict]) -> list[str]:
    """Build the target list Nuclei should scan for a host: an http(s) URL per web
    port, plus the bare ip for network templates."""
    targets = [ip]
    for p in host_ports:
        if p.get("service") in _HTTP_SERVICES:
            scheme = "https" if p.get("service") == "https" or p.get("port") == 443 else "http"
            targets.append(f"{scheme}://{ip}:{p['port']}")
    return targets


def run_nuclei(ip: str, host_ports: list[dict]) -> set[str] | None:
    """Nuclei CVE templates → CVE set. None if nuclei is unavailable."""
    if not shutil.which("nuclei"):
        return None
    cves: set[str] = set()
    for target in _nuclei_targets(ip, host_ports):
        out = _run(["nuclei", "-u", target, "-tags", "cve", "-jsonl", "-silent",
                    "-disable-update-check", "-timeout", "10"])
        cves |= parse_nuclei_jsonl(out.splitlines())
    return cves


def _import_scanner():
    backend = os.path.join(_ROOT, "backend")
    if backend not in sys.path:
        sys.path.insert(0, backend)
    import scanner  # noqa: PLC0415 - lazy so the pure scoring has no backend/nmap dep
    return scanner


def run_enumgrid(ip: str, ports_spec: str) -> set[str]:
    """EnumGrid's own on-demand vuln scan → CVE set (the SAME code path as the UI)."""
    scanner_mod = _import_scanner()
    host = scanner_mod._service_scan(
        ip, privileged=scanner_mod.is_privileged(), deep=True,
        profile="vuln", ports=ports_spec, auto_cve=True,
    )
    cves: set[str] = set()
    for p in host.get("ports", []):
        for v in getattr(p, "vulns", []):
            cves.add(v.id)
    for v in host.get("vulns", []):
        cves.add(v.id)
    return cves


def ports_spec_for(gt: dict) -> str:
    wanted: set[int] = set(gt.get("decoy_ports", []))
    for h in gt.get("hosts", []):
        for p in h.get("ports", []):
            wanted.add(int(p["port"]))
    return ",".join(str(p) for p in sorted(wanted))


_RUNNERS = {
    "enumgrid": lambda ip, spec, host: run_enumgrid(ip, spec),
    "nmap-vulners": lambda ip, spec, host: run_nmap_vulners(ip, spec),
    "nuclei": lambda ip, spec, host: run_nuclei(ip, host.get("ports", [])),
}


def run(gt: dict, tools: list[str], ports_spec: str | None = None,
        log=lambda _m: None) -> dict:
    """Run each requested baseline on every testbed host and compare. Errors surfaced."""
    ports_spec = ports_spec or ports_spec_for(gt)
    host_results = []
    for entry in gt.get("hosts", []):
        ip = entry["ip"]
        planted = entry.get("planted_cves", [])
        log(f"» {ip} ({entry.get('name', '')}) — {', '.join(tools)} …")
        tool_cves: dict[str, set[str]] = {}
        error = None
        for tool in tools:
            runner = _RUNNERS.get(tool)
            if runner is None:
                continue
            try:
                found = runner(ip, ports_spec, entry)
            except Exception as exc:  # noqa: BLE001 - a scan failure is reported, not faked
                error = f"{tool}: {exc}"
                continue
            if found is None:
                log(f"    {tool}: unavailable (not installed) — skipped")
                continue
            tool_cves[tool] = found
        if error and not tool_cves:
            host_results.append({"ip": ip, "name": entry.get("name", ""), "error": error})
            continue
        rec = compare_host(planted, tool_cves)
        rec.update({"ip": ip, "name": entry.get("name", ""),
                    "agreement": agreement_matrix(tool_cves)})
        host_results.append(rec)
    return {
        "subnet": gt.get("subnet", ""),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "ports": ports_spec,
        "tools": tools,
        "hosts": host_results,
        "summary": aggregate(host_results),
    }


def load_ground_truth(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="EnumGrid CVE-detection baseline comparison")
    ap.add_argument("--ground-truth", default=_DEFAULT_GT, help="path to ground_truth.json")
    ap.add_argument("--tools", default="enumgrid,nmap-vulners,nuclei",
                    help="comma list of: enumgrid, nmap-vulners, nuclei")
    ap.add_argument("--ports", help="override the probed port spec (default: gt ports ∪ decoys)")
    ap.add_argument("--json", metavar="FILE", help="write the full result as JSON")
    ap.add_argument("--md", metavar="FILE", help="append the markdown table to this path")
    args = ap.parse_args(argv)

    tools = [t.strip() for t in args.tools.split(",") if t.strip() in _RUNNERS]
    gt = load_ground_truth(args.ground_truth)
    result = run(gt, tools, ports_spec=args.ports, log=lambda m: print(m, file=sys.stderr))
    md = render_md(result)
    print("\n" + md + "\n")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        print(f"→ wrote {args.json}", file=sys.stderr)
    if args.md:
        with open(args.md, "a", encoding="utf-8") as fh:
            fh.write(md + "\n\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
