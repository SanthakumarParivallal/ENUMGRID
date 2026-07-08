#!/usr/bin/env python3
"""
detection_benchmark.py — ground-truth **detection accuracy** for EnumGrid.

benchmark.py measures host *discovery* (did we find the live hosts?). This
harness measures the next layer — did the on-demand service scan report the
right **ports, services, and CVEs** — against a known testbed whose answer is
fixed in advance (evaluation/docker-compose.yml + evaluation/ground_truth.json).
That turns the project's "no false positives / accurate" claim into numbers:

  * **Ports**    — precision / recall / F1 of the open-port set. Decoy ports that
    are probed but closed make a false positive show up as precision < 1.
  * **Services** — of the correctly-found ports, how many got the right service
    name (nginx/apache → http, openssh → ssh, redis → redis).
  * **CVEs**     — *recall* of a planted, documented CVE (Apache 2.4.49 →
    CVE-2021-41773/42013): did the scanner surface the bug we know is there? Any
    CVE reported beyond the planted set is surfaced as "unexpected" (a candidate
    false positive on the patched hosts) rather than silently scored, because a
    rolling image's full CVE set is not knowable a priori — honest by design.

The scan uses the SAME code path as the dashboard (backend `scanner._service_scan`
with `auto_cve`), so the measured accuracy is the product's, not a re-implementation.

Two layers, like benchmark.py:
  * the scoring functions are pure and unit-tested (see test_detection_benchmark.py)
    so the published numbers are trustworthy and run in CI with no Docker/network;
  * the live runner needs the testbed up + nmap installed and is operator-run.

Usage (with the testbed up — `docker compose -f evaluation/docker-compose.yml up -d`):
    python evaluation/detection_benchmark.py                 # uses ground_truth.json
    python evaluation/detection_benchmark.py --json out.json --md out.md
    python evaluation/detection_benchmark.py --ports 22,80,443,2222,6379

Nothing is fabricated: a host that fails to scan is reported as an error, never as
"found nothing".
"""

from __future__ import annotations

import argparse
import json
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_GT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ground_truth.json")

# nmap service-name normalisation so "https"/"www" don't count as a service miss
# against a ground truth that says "http". Only collapses genuinely-equivalent
# names; unrelated services stay distinct.
_SERVICE_ALIASES = {
    "www": "http",
    "http-alt": "http",
    "http-proxy": "http",
    "https": "http",
    "ssh": "ssh",
    "microsoft-ds": "smb",
}


# --------------------------------------------------------------------------- #
# Scoring (pure, deterministic, unit-tested — no Docker, no network)
# --------------------------------------------------------------------------- #
def _prf(found: set, truth: set) -> dict:
    """Precision / recall / F1 of a found set against a truth set."""
    tp = len(found & truth)
    precision = tp / len(found) if found else (1.0 if not truth else 0.0)
    recall = tp / len(truth) if truth else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"precision": precision, "recall": recall, "f1": f1}


def _norm_service(name: str) -> str:
    n = (name or "").strip().lower()
    return _SERVICE_ALIASES.get(n, n)


def score_ports(detected: set[int], truth: set[int]) -> dict:
    """Open-port detection accuracy + the concrete false-positive / missed sets."""
    detected, truth = set(detected), set(truth)
    return {
        **_prf(detected, truth),
        "expected": sorted(truth),
        "detected": sorted(detected),
        "false_positives": sorted(detected - truth),   # reported open but shouldn't be
        "missed": sorted(truth - detected),            # should be open but not reported
    }


def score_services(detected: dict, truth: dict) -> dict:
    """Of the expected ports that were found, how many got the right service name."""
    truth = {int(p): _norm_service(s) for p, s in truth.items()}
    detected = {int(p): _norm_service(s) for p, s in detected.items()}
    scored = 0
    correct = 0
    mismatches = []
    for port, exp in sorted(truth.items()):
        if port in detected:
            scored += 1
            if detected[port] == exp:
                correct += 1
            else:
                mismatches.append({"port": port, "expected": exp, "got": detected[port]})
    return {
        "scored_ports": scored,
        "correct": correct,
        "accuracy": (correct / scored) if scored else None,   # None = nothing to score
        "mismatches": mismatches,
    }


def score_cves(detected: set, planted: set) -> dict:
    """Recall of the planted CVEs; unexpected CVEs are surfaced, not scored.

    We can guarantee the planted CVEs are present (pinned vulnerable image), so
    recall is a true metric. We CANNOT enumerate a rolling image's full CVE set,
    so extra CVEs are reported as 'unexpected' for review rather than counted as
    false positives — over-claiming would be dishonest."""
    planted = {str(c).upper() for c in planted}
    detected = {str(c).upper() for c in detected}
    recalled = planted & detected
    return {
        "planted": sorted(planted),
        "recalled": sorted(recalled),
        "missed": sorted(planted - detected),
        "recall": (len(recalled) / len(planted)) if planted else None,
        "unexpected": sorted(detected - planted),
    }


def score_host(detected: dict, truth: dict) -> dict:
    """Score one host's detection against its ground-truth entry.

    ``detected`` = {"ports": {port: service}, "cves": set[str]}.
    ``truth``    = a ground_truth.json host entry (+ 'decoy_ports' merged in)."""
    truth_ports = {int(p["port"]): p.get("service", "") for p in truth.get("ports", [])}
    # Decoys are part of what we probed but expect CLOSED, so they belong in the
    # port-precision denominator only via the detected side; expected excludes them.
    detected_ports = {int(p): s for p, s in detected.get("ports", {}).items()}
    return {
        "ip": truth.get("ip", ""),
        "name": truth.get("name", ""),
        "ports": score_ports(set(detected_ports), set(truth_ports)),
        "services": score_services(detected_ports, truth_ports),
        "cves": score_cves(detected.get("cves", set()), truth.get("planted_cves", [])),
    }


def _micro(hosts: list[dict], key: str) -> dict:
    """Micro-averaged precision/recall/F1 for a port-level metric across hosts."""
    tp = fp = fn = 0
    for h in hosts:
        expected = set(h[key]["expected"])
        detected = set(h[key]["detected"])
        tp += len(detected & expected)
        fp += len(detected - expected)
        fn += len(expected - detected)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"precision": precision, "recall": recall, "f1": f1, "tp": tp, "fp": fp, "fn": fn}


def aggregate(host_results: list[dict]) -> dict:
    """Fold per-host scores into headline detection metrics."""
    scored = [h for h in host_results if "error" not in h]
    ports = _micro(scored, "ports")
    svc_scored = sum(h["services"]["scored_ports"] for h in scored)
    svc_correct = sum(h["services"]["correct"] for h in scored)
    planted_total = sum(len(h["cves"]["planted"]) for h in scored)
    planted_hit = sum(len(h["cves"]["recalled"]) for h in scored)
    unexpected = sum(len(h["cves"]["unexpected"]) for h in scored)
    return {
        "hosts_scored": len(scored),
        "hosts_errored": len(host_results) - len(scored),
        "ports": ports,
        "service_accuracy": (svc_correct / svc_scored) if svc_scored else None,
        "service_scored": svc_scored,
        "cve_recall": (planted_hit / planted_total) if planted_total else None,
        "cve_planted": planted_total,
        "cve_recalled": planted_hit,
        "cve_unexpected": unexpected,
    }


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def _pct(x) -> str:
    return "—" if x is None else f"{x:.2f}"


def render_md(result: dict) -> str:
    agg = result["summary"]
    p = agg["ports"]
    lines = [
        f"### Detection benchmark — `{result['subnet']}`  ({result['timestamp']})",
        "",
        f"Scan path: EnumGrid `_service_scan` (profile `{result['profile']}`, "
        f"ports `{result['ports']}`). Ground truth: {agg['hosts_scored']} host(s).",
        "",
        "| Metric | Precision | Recall | F1 |",
        "|---|---:|---:|---:|",
        f"| **Open ports** | {p['precision']:.2f} | {p['recall']:.2f} | {p['f1']:.2f} |",
        "",
        f"- **Service-name accuracy:** {_pct(agg['service_accuracy'])} "
        f"over {agg['service_scored']} found port(s)",
        f"- **Planted-CVE recall:** {_pct(agg['cve_recall'])} "
        f"({agg['cve_recalled']}/{agg['cve_planted']} planted CVEs detected)",
        f"- **Unexpected CVEs (review):** {agg['cve_unexpected']}",
        f"- **False-positive open ports:** {p['fp']}  ·  **missed ports:** {p['fn']}",
        "",
        "| Host | Ports P/R | Services | CVE recall | Unexpected |",
        "|---|---|---|---|---|",
    ]
    for h in result["hosts"]:
        if "error" in h:
            lines.append(f"| `{h['ip']}` ({h.get('name', '')}) | _error_ | {h['error']} |  |  |")
            continue
        hp, hs, hc = h["ports"], h["services"], h["cves"]
        lines.append(
            f"| `{h['ip']}` ({h['name']}) | {hp['precision']:.2f}/{hp['recall']:.2f} | "
            f"{_pct(hs['accuracy'])} | {_pct(hc['recall'])} | "
            f"{', '.join(hc['unexpected']) or '—'} |"
        )
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Live runner (needs the testbed up + nmap; imports the backend scanner lazily)
# --------------------------------------------------------------------------- #
def _import_scanner():
    backend = os.path.join(_ROOT, "backend")
    if backend not in sys.path:
        sys.path.insert(0, backend)
    import scanner  # noqa: PLC0415 - lazy so the pure scoring has no backend/nmap dep
    return scanner


def detected_from_host(host: dict, scanner_mod) -> dict:
    """Extract {ports:{port:service}, cves:set} from a `_service_scan` result."""
    open_states = (scanner_mod.PortState.OPEN, scanner_mod.PortState.OPEN_FILTERED)
    ports: dict[int, str] = {}
    cves: set[str] = set()
    for p in host.get("ports", []):
        if p.state in open_states:
            ports[p.port] = p.service
            for v in p.vulns:
                cves.add(v.id)
    for v in host.get("vulns", []):
        cves.add(v.id)
    return {"ports": ports, "cves": cves}


def scan_target(ip: str, ports_spec: str, profile: str = "vuln") -> dict:
    """Run the real on-demand scan for one host and return its detected facts."""
    scanner_mod = _import_scanner()
    host = scanner_mod._service_scan(
        ip,
        privileged=scanner_mod.is_privileged(),
        deep=True,
        profile=profile,
        ports=ports_spec,
        auto_cve=True,
    )
    return detected_from_host(host, scanner_mod)


def ports_spec_for(gt: dict) -> str:
    """Comma port spec = every ground-truth port ∪ decoy ports (fair + fast)."""
    wanted: set[int] = set(gt.get("decoy_ports", []))
    for h in gt.get("hosts", []):
        for p in h.get("ports", []):
            wanted.add(int(p["port"]))
    return ",".join(str(p) for p in sorted(wanted))


def load_ground_truth(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def run(gt: dict, ports_spec: str | None = None, profile: str = "vuln",
        log=lambda _m: None) -> dict:
    """Scan every ground-truth host and score detection. Errors are surfaced."""
    import time  # noqa: PLC0415 - only the live path needs a wall clock

    ports_spec = ports_spec or ports_spec_for(gt)
    host_results = []
    for entry in gt.get("hosts", []):
        ip = entry["ip"]
        log(f"» scanning {ip} ({entry.get('name', '')}) …")
        try:
            detected = scan_target(ip, ports_spec, profile)
        except Exception as exc:  # noqa: BLE001 - a scan failure is reported, not faked
            host_results.append({"ip": ip, "name": entry.get("name", ""), "error": str(exc)})
            continue
        host_results.append(score_host(detected, entry))
    return {
        "subnet": gt.get("subnet", ""),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "profile": profile,
        "ports": ports_spec,
        "hosts": host_results,
        "summary": aggregate(host_results),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="EnumGrid ground-truth detection benchmark")
    ap.add_argument("--ground-truth", default=_DEFAULT_GT, help="path to ground_truth.json")
    ap.add_argument("--ports", help="override the probed port spec (default: gt ports ∪ decoys)")
    ap.add_argument("--profile", default="vuln", help="nmap profile (default: vuln — enables NSE CVE scripts)")
    ap.add_argument("--json", metavar="FILE", help="write the full result as JSON")
    ap.add_argument("--md", metavar="FILE", help="append the markdown table to this path")
    args = ap.parse_args(argv)

    gt = load_ground_truth(args.ground_truth)
    result = run(gt, ports_spec=args.ports, profile=args.profile,
                 log=lambda m: print(m, file=sys.stderr))
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
