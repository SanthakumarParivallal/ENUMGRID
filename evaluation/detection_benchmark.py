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
  * **Versions** — of the found ports that carry an expected version in the
    ground truth, how many reported the right version *string* (2.4.49 vs 2.4.50).
    This is the bridge between service detection and CVE matching: an accurate
    service name on a wrong version would still mismatch every CVE. Ports whose
    version nmap can't reliably fingerprint (e.g. auth-gated Postgres) carry no
    expected version and are simply not version-scored — honest by omission.
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

It also reports accuracy **by nmap detection confidence** (a high-confidence,
actively-probed match is more trustworthy than a port-table guess), and can
measure its own **run-to-run stability** (`--repeat N`) — a serious scanner
quantifies its flakiness rather than pretending a live scan is deterministic.

Usage (with the testbed up — `docker compose -f evaluation/docker-compose.yml up -d`):
    python evaluation/detection_benchmark.py                 # uses ground_truth.json
    python evaluation/detection_benchmark.py --json out.json --md out.md
    python evaluation/detection_benchmark.py --ports 22,80,443,2222,6379
    python evaluation/detection_benchmark.py --repeat 3      # run-to-run stability

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

# nmap service/version-detection confidence is 1–10. >= this is an actively-probed,
# high-confidence match; below it (or None) is a port-table guess we trust less.
# Reporting accuracy *by* this band substantiates "high-confidence hits are more
# accurate" rather than hiding it inside one blended number.
_HIGH_CONF = 7


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


def score_versions(detected: dict, truth: dict) -> dict:
    """Of the found ports that carry an expected version, how many match.

    ``truth`` maps port → an expected version *token* (e.g. "2.4.49"); a port with
    no/empty expected version is skipped (nmap can't always fingerprint a version,
    and we never penalise what we don't assert). A detection matches when the
    reported version string CONTAINS the expected token, so "Apache httpd 2.4.49
    ((Unix))" satisfies "2.4.49" but "2.4.50" does not — the 2.4.49-vs-2.4.50
    distinction the CVE match hinges on."""
    detected = {int(p): (v or "").strip().lower() for p, v in detected.items()}
    scored = 0
    correct = 0
    mismatches = []
    for port, exp_raw in sorted(truth.items()):
        exp = (exp_raw or "").strip().lower()
        if not exp:
            continue                                   # unversioned truth → not scored
        if port in detected:
            scored += 1
            got = detected[port]
            if exp in got:
                correct += 1
            else:
                mismatches.append({"port": port, "expected": exp, "got": got})
    return {
        "scored_ports": scored,
        "correct": correct,
        "accuracy": (correct / scored) if scored else None,
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


def confidence_samples(detected: dict, truth: dict) -> list[dict]:
    """Per-found-port record of (confidence, service_ok, version_ok).

    One row per expected port that was actually found, tagging each detection
    decision with nmap's confidence so accuracy can be reported by confidence
    band. ``version_ok`` is None when the ground truth asserts no version."""
    truth_ports = {int(p["port"]): _norm_service(p.get("service", "")) for p in truth.get("ports", [])}
    truth_vers = {int(p["port"]): (p.get("version", "") or "").strip().lower()
                  for p in truth.get("ports", [])}
    det_ports = {int(p): _norm_service(s) for p, s in detected.get("ports", {}).items()}
    det_vers = {int(p): (v or "").strip().lower() for p, v in detected.get("versions", {}).items()}
    det_confs = {int(p): c for p, c in detected.get("confs", {}).items()}
    rows = []
    for port, exp_svc in sorted(truth_ports.items()):
        if port not in det_ports:
            continue
        exp_ver = truth_vers.get(port, "")
        rows.append({
            "port": port,
            "conf": det_confs.get(port),
            "service_ok": det_ports[port] == exp_svc,
            "version_ok": (exp_ver in det_vers.get(port, "")) if exp_ver else None,
        })
    return rows


def _bucket_confidence(samples: list[dict]) -> dict:
    """Fold confidence samples into high/low bands with per-band accuracy."""
    bands = {b: {"n": 0, "service_correct": 0, "version_scored": 0, "version_correct": 0}
             for b in ("high", "low")}
    for s in samples:
        conf = s.get("conf")
        band = bands["high"] if (conf is not None and conf >= _HIGH_CONF) else bands["low"]
        band["n"] += 1
        band["service_correct"] += 1 if s["service_ok"] else 0
        if s["version_ok"] is not None:
            band["version_scored"] += 1
            band["version_correct"] += 1 if s["version_ok"] else 0
    for band in bands.values():
        band["service_accuracy"] = (band["service_correct"] / band["n"]) if band["n"] else None
        band["version_accuracy"] = (
            band["version_correct"] / band["version_scored"] if band["version_scored"] else None
        )
    return bands


def stability(runs: list[dict]) -> dict:
    """Run-to-run stability of repeated scans of the SAME host (flake measurement).

    A scan is non-deterministic (the network changes, probes race), so a serious
    tool should *quantify* its own flakiness rather than pretend it is zero.
    Given N ``detected_from_host`` dicts for the same target this reports:

      * **port_stability**    — Jaccard of the open-port sets (1.0 = identical
        every run; < 1.0 = a port flapped in/out).
      * **service_stability** — of the ports open in *every* run, the fraction
        whose service name was identical every run.
      * **cve_stability**     — Jaccard of the CVE-id sets across runs.

    One run (nothing to compare) is trivially stable (1.0)."""
    runs = [r for r in runs if r is not None]
    if len(runs) < 2:
        return {"runs": len(runs), "port_stability": 1.0, "service_stability": 1.0,
                "cve_stability": 1.0, "stable_ports": [], "flapping_ports": []}
    port_sets = [set(int(p) for p in r.get("ports", {})) for r in runs]
    inter = set.intersection(*port_sets)
    union = set.union(*port_sets)
    port_stability = (len(inter) / len(union)) if union else 1.0

    svc_agree = 0
    for port in inter:
        names = {_norm_service(r["ports"][port]) for r in runs}
        if len(names) == 1:
            svc_agree += 1
    service_stability = (svc_agree / len(inter)) if inter else 1.0

    cve_sets = [{str(c).upper() for c in r.get("cves", set())} for r in runs]
    ci = set.intersection(*cve_sets)
    cu = set.union(*cve_sets)
    cve_stability = (len(ci) / len(cu)) if cu else 1.0

    return {
        "runs": len(runs),
        "port_stability": port_stability,
        "service_stability": service_stability,
        "cve_stability": cve_stability,
        "stable_ports": sorted(inter),
        "flapping_ports": sorted(union - inter),
    }


def score_host(detected: dict, truth: dict) -> dict:
    """Score one host's detection against its ground-truth entry.

    ``detected`` = {"ports": {port: service}, "cves": set[str]}.
    ``truth``    = a ground_truth.json host entry (+ 'decoy_ports' merged in)."""
    truth_ports = {int(p["port"]): p.get("service", "") for p in truth.get("ports", [])}
    truth_versions = {int(p["port"]): p.get("version", "") for p in truth.get("ports", [])}
    # Decoys are part of what we probed but expect CLOSED, so they belong in the
    # port-precision denominator only via the detected side; expected excludes them.
    detected_ports = {int(p): s for p, s in detected.get("ports", {}).items()}
    detected_versions = {int(p): v for p, v in detected.get("versions", {}).items()}
    return {
        "ip": truth.get("ip", ""),
        "name": truth.get("name", ""),
        "ports": score_ports(set(detected_ports), set(truth_ports)),
        "services": score_services(detected_ports, truth_ports),
        "versions": score_versions(detected_versions, truth_versions),
        "cves": score_cves(detected.get("cves", set()), truth.get("planted_cves", [])),
        "confidence_samples": confidence_samples(detected, truth),
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
    ver_scored = sum(h["versions"]["scored_ports"] for h in scored if "versions" in h)
    ver_correct = sum(h["versions"]["correct"] for h in scored if "versions" in h)
    planted_total = sum(len(h["cves"]["planted"]) for h in scored)
    planted_hit = sum(len(h["cves"]["recalled"]) for h in scored)
    unexpected = sum(len(h["cves"]["unexpected"]) for h in scored)
    all_samples = [s for h in scored for s in h.get("confidence_samples", [])]
    return {
        "hosts_scored": len(scored),
        "hosts_errored": len(host_results) - len(scored),
        "ports": ports,
        "service_accuracy": (svc_correct / svc_scored) if svc_scored else None,
        "service_scored": svc_scored,
        "version_accuracy": (ver_correct / ver_scored) if ver_scored else None,
        "version_scored": ver_scored,
        "cve_recall": (planted_hit / planted_total) if planted_total else None,
        "cve_planted": planted_total,
        "cve_recalled": planted_hit,
        "cve_unexpected": unexpected,
        "confidence_buckets": _bucket_confidence(all_samples),
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
        f"- **Version-string accuracy:** {_pct(agg['version_accuracy'])} "
        f"over {agg['version_scored']} versioned port(s)",
        f"- **Planted-CVE recall:** {_pct(agg['cve_recall'])} "
        f"({agg['cve_recalled']}/{agg['cve_planted']} planted CVEs detected)",
        f"- **Unexpected CVEs (review):** {agg['cve_unexpected']}",
        f"- **False-positive open ports:** {p['fp']}  ·  **missed ports:** {p['fn']}",
    ]
    buckets = agg.get("confidence_buckets")
    if buckets and any(buckets[b]["n"] for b in buckets):
        lines += [
            "",
            f"**Accuracy by nmap detection confidence** (high = conf ≥ {_HIGH_CONF}):",
            "",
            "| Confidence | Detections | Service acc. | Version acc. |",
            "|---|---:|---:|---:|",
        ]
        for band in ("high", "low"):
            b = buckets[band]
            lines.append(
                f"| {band} | {b['n']} | {_pct(b['service_accuracy'])} | {_pct(b['version_accuracy'])} |"
            )
    lines += [
        "",
        "| Host | Ports P/R | Services | Versions | CVE recall | Unexpected |",
        "|---|---|---|---|---|---|",
    ]
    for h in result["hosts"]:
        if "error" in h:
            lines.append(f"| `{h['ip']}` ({h.get('name', '')}) | _error_ | {h['error']} |  |  |  |")
            continue
        hp, hs, hc = h["ports"], h["services"], h["cves"]
        hv = h.get("versions", {"accuracy": None})
        lines.append(
            f"| `{h['ip']}` ({h['name']}) | {hp['precision']:.2f}/{hp['recall']:.2f} | "
            f"{_pct(hs['accuracy'])} | {_pct(hv['accuracy'])} | {_pct(hc['recall'])} | "
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
    """Extract {ports, versions, confs, cves} from a `_service_scan` result."""
    open_states = (scanner_mod.PortState.OPEN, scanner_mod.PortState.OPEN_FILTERED)
    ports: dict[int, str] = {}
    versions: dict[int, str] = {}
    confs: dict[int, int | None] = {}
    cves: set[str] = set()
    for p in host.get("ports", []):
        if p.state in open_states:
            ports[p.port] = p.service
            versions[p.port] = getattr(p, "version", "") or ""
            confs[p.port] = getattr(p, "conf", None)
            for v in p.vulns:
                cves.add(v.id)
    for v in host.get("vulns", []):
        cves.add(v.id)
    return {"ports": ports, "versions": versions, "confs": confs, "cves": cves}


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


def render_stability_md(result: dict) -> str:
    """Markdown for a repeated-scan stability run (flake measurement)."""
    lines = [
        f"### Scan stability — `{result['subnet']}`, {result['repeats']}× per host "
        f"({result['timestamp']})",
        "",
        "Each host scanned repeatedly; 1.00 = identical every run.",
        "",
        "| Host | Runs | Port stability | Service stability | CVE stability | Flapping ports |",
        "|---|---:|---:|---:|---:|---|",
    ]
    for h in result["hosts"]:
        if "error" in h:
            lines.append(f"| `{h['ip']}` ({h.get('name', '')}) | _error_ | {h['error']} |  |  |  |")
            continue
        s = h["stability"]
        lines.append(
            f"| `{h['ip']}` ({h['name']}) | {s['runs']} | {s['port_stability']:.2f} | "
            f"{s['service_stability']:.2f} | {s['cve_stability']:.2f} | "
            f"{', '.join(str(p) for p in s['flapping_ports']) or '—'} |"
        )
    return "\n".join(lines)


def scan_repeat(ip: str, ports_spec: str, profile: str, repeats: int) -> list[dict]:
    """Scan one host ``repeats`` times, returning each run's detected facts."""
    return [scan_target(ip, ports_spec, profile) for _ in range(max(1, repeats))]


def run_stability(gt: dict, repeats: int, ports_spec: str | None = None,
                  profile: str = "vuln", log=lambda _m: None) -> dict:
    """Repeatedly scan every host and report run-to-run stability. Errors surfaced."""
    import time  # noqa: PLC0415 - only the live path needs a wall clock

    ports_spec = ports_spec or ports_spec_for(gt)
    host_results = []
    for entry in gt.get("hosts", []):
        ip = entry["ip"]
        log(f"» stability {ip} ({entry.get('name', '')}) ×{repeats} …")
        try:
            runs = scan_repeat(ip, ports_spec, profile, repeats)
        except Exception as exc:  # noqa: BLE001 - a scan failure is reported, not faked
            host_results.append({"ip": ip, "name": entry.get("name", ""), "error": str(exc)})
            continue
        host_results.append({"ip": ip, "name": entry.get("name", ""), "stability": stability(runs)})
    return {
        "subnet": gt.get("subnet", ""),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "profile": profile,
        "ports": ports_spec,
        "repeats": repeats,
        "hosts": host_results,
    }


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
    ap.add_argument("--repeat", type=int, default=1, metavar="N",
                    help="scan each host N times and report run-to-run stability instead of accuracy")
    ap.add_argument("--json", metavar="FILE", help="write the full result as JSON")
    ap.add_argument("--md", metavar="FILE", help="append the markdown table to this path")
    args = ap.parse_args(argv)

    gt = load_ground_truth(args.ground_truth)
    if args.repeat > 1:
        result = run_stability(gt, args.repeat, ports_spec=args.ports, profile=args.profile,
                               log=lambda m: print(m, file=sys.stderr))
        md = render_stability_md(result)
    else:
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
