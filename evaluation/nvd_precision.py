#!/usr/bin/env python3
"""
nvd_precision.py — precision / recall of EnumGrid's **live-NVD** CPE->CVE pipeline.

`cve_precision.py` measures the OFFLINE curated matcher (a hand-maintained table).
This harness measures the **primary** path: the live NVD API 2.0 lookup in
`backend/cve.py` — `cpe_to_23` -> query NVD by the version-scoped CPE ->
`parse_nvd` -> keep the top `MAX_PER_SERVICE` by CVSS. That pipeline is EnumGrid's
*own* logic layered on the authoritative feed, and it has two failure modes that a
serious tool must quantify rather than assume away:

  * **RECALL** — does query + parse + truncate actually surface the known-important
    CVEs for a version? The "top-N-by-CVSS" cap can silently drop a documented bug
    when a version carries many higher-scored CVEs. Each corpus case pins an
    `expect_present` set: a **lower bound** of CVE ids that MUST appear. NVD returns
    more, and those extras are **not** scored as false positives — a version's full
    CVE set is not knowable a priori, so scoring "unlisted => wrong" would be
    dishonest. Missed ids are split into *truncated* (present in the raw NVD
    response but dropped by the top-N cap) vs *absent* (NVD didn't return it at all)
    so a recall miss is attributed to the right cause.

  * **VERSION-SCOPING PRECISION** — does the version-scoped CPE query correctly
    EXCLUDE CVEs that do not apply to this exact build (fixed upstream, or belonging
    to a different product)? Each case pins an `expect_absent` set that MUST NOT
    appear; any that does is a precision violation. This is the honest precision
    signal for a thin-wrapper-over-NVD path: we cannot re-judge NVD's applicability,
    but we CAN check that a *patched* version and a *different product* come back
    clean.

Two layers, exactly like `detection_benchmark.py`:
  * the pure scoring + the REAL parser (`backend/cve.parse_nvd`) run on NVD-2.0
    **schema fixtures** — unit-tested in CI, no network. This proves the scorer and
    parser are correct; it deliberately does NOT publish a "live" number.
  * the LIVE runner (`--live`) hits the authoritative NVD feed for every corpus CPE
    and computes the PUBLISHED precision / recall. It needs network and honours
    NVD's rate limit, so it is operator-run. Nothing here is fabricated: the
    dissertation number comes from real NVD, and a CPE that fails to fetch is
    reported as an error, never as "found nothing".

The corpus (`evaluation/nvd_corpus.json`) holds only labels (cpe -> expect_present
/ expect_absent) drawn from publicly-documented CVE applicability; `--live` is
authoritative, and any label the live feed contradicts is a *finding to
investigate*, not something to paper over.

Usage:
    python evaluation/nvd_precision.py                 # scorer self-check on fixtures
    python evaluation/nvd_precision.py --live          # real NVD (operator, network)
    python evaluation/nvd_precision.py --live --json out.json --md out.md
    python evaluation/nvd_precision.py --live --min-recall 0.9 --max-violations 0
    ENUMGRID_NVD_API_KEY=… python evaluation/nvd_precision.py --live   # higher rate limit
"""

from __future__ import annotations

import argparse
import json
import os
import sys

# Reuse the Wilson score interval from the offline harness rather than duplicate it.
from cve_precision import wilson_ci

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_CORPUS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nvd_corpus.json")


# --------------------------------------------------------------------------- #
# Scoring (pure, deterministic, unit-tested)
# --------------------------------------------------------------------------- #
def _norm(ids) -> set[str]:
    return {str(c).strip().upper() for c in ids if str(c).strip()}


def raw_cve_ids(data: dict) -> set[str]:
    """Every CVE id present in a raw NVD API 2.0 response (before EnumGrid's top-N).

    Used to attribute a recall miss to *truncation* (the id was in the response but
    dropped by the top-`MAX_PER_SERVICE` cap) vs genuine *absence* (NVD never
    returned it — a query/CPE issue, not a truncation one)."""
    out: set[str] = set()
    for item in (data or {}).get("vulnerabilities", []):
        cid = (item.get("cve", {}) or {}).get("id", "")
        if cid:
            out.add(str(cid).strip().upper())
    return out


def score_case(returned, raw_ids, expect_present, expect_absent) -> dict:
    """Score one CPE's live-NVD result against its labelled expectations.

    `returned`  = CVE ids EnumGrid's pipeline surfaced (post-parse, post-top-N).
    `raw_ids`   = CVE ids in the raw NVD response (to split truncated vs absent).
    Recall is closed only over `expect_present`; extras are not penalised.
    Any `expect_absent` id that appears is a version-scoping precision violation.
    """
    returned, raw = _norm(returned), _norm(raw_ids)
    present, absent = _norm(expect_present), _norm(expect_absent)

    recalled = present & returned
    missed = present - returned
    truncated = missed & raw          # in NVD's response but dropped by the cap
    absent_missing = missed - raw     # NVD never returned it (query/CPE gap)
    violations = absent & returned    # a must-not-appear id came back

    return {
        "expect_present": sorted(present),
        "expect_absent": sorted(absent),
        "returned": sorted(returned),
        "recalled": sorted(recalled),
        "missed": sorted(missed),
        "truncated": sorted(truncated),
        "absent_missing": sorted(absent_missing),
        "violations": sorted(violations),
        "n_present": len(present),
        "n_recalled": len(recalled),
        "n_absent": len(absent),
        "n_violations": len(violations),
    }


def aggregate(cases: list[dict]) -> dict:
    """Micro-average recall (over expect_present) + version-scoping precision.

    Recall is a binomial proportion (recalled / expected-present) with a 95 % Wilson
    CI — the same interval the offline harness uses, correct at the 0/1 boundary.
    Version-scoping precision is (absent labels correctly excluded) / (absent
    labels); a single violation drops it below 1.0 and is named explicitly.
    """
    scored = [c for c in cases if "error" not in c]
    present_total = sum(c["n_present"] for c in scored)
    recalled_total = sum(c["n_recalled"] for c in scored)
    absent_total = sum(c["n_absent"] for c in scored)
    violations_total = sum(c["n_violations"] for c in scored)

    recall = recalled_total / present_total if present_total else 1.0
    r_lo, r_hi = wilson_ci(recalled_total, present_total)
    absent_clean = absent_total - violations_total
    scoping = absent_clean / absent_total if absent_total else 1.0
    s_lo, s_hi = wilson_ci(absent_clean, absent_total)

    by_cat: dict[str, dict] = {}
    for c in scored:
        cat = by_cat.setdefault(
            c.get("category", ""),
            {"present": 0, "recalled": 0, "absent": 0, "violations": 0, "cases": 0},
        )
        cat["present"] += c["n_present"]
        cat["recalled"] += c["n_recalled"]
        cat["absent"] += c["n_absent"]
        cat["violations"] += c["n_violations"]
        cat["cases"] += 1
    for cat in by_cat.values():
        cat["recall"] = cat["recalled"] / cat["present"] if cat["present"] else 1.0
        cat["scoping"] = (
            (cat["absent"] - cat["violations"]) / cat["absent"] if cat["absent"] else 1.0
        )

    return {
        "cases": len(cases),
        "scored": len(scored),
        "errors": [c["cpe"] for c in cases if "error" in c],
        "recall": recall,
        "recall_ci": [r_lo, r_hi],
        "recalled": recalled_total,
        "present": present_total,
        "scoping_precision": scoping,
        "scoping_ci": [s_lo, s_hi],
        "absent": absent_total,
        "violations": violations_total,
        "truncation_losses": sorted(
            {t for c in scored for t in c["truncated"]}
        ),
        "violation_detail": [
            {"cpe": c["cpe"], "violations": c["violations"]}
            for c in scored
            if c["n_violations"]
        ],
        "missed_detail": [
            {"cpe": c["cpe"], "missed": c["missed"]}
            for c in scored
            if c["missed"]
        ],
        "by_category": by_cat,
    }


# --------------------------------------------------------------------------- #
# Wiring the REAL parser (CI-safe: takes a JSON dict, does no network itself)
# --------------------------------------------------------------------------- #
def _import_cve():
    """Lazily import the real live-NVD module so pure scoring has no backend dep."""
    backend = os.path.join(_ROOT, "backend")
    if backend not in sys.path:
        sys.path.insert(0, backend)
    import cve  # noqa: PLC0415 - lazy so the pure scorer imports without the backend

    return cve


def evaluate_response(data: dict, expect_present, expect_absent, parser=None) -> dict:
    """Run the REAL `cve.parse_nvd` on one NVD response dict and score it.

    Deterministic and network-free — this is what CI exercises with schema fixtures,
    and what the live runner calls per fetched response, so the published number and
    the unit test share the exact production parser."""
    parser = parser or _import_cve().parse_nvd
    returned = [getattr(v, "id", v) for v in parser(data)]
    return score_case(returned, raw_cve_ids(data), expect_present, expect_absent)


def run_fixtures(fixtures: list[dict], parser=None) -> dict:
    """Score a list of {cpe, data, expect_present, expect_absent, category} fixtures.

    Used by the CI self-check (schema fixtures) and available for replaying captured
    responses offline. `data` is a raw NVD-2.0 response dict."""
    cases: list[dict] = []
    for fx in fixtures:
        row = evaluate_response(
            fx["data"], fx.get("expect_present", []), fx.get("expect_absent", []), parser
        )
        row["cpe"] = fx["cpe"]
        row["category"] = fx.get("category", "")
        row["note"] = fx.get("note", "")
        cases.append(row)
    return {"source": "fixtures", "cases": cases, "summary": aggregate(cases)}


# --------------------------------------------------------------------------- #
# Live runner (needs network; hits the authoritative NVD feed — operator-run)
# --------------------------------------------------------------------------- #
def run_live(corpus: dict, cve_mod=None, limit: int | None = None) -> dict:
    """Query real NVD for every corpus CPE and score the live-NVD pipeline.

    Honours NVD's published rate limit via the production limiter (`cve._acquire_slot`)
    and reuses the production query + parser, so the measured accuracy is the
    product's. A CPE that fails to fetch is recorded as an error, not a zero-score."""
    cve = cve_mod or _import_cve()
    cases: list[dict] = []
    for case in corpus.get("cases", [])[: limit or None]:
        cpe = case["cpe"]
        cpe23 = cve.cpe_to_23(cpe) or cpe
        cve._acquire_slot(None)  # block until a rate-limit slot is free (real limiter)
        try:
            data = cve._query_nvd(cpe23)
        except Exception as exc:  # noqa: BLE0001 - honest: any fetch failure is reported
            cases.append(
                {"cpe": cpe, "category": case.get("category", ""), "error": str(exc)}
            )
            continue
        row = evaluate_response(
            data, case.get("expect_present", []), case.get("expect_absent", []), cve.parse_nvd
        )
        row["cpe"] = cpe
        row["category"] = case.get("category", "")
        row["note"] = case.get("note", "")
        row["raw_count"] = len(raw_cve_ids(data))
        cases.append(row)
    return {
        "source": "live-nvd",
        "endpoint": cve.NVD_URL,
        "api_key": cve.key_active(),
        "cases": cases,
        "summary": aggregate(cases),
    }


def load_corpus(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _nvd_item(cid: str, score: float | None) -> dict:
    """One NVD-2.0 `vulnerabilities[]` entry (the exact shape `parse_nvd` reads)."""
    metrics = {"cvssMetricV31": [{"cvssData": {"baseScore": score}}]} if score is not None else {}
    return {"cve": {"id": cid, "descriptions": [{"lang": "en", "value": cid}], "metrics": metrics}}


def _nvd_response(items: list[tuple[str, float | None]]) -> dict:
    """A minimal, hand-authored NVD-2.0 response following the documented schema.

    These are SCHEMA FIXTURES for the offline scorer self-check — not live captures.
    CVE ids/CVSS quoted here are publicly-documented facts; `CVE-2099-*` ids are
    synthetic filler used only to force the top-N truncation path. `--live` is the
    authoritative source of real numbers."""
    return {"vulnerabilities": [_nvd_item(cid, s) for cid, s in items]}


# A tiny self-check set so `nvd_precision.py` (no --live) can prove the scorer +
# real parser run end-to-end without network. The full edge-case fixtures live in
# the test module. See the module docstring: this is NOT the published live number.
SELFCHECK_FIXTURES: list[dict] = [
    {"cpe": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", "category": "recall",
     "expect_present": ["CVE-2021-41773"], "expect_absent": [],
     "data": _nvd_response([("CVE-2021-42013", 9.8), ("CVE-2021-41773", 7.5)])},
    {"cpe": "cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*", "category": "version-scope",
     "expect_present": [], "expect_absent": ["CVE-2021-41773", "CVE-2021-42013"],
     "data": _nvd_response([("CVE-2021-44790", 9.8)])},
]


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def _ci(pair) -> str:
    lo, hi = pair
    return "—" if lo is None else f"[{lo:.3f}, {hi:.3f}]"


def render_md(result: dict) -> str:
    s = result["summary"]
    live = result.get("source") == "live-nvd"
    head = (
        f"### Live-NVD CVE pipeline — precision / recall ({s['scored']} CPEs, "
        f"{'live NVD feed' if live else 'schema fixtures'})"
    )
    lines = [
        head,
        "",
        "Measures EnumGrid's primary path: version-scoped CPE query -> `parse_nvd` -> "
        "top-N by CVSS. Recall is a lower bound over documented CVEs (extras are not "
        "penalised); version-scoping precision checks that patched/other-product CPEs "
        "come back clean. 95 % Wilson CIs.",
        "",
        "| Metric | Value | 95 % CI | Counts |",
        "|---|---:|:---:|---|",
        f"| **Recall** (documented CVEs surfaced) | {s['recall']:.3f} | {_ci(s['recall_ci'])} | "
        f"{s['recalled']}/{s['present']} |",
        f"| **Version-scoping precision** | {s['scoping_precision']:.3f} | {_ci(s['scoping_ci'])} | "
        f"{s['absent'] - s['violations']}/{s['absent']} excluded |",
    ]
    if not live:
        lines += [
            "",
            "> Fixture self-check only — proves the scorer + `parse_nvd` are correct. "
            "Run `--live` for the authoritative measurement against real NVD.",
        ]
    lines += [
        "",
        "| Category | CPEs | Recall | Scoping |",
        "|---|---:|---:|---:|",
    ]
    for name in sorted(s["by_category"]):
        c = s["by_category"][name]
        lines.append(
            f"| {name} | {c['cases']} | {c['recall']:.3f} | {c['scoping']:.3f} |"
        )
    if s["truncation_losses"]:
        lines += ["", f"- **Recall lost to top-N truncation:** {', '.join(s['truncation_losses'])}"]
    if s["violation_detail"]:
        v = "; ".join(f"{d['cpe']} → {', '.join(d['violations'])}" for d in s["violation_detail"])
        lines += [f"- **Version-scoping violations:** {v}"]
    else:
        lines += ["", "- **Version-scoping violations:** none"]
    if s["errors"]:
        lines += [f"- **Fetch errors (not scored):** {', '.join(s['errors'])}"]
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="EnumGrid live-NVD CVE precision/recall")
    ap.add_argument("--corpus", default=_DEFAULT_CORPUS, help="path to nvd_corpus.json")
    ap.add_argument("--live", action="store_true",
                    help="hit the real NVD feed (needs network; operator-run). "
                         "Without it, only the fixture scorer self-check runs.")
    ap.add_argument("--limit", type=int, default=None, help="only query the first N CPEs")
    ap.add_argument("--json", metavar="FILE", help="write the full result as JSON")
    ap.add_argument("--md", metavar="FILE", help="append the markdown table to this path")
    ap.add_argument("--min-recall", type=float, default=None,
                    help="exit 1 if measured recall is below this")
    ap.add_argument("--max-violations", type=int, default=None,
                    help="exit 1 if version-scoping violations exceed this")
    args = ap.parse_args(argv)

    if not args.live:
        print(
            "\nnvd_precision measures the LIVE NVD pipeline. Re-run with --live "
            "(needs network) for the authoritative number.\n"
            "Running the scorer self-check on NVD-2.0 schema fixtures instead:\n",
            file=sys.stderr,
        )
        result = run_fixtures(SELFCHECK_FIXTURES)
    else:
        result = run_live(load_corpus(args.corpus), limit=args.limit)

    md = render_md(result)
    print("\n" + md + "\n")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        print(f"→ wrote {args.json}", file=sys.stderr)
    if args.md:
        with open(args.md, "a", encoding="utf-8") as fh:
            fh.write(md + "\n\n")

    s = result["summary"]
    failed = False
    if args.min_recall is not None and s["recall"] < args.min_recall:
        print(f"FAIL: recall {s['recall']:.3f} < {args.min_recall}", file=sys.stderr)
        failed = True
    if args.max_violations is not None and s["violations"] > args.max_violations:
        print(f"FAIL: {s['violations']} scoping violations > {args.max_violations}", file=sys.stderr)
        failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
