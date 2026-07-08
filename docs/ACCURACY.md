# Accuracy & Limitations

> Dissertation section. How accurate is ENUMGRID, how do we *know*, and where are
> the edges? Every number below is produced by a checked-in, reproducible harness
> (`evaluation/`) or a determinism test (`backend/tests/test_golden.py`), not
> asserted. This document is the honest counterpart to the feature list: what is
> measured, what is bounded, and what is explicitly out of scope.

## 1. The principle: measured, bounded, fail-safe

A network scanner cannot be "100 % accurate" in the absolute — the network itself
is non-deterministic (hosts appear and vanish between probes), service banners can
be spoofed or ambiguous, and a version string alone cannot prove exploitability.
Claiming otherwise would be the very dishonesty this project rejects. The
publication-grade bar is therefore threefold:

1. **Measured** — accuracy is a number produced by a harness, with the harness
   itself unit-tested so the number is trustworthy.
2. **Bounded** — every headline carries a confidence interval, so the reader sees
   the uncertainty instead of a false point-certainty.
3. **Fail-safe** — when the tool is unsure it says *"Unknown"* or surfaces the
   finding for review; it never fabricates a host, a port, a version, or a CVE.
   A missed detail is recoverable; an invented one is not.

## 2. The four measured layers

| Layer | Harness | Metric | Measured result |
| --- | --- | --- | --- |
| **Discovery** | `evaluation/benchmark.py` | host recall / precision vs `nmap -sn` | recall **0.98–1.00**, precision **1.00** (vs `nmap -sn` 0.07–0.27 unprivileged) — see [EVALUATION.md](EVALUATION.md) |
| **Detection** | `evaluation/detection_benchmark.py` | port P/R, service + **version** accuracy, planted-CVE recall, **by confidence** | ports **1.00/1.00**, service **1.00**, version **1.00**, planted-CVE recall **1.00** on the pinned testbed |
| **CVE matching** | `evaluation/cve_precision.py` | **precision *and* recall** of version→CVE, offline | **precision 1.00, recall 1.00**, 0 false positives over 33 labelled cases (95 % Wilson CI [0.82, 1.00]) |
| **Copilot grounding** | `evaluation/copilot_eval.py` | fabrication rate of the AI explanation | grounding **1.000 ± 0.000** (0 fabrications over 5 runs) — see [COPILOT.md](COPILOT.md) |

The first three run through the **same code paths as the product** (the detection
benchmark calls `scanner._service_scan`; the CVE benchmark calls the real
`vulndb.lookup_offline_cves`), so the numbers are ENUMGRID's own, not a
re-implementation's.

## 3. CVE-matching precision *and* recall (the highest-stakes claim)

Finding a CVE is easy; attaching the **right** CVE to the **right** version — and
*never a wrong one* — is where real scanners fail, and it is the crux of the "no
fake data" thesis. `cve_precision.py` runs a labelled corpus
(`evaluation/cve_corpus.json`, 33 cases) through the real offline matcher with
**closed-world** scoring: each banner pins the *exact* CVE set expected, so any
extra id is a false positive and any missing id a false negative. The corpus
deliberately includes the cases that break naïve matchers:

| Trap category | Example | Correct behaviour |
| --- | --- | --- |
| **Boundary** | `Apache httpd 2.4.49` vs `2.4.50` vs `2.4.51` | 2.4.49→CVE-2021-41773 only; 2.4.50→CVE-2021-42013 only; 2.4.51→none |
| **Wrong-product (substring)** | `lighttpd 2.4.49` | must **not** inherit Apache's CVE-2021-41773 — "httpd" is a substring of "lighttpd" |
| **Wrong-product (version collision)** | `OpenSSH 2.3.4` | 2.3.4 is vsftpd's backdoor version, but on OpenSSH it maps to the OpenSSH CVE, never vsftpd's |
| **Backport** | `Apache httpd 2.4.6 ((CentOS))` | the exact-match table does not treat a RHEL backport build as the vulnerable 2.4.49/2.4.50 |
| **Control** | `Redis 6.2.6`, `Apache httpd` (no version) | never guess a CVE for an untabled product or a version-less banner |

**Result: precision 1.00, recall 1.00, 0 false positives.** The Wilson 95 % CI
lower bound of 0.82 is reported honestly — it reflects that 17 positive matches is
a modest sample, not that any match was wrong. This runs offline and deterministic
in CI, and is gated: `cve_precision.py --min-precision 1.0 --min-recall 1.0` fails
the build on any regression.

> **A real bug this caught.** Building the corpus surfaced a genuine false
> positive: the matcher used naive substring keyword matching, so `"httpd"`
> matched inside `"lighttpd"` and a patched lighttpd was flagged with Apache's
> path-traversal CVE. The fix (whole-token, letter-boundary matching in
> `vulndb._kw_hit`) is locked in by a regression test. This is the value of a
> precision corpus: it turns "we think it's accurate" into "it is, and here is the
> bug we found proving the test works."

## 4. Detection accuracy, version strings, and confidence

`detection_benchmark.py` scores the on-demand service scan against a **pinned,
version-locked** testbed (`evaluation/docker-compose.yml`,
`evaluation/ground_truth.json`) of six deliberately diverse hosts — two web
servers (nginx / Apache), an SSH server on a non-standard port, a key-value store
(redis), a relational database (postgres), and a **redis on a non-standard port
(1999)** that proves service detection follows the *banner*, not the port number.

- **Version-string accuracy** is scored separately from the service name, because
  CVE matching hinges on `2.4.49` vs `2.4.50`, not on "it's Apache". A port whose
  version nmap cannot reliably fingerprint (e.g. auth-gated Postgres) carries no
  expected version and is simply not version-scored — we never penalise a claim we
  did not make.
- **Accuracy by confidence.** Every detection carries nmap's service-detection
  confidence (1–10, now propagated into the `Port` model), and the benchmark
  reports service/version accuracy split into **high** (conf ≥ 7, actively probed)
  and **low** (a port-table guess) bands. "High-confidence detections are more
  accurate than low-confidence guesses" is thereby a measured claim, not an
  assumption — and the UI can flag a low-confidence hit for verification.

### Why patched hosts' extra CVEs are *not* auto-scored as false positives

On a rolling image, a CVE reported beyond the planted set may be **genuine** (the
image really is affected by a later-disclosed bug). Scoring it as a false positive
would itself be dishonest. The detection benchmark therefore *surfaces* unexpected
CVEs for review but never counts them — the rigorous, zero-false-positive CVE
claim is delivered separately and deterministically by the offline precision
corpus (§3), where the ground truth is fully known.

## 5. Sources of non-determinism (and what is pinned)

| Non-deterministic | Pinned / deterministic |
| --- | --- |
| Which hosts are up at scan time (network churn) | Parsing a fixed nmap XML → host model (`test_golden.py`) |
| Probe timing, retransmits, race between ports | `report.build_pdf` is byte-identical for identical input (`SOURCE_DATE_EPOCH`) |
| A rolling image's full CVE set over time | The offline version→CVE table (`vulndb`) — exact, hand-checked |
| Live NVD/OSV/EPSS availability and ordering | The copilot's grounding guarantee (structural, not sampled) |

The `--repeat N` mode of the detection benchmark **quantifies** the first row:
it scans each host N times and reports run-to-run **port / service / CVE
stability** (Jaccard of the sets across runs, 1.00 = identical every run). A tool
that measures its own flake rate is more trustworthy than one that pretends a live
scan is repeatable.

## 6. Known false-positive modes (and their mitigations)

- **Backported distro builds.** The offline version-range table (e.g. OpenSSH
  8.5–9.7 → regreSSHion) matches on the *upstream* version, so an Ubuntu build
  that backported the fix without bumping the version looks vulnerable. This is
  **flagged, not hidden**: every offline/version match carries `confidence:
  "version"` and a "verify — distros may backport the fix" note, and the
  backport-aware **OSV** layer (`osv.py`, querying the distro ecosystem)
  suppresses exactly these when a credentialed package list is available.
- **Substring name collisions.** Fixed (§3) and regression-tested.
- **Version-less banners.** A banner with no parseable version returns **no** CVE
  — the matcher never guesses from the product name alone.

## 7. Known false-negative modes

- **Per-scan NVD time budget / rate limits.** Live NVD enrichment is capped so a
  scan never stalls; anything not fetched in budget is covered by the in-scan
  `vulners` script and filled into the cache on the next scan — a *latency* limit,
  not a silent drop.
- **Services nmap cannot fingerprint.** No version → not version-scored and no
  offline CVE match; the finding degrades to a service/port fact, honestly.
- **Curated-table coverage.** The offline table is deliberately small and
  conservative (the classics); the long tail is covered online by `vulners` + NVD.

## 8. Limitations & threats to validity

- The CVE precision corpus (33 cases) and the detection testbed (6 hosts) are
  **synthetic and bounded**; the 0.82 Wilson lower bound reflects the sample size.
  Broadening both — more device types, more adversarial banners, a wider corpus —
  is the natural next step and would tighten the intervals.
- Version-string accuracy depends on nmap's own fingerprint database; ENUMGRID
  measures *its handling* of what nmap reports, not nmap's fingerprints.
- Backport suppression is only exercised when a credentialed package list is
  available; anonymous scans keep the flagged, conservative version-match.
- Confidence banding uses a fixed threshold (conf ≥ 7); the split is a reporting
  convenience, not a claim about nmap's internal scoring.

## 9. Reproducing every number

```bash
# CVE matching — precision & recall (offline, deterministic, CI-gated)
python evaluation/cve_precision.py                              # the table
python evaluation/cve_precision.py --min-precision 1.0 --min-recall 1.0

# Detection accuracy + version strings + accuracy-by-confidence (testbed up)
cd evaluation && docker compose up -d
python detection_benchmark.py --md detection.md
python detection_benchmark.py --repeat 3        # run-to-run stability
docker compose down

# Discovery + copilot grounding
python evaluation/benchmark.py 172.28.0.0/24 --ground-truth <ips>   # see EVALUATION.md
python evaluation/copilot_eval.py --provider ollama --model llama3.2 --runs 5

# The scoring math behind all of the above (no Docker, no network):
python -m pytest evaluation/
```

Raw results live in [`../evaluation/results/`](../evaluation/results/README.md).
