# Evaluation harness

Reproducible accuracy measurement across three layers: host **discovery**,
service/CVE **detection**, and the AI **copilot's grounding**.

| File | Purpose |
|---|---|
| `benchmark.py` | Discovery: EnumGrid vs `nmap -sn` (+ arp-scan/netdiscover/masscan) — precision/recall/Jaccard + timing, mean ± 95 % CI |
| `detection_benchmark.py` | Detection: open ports, service names, and planted CVEs vs a pinned testbed's known-good answer |
| `cve_precision.py` | **Offline CVE-matching precision *and* recall** vs a labelled corpus — the "no wrong CVE" gate (no Docker, no network) |
| `cve_corpus.json` | Labelled `banner → exact CVE set` cases: boundary / wrong-product / backport / control traps |
| `copilot_eval.py` | Copilot grounding + coverage vs a fixed scan (see [`../docs/COPILOT.md`](../docs/COPILOT.md)) |
| `docker-compose.yml` | A deterministic, **version-pinned** 4-host testbed (known ground truth) |
| `ground_truth.json` | The testbed's exact open ports / services / planted CVEs |
| `test_*.py` | Unit tests for all the metric math (no Docker, no network — CI-gated) |

## Quick start

```bash
# --- Discovery ---
# Real network (authorized use only) — union of both tools is the ground-truth proxy:
python evaluation/benchmark.py 192.168.0.0/24 --json result.json

# Deterministic testbed — TRUE precision/recall:
cd evaluation && docker compose up -d
python benchmark.py 172.28.0.0/24 \
    --ground-truth 172.28.0.10,172.28.0.11,172.28.0.12,172.28.0.13

# --- Detection (ports / services / planted CVE) --- (testbed still up)
python detection_benchmark.py --md detection.md   # scores against ground_truth.json
docker compose down

# --- CVE-matching precision + recall (offline, no testbed needed) ---
python evaluation/cve_precision.py                              # print the table
python evaluation/cve_precision.py --min-precision 1.0 --min-recall 1.0   # CI gate
```

`cve_precision.py` closes the gap the detection benchmark leaves open. Detection
measures CVE **recall** (did we find the planted bug?); this measures
**precision** — does the matcher attach the *right* CVE to the *right* version
and *never a wrong one*? It runs a 33-case labelled corpus through the real
offline matcher (`backend/vulndb.lookup_offline_cves`) with **closed-world**
scoring (each banner pins the exact CVE set expected), so boundary edges
(`2.4.49` matches, `2.4.51` must not), wrong-product collisions (`lighttpd
2.4.49` must not inherit Apache's CVE; `2.3.4` on OpenSSH must not become
vsftpd's), and backport builds are all scored. Measured: **precision 1.00,
recall 1.00** (95 % Wilson CI [0.82, 1.00] — honest about a 17-positive sample),
0 false positives, fully deterministic and CI-gated.

The detection harness scans through the **same code path as the dashboard**
(`backend/scanner._service_scan` with `auto_cve`), so the numbers are the
product's own. Ground truth is fixed by the pinned images: ports and service
names are exact, and `172.28.0.11` deliberately runs Apache 2.4.49 so
**CVE-detection recall** can be measured against a documented, planted bug
(CVE-2021-41773/42013). CVEs reported beyond the planted set are surfaced as
*unexpected* for review — a rolling image's full CVE list isn't knowable a
priori, so the harness never dishonestly scores them as false positives.

See **[`../docs/EVALUATION.md`](../docs/EVALUATION.md)** for methodology, measured
results (EnumGrid ~11–12 vs `nmap -sn` 3 on a real `/24`, recall 1.00 vs 0.27),
and the honest caveats (unprivileged comparison; `sudo nmap -sn` uses ARP).
