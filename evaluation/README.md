# Evaluation harness

Reproducible accuracy measurement across three layers: host discovery, service and
CVE detection, and the AI copilot's grounding.

| File | Purpose |
|---|---|
| `benchmark.py` | Discovery: EnumGrid against `nmap -sn`, plus arp-scan, netdiscover and masscan. Precision, recall, Jaccard and timing, as mean ± 95% CI |
| `aggregate_runs.py` | Cross-environment pooling: combines several `benchmark.py` result files, one per network, into per-tool recall as mean ± 95% CI across environments, plus a bar chart. This is the external-validity figure |
| `scalability_benchmark.py` | Scalability: discovery time and peak memory against address-space size over a widening CIDR sweep, with a least-squares fit (ms per address, R²), throughput, and a time-against-size plot |
| `detection_benchmark.py` | Detection: open ports, service names, and planted CVEs vs a pinned testbed's known-good answer |
| `cve_precision.py` | Offline CVE-matching precision and recall against a labelled corpus: the "no wrong CVE" gate, with no Docker and no network |
| `cve_corpus.json` | Labelled `banner → exact CVE set` cases: boundary, wrong-product, backport and control traps |
| `nvd_precision.py` | Live-NVD pipeline precision and recall on the primary CVE path (version-scoped CPE → `parse_nvd` → top-N): documented-CVE recall, version-scoping and truncation loss. Real `parse_nvd` on schema fixtures in CI; `--live` hits real NVD for the operator |
| `nvd_corpus.json` | Labelled `CPE → expect_present / expect_absent` cases: recall / version-scope / wrong-product |
| `cve_baselines.py` | CVE detection against real scanners: planted-CVE recall and agreement for EnumGrid, nmap-`vulners` and Nuclei on the same testbed, answering "compared to what?" |
| `copilot_eval.py` | Copilot grounding and coverage against a fixed scan (see [`../docs/COPILOT.md`](../docs/COPILOT.md)) |
| `docker-compose.yml` | A deterministic, version-pinned 9-host testbed with known ground truth |
| `ground_truth.json` | The testbed's exact open ports / services / planted CVEs |
| `test_*.py` | Unit tests for all the metric math, CI-gated, with no Docker and no network |

## Quick start

```bash
# --- Discovery ---
# Real network (authorized use only). The union of both tools is the ground-truth proxy:
python evaluation/benchmark.py 192.168.0.0/24 --json result.json

# --- Generalisation: pool several networks into one figure (authorized targets only) ---
python evaluation/benchmark.py 192.168.0.0/24 --runs 5 --json home.json
python evaluation/benchmark.py 10.0.5.0/24    --runs 5 --json office.json
python evaluation/aggregate_runs.py home.json office.json --md pooled.md --plot pooled.png

# --- Scalability: discovery time against network size (a widening sweep you are authorized for) ---
python evaluation/scalability_benchmark.py 10.0.0.0/26 10.0.0.0/25 10.0.0.0/24 10.0.0.0/23 \
    --repeat 3 --md scaling.md --plot scaling.png

# Deterministic testbed: TRUE precision and recall:
cd evaluation && docker compose up -d
python benchmark.py 172.28.0.0/24 \
    --ground-truth 172.28.0.10,172.28.0.11,172.28.0.12,172.28.0.13,172.28.0.14,172.28.0.15,172.28.0.16,172.28.0.17,172.28.0.18

# --- Detection (ports / services / planted CVE) --- (testbed still up)
python detection_benchmark.py --md detection.md   # scores against ground_truth.json

# --- CVE detection vs real scanners (nmap-vulners, Nuclei) --- (testbed still up)
python cve_baselines.py --md baselines.md         # head-to-head planted-CVE recall
docker compose down

# --- CVE-matching precision + recall (offline, no testbed needed) ---
python evaluation/cve_precision.py                              # print the table
python evaluation/cve_precision.py --min-precision 1.0 --min-recall 1.0   # CI gate

# --- Live-NVD pipeline precision + recall (the PRIMARY CVE path) ---
python evaluation/nvd_precision.py                 # scorer self-check on schema fixtures
python evaluation/nvd_precision.py --live --md nvd.md   # real NVD feed (operator, network)
ENUMGRID_NVD_API_KEY=… python evaluation/nvd_precision.py --live   # higher rate limit
```

`cve_baselines.py` answers the reviewer's *"compared to what?"*: it runs EnumGrid,
**nmap-`vulners`** (version-match, same school as EnumGrid) and **Nuclei**
(active-PoC) against the *same* pinned hosts and reports each tool's planted-CVE
recall, its unexpected CVEs, and pairwise agreement. A scanner that is not installed
is reported as unavailable, never scored as having found nothing. The parsers and
comparison math are pure and CI-tested, and the live runner is operator-run.

`cve_precision.py` closes the gap the detection benchmark leaves open. Detection
measures CVE recall, asking whether we found the planted bug. This measures
precision: does the matcher attach the right CVE to the right version, and never a
wrong one? It runs a 33-case labelled corpus through the real offline matcher
(`backend/vulndb.lookup_offline_cves`) with closed-world scoring, where each banner
pins the exact CVE set expected, so boundary edges (`2.4.49` matches, `2.4.51` must
not), wrong-product collisions (`lighttpd 2.4.49` must not inherit Apache's CVE, and
`2.3.4` on OpenSSH must not become vsftpd's), and backport builds are all scored.
Measured: precision 1.00, recall 1.00, with a 95% Wilson CI of [0.82, 1.00] that
reflects a 17-positive sample, 0 false positives, fully deterministic and CI-gated.

`nvd_precision.py` measures the path `cve_precision.py` cannot: the live NVD lookup
(`backend/cve.py`) that is EnumGrid's primary CVE source, rather than the curated
offline table. It scores three things per version-scoped CPE. Documented-CVE recall
is a lower bound, because NVD returns more and those extras are not penalised.
Version-scoping precision requires that a patched build such as Apache `2.4.51`, or a
different product's CPE, comes back clean. Top-N truncation loss counts a documented
CVE dropped by the CVSS-ranked `MAX_PER_SERVICE` cap. The scorer and the real
`parse_nvd` run over hand-authored NVD-2.0 schema fixtures in CI, deterministically
and without a network, which proves the pipeline is correct without being the
published figure. `--live` queries the authoritative feed, honouring NVD's rate limit,
for the real number. A CPE that fails to fetch is reported as an error, and any corpus
label the live feed contradicts is a finding to investigate rather than something to
fabricate away.

The detection harness scans through the same code path as the dashboard
(`backend/scanner._service_scan` with `auto_cve`), so the numbers are the product's
own. Ground truth is fixed by the pinned images: ports and service names are exact,
and two hosts deliberately run known-vulnerable Apache builds, `172.28.0.11`
(2.4.49, giving CVE-2021-41773 and CVE-2021-42013) and `172.28.0.16` (2.4.50, giving
CVE-2021-42013, the incomplete-fix twin). CVE-detection recall is therefore measured
against documented, planted bugs on independent hosts. CVEs reported beyond the
planted set are surfaced as unexpected for review, because a rolling image's full CVE
list is not knowable a priori, so the harness never scores them as false positives.
Hosts `172.28.0.17` and `.18` (MySQL, MongoDB) add service diversity, and are
service-scored until a first run pins their exact banners; see the compose file's
reconciliation note.

See [`../docs/EVALUATION.md`](../docs/EVALUATION.md) for the methodology and measured
results (EnumGrid 11 against `nmap -sn` 3 on a real home `/24`, recall 1.00 against
0.27; and on a busy `/24`, 0.98 ± 0.04 against 0.06), and
[`../docs/CONTRIBUTIONS.md`](../docs/CONTRIBUTIONS.md) for the positioning, the
threats to validity, and what the evaluation does and does not support.
