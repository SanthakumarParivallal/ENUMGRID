# Evaluation harness

Reproducible accuracy measurement across three layers: host **discovery**,
service/CVE **detection**, and the AI **copilot's grounding**.

| File | Purpose |
|---|---|
| `benchmark.py` | Discovery: EnumGrid vs `nmap -sn` (+ arp-scan/netdiscover/masscan) — precision/recall/Jaccard + timing, mean ± 95 % CI |
| `detection_benchmark.py` | Detection: open ports, service names, and planted CVEs vs a pinned testbed's known-good answer |
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
```

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
