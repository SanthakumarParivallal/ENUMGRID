# Evaluation harness

Reproducible accuracy + speed comparison of **PurpleRecon** vs **`nmap -sn`**.

| File | Purpose |
|---|---|
| `benchmark.py` | Runs both tools on the same target, computes precision/recall/Jaccard + timing |
| `docker-compose.yml` | A deterministic 4-host testbed (known ground truth) |
| `test_benchmark.py` | Unit tests for the metric math (no network) |

## Quick start

```bash
# Real network (authorized use only) — union of both tools is the ground-truth proxy:
python evaluation/benchmark.py 192.168.0.0/24 --json result.json

# Deterministic testbed — TRUE precision/recall:
cd evaluation && docker compose up -d
python benchmark.py 172.28.0.0/24 \
    --ground-truth 172.28.0.10,172.28.0.11,172.28.0.12,172.28.0.13
docker compose down
```

See **[`../docs/EVALUATION.md`](../docs/EVALUATION.md)** for methodology, measured
results (PurpleRecon ~11–12 vs `nmap -sn` 3 on a real `/24`, recall 1.00 vs 0.27),
and the honest caveats (unprivileged comparison; `sudo nmap -sn` uses ARP).
