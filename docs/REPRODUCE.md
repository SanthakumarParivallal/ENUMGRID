# Reproduce every headline number (one page)

Each row maps a claim in [`PAPER.md`](PAPER.md) / [`ACCURACY.md`](ACCURACY.md) to the
exact command that produces it and the artifact it lands in. All scoring math is
pure and unit-tested, so the *numbers* re-run in CI with **no Docker and no
network**; the **live** runs (marked ⚡) need the operator's environment and are
authoritative. Nothing here uses mock data.

Use `.venv/bin/python` (or `python -m …`) — the repo venv's console scripts have
stale shebangs after a folder rename.

## The measured headlines

| Claim (paper §) | Value | Command | Artifact |
|---|---|---|---|
| Offline CVE precision/recall (§6.4) | P 1.00 / R 1.00, 0 FP (33 cases) | `python evaluation/cve_precision.py --json evaluation/results/cve_precision.json` | `cve_precision.json` |
| Live-NVD primary path ⚡ (§6.5) | recall 1.00 (8/8), scoping 1.00 (7/7), 0 trunc | `python evaluation/nvd_precision.py --live --json evaluation/results/nvd_live.json` | `nvd_live.json` |
| Detection accuracy ⚡ (§6.3) | ports 1.00/1.00, service 0.89, version 0.83, CVE 3/3 | `python evaluation/detection_benchmark.py --json evaluation/results/detection_172-28.json` | `detection_172-28.json` |
| CVE baselines, 2 schools ⚡ (§6.6) | vulners 3/3·133 · EnumGrid 2/3·13 · Nuclei 0/3 | `python evaluation/cve_baselines.py --json evaluation/results/cve_baselines_172-28.json` | `cve_baselines_172-28.json` |
| Discovery vs `nmap -sn` ⚡ (§6.2) | EnumGrid 0.98±0.04 vs 0.06 | `python evaluation/benchmark.py 172.16.2.0/24 --runs 3 --json evaluation/results/benchmark_172-16-2.json` | `benchmark_172-16-2.json` |
| Cross-env discovery pool (§6.2) | EnumGrid 0.99±0.02 vs `nmap -sn` 0.53±0.93 (n=2) | `python evaluation/aggregate_runs.py evaluation/results/benchmark_*.json --json evaluation/results/pooled_recall.json --plot docs/screenshots/pooled_recall.png` | `pooled_recall.json` |
| Scalability ⚡ (§6.7) | 46.5 ms/addr + 9.1 s, R²=0.83 | `python evaluation/scalability_benchmark.py 172.16.2.0/28 …/24 --repeat 2 --json evaluation/results/scalability_172-16-2.json` | `scalability_172-16-2.json` |
| Copilot grounding ⚡ (§6.8) | grounding 1.000±0.000 (5 runs) | `python evaluation/copilot_eval.py --provider ollama --model llama3.2 --runs 5 --json evaluation/results/llama3.2_x5.json` | `llama3.2_x5.json` |

## Testbed lifecycle (for the ⚡ testbed rows)

```bash
docker compose -f evaluation/docker-compose.yml up -d     # 9-host pinned testbed
#   … run detection_benchmark.py / cve_baselines.py / benchmark.py 172.28.0.0/24 …
docker compose -f evaluation/docker-compose.yml down
```
No Docker Desktop? `brew install colima docker docker-compose nuclei && colima start`,
then run the scans **inside** the VM (`colima ssh --`) where the container IPs are
routable. Tear down with `colima stop`.

## Verify the scoring math + figures (no Docker, no network)

```bash
python -m pytest evaluation/                     # 177 tests — all harness scoring
python docs/screenshots/redact.py --check        # figure redaction regions in bounds
```

## Turnkey scaffolding (operator-supplied inputs, no fake data)

| Gap | How to close it | Entry point |
|---|---|---|
| More real networks | one runbook per authorised `/24` → pool | [`evaluation/COLLECTING_NETWORKS.md`](../evaluation/COLLECTING_NETWORKS.md) |
| Held-out CVE corpus | blind-sample, freeze, then `--corpus` | [`evaluation/nvd_corpus_heldout.json`](../evaluation/nvd_corpus_heldout.json) |
| OpenVAS/Nessus baseline | export a report, set env var, `--tools openvas,nessus` | `evaluation/cve_baselines.py` |
| Analyst user study | run the pre-registered protocol under ethics approval | [`USER_STUDY_PROTOCOL.md`](USER_STUDY_PROTOCOL.md) |
