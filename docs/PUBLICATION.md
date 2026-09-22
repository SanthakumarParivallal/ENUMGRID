# ENUMGRID — publication package (index)

One entry point to everything needed to submit, defend, or reproduce this work. It
is deliberately honest about what is finished and what still needs real-world
inputs that cannot be fabricated.

## Deliverables

| Artifact | Files | Notes |
| --- | --- | --- |
| **Paper** | [`PAPER.md`](PAPER.md) · [`ENUMGRID_Paper.docx`](ENUMGRID_Paper.docx) · [`ENUMGRID_Paper.pdf`](ENUMGRID_Paper.pdf) | Engineering + measurement paper; Word has title page, auto-TOC, embedded **redacted** figures + eval plots |
| **Defense deck** | *not currently checked in* | 16 slides, speaker notes, visually QA'd — the `.pptx`/`.pdf` were removed from `docs/`, so this index no longer links them |
| **Reproducibility map** | [`REPRODUCE.md`](REPRODUCE.md) | Every headline number → its command → its artifact |

## Supporting documents

| Topic | Doc |
| --- | --- |
| Contribution, positioning, threats to validity, ethics, roadmap | [`CONTRIBUTIONS.md`](CONTRIBUTIONS.md) |
| Accuracy methodology, every measured layer, the CPE-drift finding (§10) | [`ACCURACY.md`](ACCURACY.md) |
| Architecture | [`ARCHITECTURE.md`](ARCHITECTURE.md) |
| LLM copilot grounding methodology | [`COPILOT.md`](COPILOT.md) |
| STRIDE threat model | [`THREAT_MODEL.md`](THREAT_MODEL.md) |
| Figure manifest + redaction | [`screenshots/README.md`](screenshots/README.md) |

## The measured results (all from real runs)

Full table + methodology in [`ACCURACY.md`](ACCURACY.md); raw artifacts in
[`../evaluation/results/`](../evaluation/results/README.md).

| Claim | Result | Artifact |
| --- | --- | --- |
| Offline CVE precision/recall | 1.00 / 1.00, 0 FP (33 cases) | `cve_precision.json` |
| Live-NVD primary path | recall 8/8, scoping 7/7, 0 truncation | `nvd_live.json` |
| Detection (9-host testbed) | ports 1.00/1.00, service 0.89, version 0.83, planted-CVE 3/3 | `detection_172-28.json` |
| CVE baselines (two schools) | vulners 3/3·133 · EnumGrid 2/3·13 · Nuclei 0/3 | `cve_baselines_172-28.json` |
| Discovery, cross-env pool (n=2) | EnumGrid 0.99±0.02 vs nmap-sn 0.53±0.93 | `pooled_recall.json` |
| Scalability | 46.5 ms/addr + 9.1 s, R²=0.83 | `scalability_172-16-2.json` |
| Copilot grounding | 1.000 ± 0.000 (5 runs, 0 fabrications) | `llama3.2_x5.json` |

## Quality status

- **1,365 automated tests** — Python 1,151 (CLI 197 + backend 776 + evaluation 178) +
  frontend 214. All green.
- ruff clean; SAST (bandit) + dependency audit (pip-audit) clean; SBOM; digest-pinned
  non-root Docker image.
- All scoring math is pure + unit-tested → the published numbers re-run in CI with no
  Docker/network (`python -m pytest evaluation/`).

## What still needs the operator (cannot be fabricated)

Each is *scaffolded* so it is one input away — but the input is real-world and must not
be invented. See [`CONTRIBUTIONS.md`](CONTRIBUTIONS.md) §8.

| Gap | Turnkey entry point | What you must supply |
| --- | --- | --- |
| More distinct authorised networks (tighten the n=2 CI) | [`../evaluation/COLLECTING_NETWORKS.md`](../evaluation/COLLECTING_NETWORKS.md) | Real networks you are authorised to scan |
| Held-out CVE corpus (kill the fit-to-matcher objection) | [`../evaluation/nvd_corpus_heldout.json`](../evaluation/nvd_corpus_heldout.json) | A blind, independent sample |
| OpenVAS/Nessus baseline (broader precision picture) | `cve_baselines.py --tools openvas,nessus` | An exported scanner report |
| Analyst user study (the HCI contribution) | [`USER_STUDY_PROTOCOL.md`](USER_STUDY_PROTOCOL.md) | Real participants under ethics approval |

## Honesty statement

Every figure and number in this package is produced by a checked-in, reproducible
harness or captured from a real, authorised scan — never simulated or hand-tuned.
Where the tool or the evaluation has a limit or a failure mode (small n, author-curated
corpora, the CPE-dictionary drift on the live-NVD path), it is named in the paper rather
than hidden. That discipline is itself the contribution.
