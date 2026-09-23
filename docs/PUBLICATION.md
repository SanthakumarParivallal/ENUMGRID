# ENUMGRID publication package (index)

One entry point to everything needed to submit, defend, or reproduce this work. It
states plainly what is finished and what still needs real-world inputs that cannot be
fabricated.

## Deliverables

| Artifact | Files | Notes |
| --- | --- | --- |
| Paper (source of truth) | [`PAPER.md`](PAPER.md) | Engineering and measurement paper; every quantitative claim cites an `evaluation/results/*.json` |
| Paper (Word / PDF) | generated on demand, not checked in | The `.docx` and `.pdf` renderings were last built 2026-07-11 and had drifted from `PAPER.md`; they still quoted the 1,307-test figure against today's 1,501, so a stale binary could be submitted by mistake. Regenerate from the Markdown when you submit, as below |
| Defense deck | not currently checked in | 16 slides, speaker notes, visually QA'd. The `.pptx` and `.pdf` were removed from `docs/`, so this index no longer links them |
| Reproducibility map | [`REPRODUCE.md`](REPRODUCE.md) | Every headline number → its command → its artifact |

> **Regenerating the submission binaries.** `PAPER.md` is the only version-controlled
> copy, so the rendering is always current by construction:
>
> ```bash
> pandoc docs/PAPER.md -o ENUMGRID_Paper.docx --toc --resource-path=docs
> soffice --headless --convert-to pdf ENUMGRID_Paper.docx
> ```
>
> Build them outside `docs/`, or add them to `.gitignore`, so a rendering can never again
> drift from its source inside the repository. The previously checked-in copies stay reachable in the
> history preceding the commit that removed them, and the recipe above rebuilds them
> from the current `PAPER.md`.

## Supporting documents

| Topic | Doc |
| --- | --- |
| Contribution, positioning, threats to validity, ethics, roadmap | [`CONTRIBUTIONS.md`](CONTRIBUTIONS.md) |
| Accuracy methodology, every measured layer, the CPE-drift finding (§10) | [`ACCURACY.md`](ACCURACY.md) |
| Architecture | [`ARCHITECTURE.md`](ARCHITECTURE.md) |
| LLM copilot grounding methodology | [`COPILOT.md`](COPILOT.md) |
| STRIDE threat model | [`THREAT_MODEL.md`](THREAT_MODEL.md) |
| Figure manifest and redaction | [`screenshots/README.md`](screenshots/README.md) |

## The measured results (all from real runs)

Full table and methodology in [`ACCURACY.md`](ACCURACY.md); raw artifacts in
[`../evaluation/results/`](../evaluation/results/README.md).

| Claim | Result | Artifact |
| --- | --- | --- |
| Offline CVE precision/recall | 1.00 / 1.00, 0 FP (33 cases) | `cve_precision.json` |
| Live-NVD primary path | recall 8/8, scoping 7/7, 0 truncation | `nvd_live.json` |
| Detection (9-host testbed) | ports 1.00/1.00, service 0.89, version 0.83, planted-CVE 3/3 | `detection_172-28.json` |
| CVE baselines (two schools) | vulners 3/3·133 · EnumGrid 2/3·13 · Nuclei 0/3 | `cve_baselines_172-28.json` |
| Discovery, cross-env pool (n=3) | EnumGrid 0.97±0.04 vs nmap-sn 0.49±0.54 | `pooled_recall.json` |
| Scalability | 46.5 ms/addr + 9.1 s, R²=0.83 | `scalability_172-16-2.json` |
| Copilot grounding | 1.000 ± 0.000 (5 runs, 0 fabrications) | `llama3.2_x5.json` |

## Quality status

- 1,501 automated tests: Python 1,287 (CLI 315, backend 794, evaluation 178) plus
  frontend 214. All green.
- ruff clean; SAST (bandit) and dependency audit (pip-audit) clean; SBOM; digest-pinned
  non-root Docker image.
- All scoring math is pure and unit-tested, so the published numbers re-run in CI with no
  Docker and no network (`python -m pytest evaluation/`).

## What still needs the operator (cannot be fabricated)

Each one is scaffolded so that it is a single input away, and that input is real-world
and must not be invented. See [`CONTRIBUTIONS.md`](CONTRIBUTIONS.md) §8.

| Gap | Turnkey entry point | What you must supply |
| --- | --- | --- |
| More distinct authorised networks (tighten the n=3 CI) | [`../evaluation/COLLECTING_NETWORKS.md`](../evaluation/COLLECTING_NETWORKS.md) | Real networks you are authorised to scan |
| Held-out CVE corpus (kill the fit-to-matcher objection) | [`../evaluation/nvd_corpus_heldout.json`](../evaluation/nvd_corpus_heldout.json) | A blind, independent sample |
| OpenVAS/Nessus baseline (broader precision picture) | `cve_baselines.py --tools openvas,nessus` | An exported scanner report |
| Analyst user study (the HCI contribution) | [`USER_STUDY_PROTOCOL.md`](USER_STUDY_PROTOCOL.md) | Real participants under ethics approval |

## Honesty statement

Every figure and number in this package is produced by a checked-in, reproducible
harness or captured from a real, authorised scan, never simulated or hand-tuned. Where
the tool or the evaluation has a limit or a failure mode (small n, author-curated
corpora, the CPE-dictionary drift on the live-NVD path), it is named in the paper rather
than hidden.
