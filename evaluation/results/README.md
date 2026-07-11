# Evaluation — results

> **Where these numbers are used:** the write-up in [`../../docs/PAPER.md`](../../docs/PAPER.md)
> cites each artifact below; [`../../docs/REPRODUCE.md`](../../docs/REPRODUCE.md) maps every
> headline to its exact command. Methodology: [`../../docs/ACCURACY.md`](../../docs/ACCURACY.md).

## Offline CVE-matching precision / recall (`cve_precision.json`)

The highest-stakes accuracy artifact: does the matcher attach the *right* CVE to
the *right* version and **never a wrong one**? A 33-case labelled corpus
(`../cve_corpus.json`) run through the real offline matcher
(`backend/vulndb.lookup_offline_cves`) with closed-world scoring.

| Metric | Value | 95 % Wilson CI | Counts |
| --- | ---: | :---: | --- |
| **Precision** | **1.000** | [0.816, 1.000] | 17/17 predicted-positive |
| **Recall** | **1.000** | [0.816, 1.000] | 17/17 actual-positive |
| **F1** | **1.000** |  | 0 false positives, 0 false negatives |

Per-category (all 1.00): `exact` 16 · `boundary` 8 · `wrong-product` 4 ·
`backport` 1 · `control` 4. The corpus deliberately includes the traps that break
naive matchers — version-range boundaries (`2.4.49` matches, `2.4.51` must not),
substring collisions (`lighttpd 2.4.49` must not inherit Apache's CVE), magic
version collisions (`OpenSSH 2.3.4` must not become vsftpd's CVE), and a RHEL
backport build. Deterministic and CI-gated
(`cve_precision.py --min-precision 1.0 --min-recall 1.0`). Full methodology:
[`../../docs/ACCURACY.md`](../../docs/ACCURACY.md).

Reproduce:

```bash
python evaluation/cve_precision.py --json evaluation/results/cve_precision.json
```

## Live-NVD pipeline precision / recall (`nvd_live.json`)

The **primary** CVE path — version-scoped CPE query → `parse_nvd` → top-N by CVSS —
measured against the **real NVD API 2.0 feed** on 2026-07-11 (12 labelled CPEs,
`../nvd_corpus.json`).

| Metric | Value | 95 % Wilson CI | Counts |
| --- | ---: | :---: | --- |
| **Recall** (documented CVEs surfaced) | **1.000** | [0.676, 1.000] | 8/8 |
| **Version-scoping precision** | **1.000** | [0.646, 1.000] | 7/7 excluded, 0 violations |
| **Top-N truncation loss** | **0** | | no documented CVE dropped by the CVSS cap |

**Finding (surfaced, not hidden).** The first run scored recall **7/8**: the miss was
`vsftpd 2.3.4 → CVE-2011-2523`, which the harness attributed to *absence* (NVD
returned 0 rows), not truncation. NVD indexes it under vendor **`vsftpd_project`**
while nmap emits **`vsftpd`** — a CPE-dictionary drift. With the canonical CPE the
pipeline recalls it (**8/8**); the drift is retained as a documented construct-validity
limitation ([`../../docs/ACCURACY.md`](../../docs/ACCURACY.md) §10) and is covered in
production by the independent `vulners` + offline layers.

Reproduce (needs network; honours NVD's rate limit):

```bash
python evaluation/nvd_precision.py --live --json evaluation/results/nvd_live.json
```

## Live testbed — detection accuracy (`detection_172-28.json`)

Ran against the **live** 9-host docker testbed (`../docker-compose.yml`, brought up on
a colima VM) on 2026-07-11 through the product's own `scanner._service_scan` (profile
`vuln`):

| Metric | Result |
| --- | --- |
| **Open ports** | precision **1.00**, recall **1.00**, F1 **1.00** (0 FP, 0 missed) |
| **Service-name accuracy** | **0.89** (8/9; the mongo banner is the one low-confidence miss) |
| **Version-string accuracy** | **0.83** (5/6 versioned ports) |
| **Planted-CVE recall** | **1.00 (3/3)** — CVE-2021-41773 + CVE-2021-42013 on 2.4.49, CVE-2021-42013 on 2.4.50 |
| **Unexpected CVEs** | **56**, surfaced for review, **not** scored as FPs (a rolling image's full CVE set is unknowable a priori) |

## Live testbed — CVE-detection baselines (`cve_baselines_172-28.json`)

The *"compared to what?"* head-to-head — three detectors on the **same** planted hosts,
one from each detection school:

| Tool | School | Planted-CVE recall | Unexpected |
| --- | --- | ---: | ---: |
| **nmap-`vulners`** | version-match | **1.00 (3/3)** | **133** |
| **EnumGrid** | version-match (conservative) | **0.67 (2/3)** | **13** |
| **Nuclei** | active-PoC | **0.00 (0/3)** | **0** |

**The finding this baseline exists to show** — the two schools trade off exactly as
theory predicts, now demonstrated on real hosts:
- **Version-match** tools flag on the detected version. `nmap-vulners` maximises recall
  (3/3) but at **10× the noise** (133 unexpected vs EnumGrid's 13) — EnumGrid deliberately
  trades a little recall for far fewer false alarms.
- **Active-PoC** (`nuclei`) is **exploitability-gated**: its CVE templates did not fire
  (0/3) because the vanilla images expose the *version* but not the *exploitable config*
  (e.g. the CVE-2021-41773 path-traversal PoC needs a `cgi-bin`/alias the default image
  doesn't ship). High precision, config-dependent recall — the mirror image of version-match.
- EnumGrid's own **planted-CVE recall varied 2/3 ↔ 3/3** between this run and the detection
  run above — real live-scan nondeterminism on the 2.4.50 incomplete-fix twin, which is
  precisely why the project measures run-to-run **stability** (`--repeat`).

**Heavyweight scanners (OpenVAS/Nessus) — adapters ready, not yet run.** `cve_baselines.py`
now includes report-file adapters (`--tools openvas,nessus`): export a Greenbone (GVM XML)
or Nessus (`.nessus`) report, point `ENUMGRID_OPENVAS_REPORT` / `ENUMGRID_NESSUS_REPORT` at
it, and the harness parses the **real** report host-by-host and scores planted-CVE recall
with the same comparison. With no report supplied the tool is `unavailable` (never "found
nothing"). This closes the "beat/meet a mature vuln scanner" gap to an operator export + one
flag — no result is fabricated here.

## Cross-environment discovery pooling (`pooled_recall.json`)

`aggregate_runs.py` macro-averaging **two real environments** — the `172.16.2.0/24` home
LAN and the `172.28.0.0/24` testbed (each network = one sample):

| Tool | Recall (mean ± 95 % CI across envs) | `172.16.2.0/24` | `172.28.0.0/24` |
| --- | ---: | ---: | ---: |
| **EnumGrid** | **0.99 ± 0.02** | 0.98 | 1.00 |
| **nmap -sn** | **0.53 ± 0.93** | 0.06 | 1.00 |

EnumGrid is consistently high; `nmap -sn`'s enormous CI is honest — it is **environment
dependent**, crippled to 0.06 on the ICMP-filtered real LAN yet perfect on the clean
testbed. **n = 2** (one real LAN + one synthetic testbed) is small and reported as such;
more *distinct* authorised networks would tighten it. Plot: `../../docs/screenshots/pooled_recall.png`.

Reproduce (testbed up; scans run where container IPs are reachable):

```bash
docker compose -f evaluation/docker-compose.yml up -d
python evaluation/detection_benchmark.py --json evaluation/results/detection_172-28.json
python evaluation/cve_baselines.py       --json evaluation/results/cve_baselines_172-28.json
python evaluation/benchmark.py 172.28.0.0/24 --runs 3 --json evaluation/results/benchmark_172-28.json
python evaluation/aggregate_runs.py evaluation/results/benchmark_*.json --plot docs/screenshots/pooled_recall.png
docker compose -f evaluation/docker-compose.yml down
```

---

# Copilot evaluation — results

Real runs of `evaluation/copilot_eval.py` against the local Ollama backend.
Reproduce with:

```bash
python evaluation/copilot_eval.py --self-test                 # metric sanity (no model)
python evaluation/copilot_eval.py --provider ollama --model llama3.2 --json evaluation/results/llama3.2.json
python evaluation/copilot_eval.py --provider ollama --model qwen2.5  --json evaluation/results/qwen2.5.json
```

## Metric sanity (`--self-test`)

The scorer is validated against two built-in reference sets before any model is
trusted:

| Reference replies      | Coverage | Grounding | Verdict |
| ---------------------- | -------- | --------- | ------- |
| Grounded (ideal)       | 1.00     | 1.00      | PASS    |
| Hallucinated (adverse) | 0.00     | 0.00      | PASS    |

`metric sanity: PASS` — grounding collapses to 0 exactly when a reply cites
hosts/CVEs that are not in the scan context, so the score cannot be gamed by a
fluent-but-fabricated answer.

## Model-scaling comparison (Ollama · local · temperature 0.2)

Same 5-question fixture (`172.16.2.0/24` scan context), `propose_scan` tool
intent-gated, sampling temperature 0.2.

### The fix that mattered: put the real CVE ids in the context

The first runs exposed a grounding *gap in the prompt*, not just the model: the
context block summarised vulnerabilities by count and severity but never listed
the actual CVE identifiers. Asked to "name the CVEs," a model therefore had none
to cite — so a weak model **invented** one. The fix (`build_context_block`) feeds
the real CVE ids (with severity + host) into the context, and a deterministic
guard (`ungrounded_cves`) flags any id a model still emits that isn't in the scan.

Before/after on the same fixture:

| Model    | Params | Coverage | Grounding | Score | Hallucinated facts |
| -------- | ------ | -------- | --------- | ----- | ------------------ |
| llama3.2 | 3B     | 0.80     | 0.80 → **1.00** | 0.80 → **0.90** | 1 → **0** |
| qwen2.5  | 7B     | 0.60 → **1.00** | **1.00** | 0.80 → **1.00** | **0** |

**Finding.** Once the model is given the real identifiers, both models stop
fabricating entirely — grounding is **1.00** for both, and the 7B model reaches a
perfect 1.00 overall. The remaining spread is coverage (recall), not
truthfulness: the residual failure mode of a grounded model is *silence* on a
fact, never *invention* of one. For a security tool that is exactly the right
trade — a missed detail is recoverable; a fabricated CVE is not.

**Caveat.** Small local models show run-to-run coverage variance at temperature
0.2, so the coverage figures above are single-run snapshots. The grounding result
(0 fabricated facts) is stable because it is now enforced structurally — real ids
in, guard on the way out — and the metric-sanity check is fully deterministic.

### Headline with uncertainty (`--runs 5`, mean ± 95 % CI)

Repeating the evaluation five times removes the single-run caveat
(`llama3.2_x5.json`, from `python evaluation/copilot_eval.py --provider ollama
--model llama3.2 --runs 5`):

| Metric | Mean ± 95 % CI | Min / Max |
| --- | --- | --- |
| Grounding | **1.000 ± 0.000** | 1.00 / 1.00 |
| Coverage | 0.760 ± 0.078 | 0.60 / 0.80 |
| Score | 0.880 ± 0.039 | 0.80 / 0.90 |

**Grounding is perfectly stable at 1.00 across all five runs** — the model
fabricated nothing, five times out of five, exactly as the structural guarantee
predicts. The only variance is in coverage (recall), never truthfulness: the
residual failure mode of a grounded model is *silence* on a fact, never
*invention* of one.
