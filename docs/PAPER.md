# ENUMGRID: An Honesty-Disciplined, Unprivileged-First Network Enumeration Platform with a Grounded LLM Triage Copilot

**Draft — engineering + measurement paper / dissertation core.** Every
quantitative claim in this paper is produced by a checked-in, reproducible
harness under [`evaluation/`](../evaluation/) and cites the exact artifact in
[`evaluation/results/`](../evaluation/results/README.md); the reproduce commands
are in [Appendix B](#appendix-b--reproduce-every-number) and
[`docs/REPRODUCE.md`](REPRODUCE.md). The paper is written to be defensible under
examination: it deliberately **under**-claims, carries confidence intervals on
every headline, and names its own threats before a reviewer can.

---

## Abstract

Network enumeration tools face a credibility problem: they blend host discovery,
service detection, and CVE correlation into a single verdict and hide the
uncertainty in each layer, so a version-string guess and a confirmed exploit look
alike. ENUMGRID is a two-tier (single-file CLI + FastAPI/React) purple-team
enumeration platform built around a different discipline — **no fabrication as a
first-class, measurable property**. Findings are confidence-banded, unresolved
fields are labelled `Unknown` rather than guessed, the data path is never
simulated, and both the deterministic CVE matcher *and* the LLM triage copilot are
measured for false-positive/hallucination behaviour, not only recall. We make
three claims and evaluate each: (1) **honesty-as-a-property** — the offline CVE
matcher scores precision 1.00 / recall 1.00 (0 false positives) on a 33-case
adversarial corpus, and the copilot fabricates 0 CVEs across five runs (grounding
1.000 ± 0.000); (2) **unprivileged fidelity** — a four-signal (TTL + OUI + hostname
+ mDNS) discovery/OS fusion recalls 0.99 ± 0.02 of hosts across two environments
versus 0.53 ± 0.93 for an unprivileged `nmap -sn`, all without root; (3) a
**grounded triage copilot** with structural hallucination guards. We further
measure the primary live-NVD CVE path (recall 1.00, 8/8; version-scoping precision
1.00, 7/7) and, crucially, report where it *fails* — a CPE-dictionary drift
between nmap and NVD that the harness surfaced rather than hid. We position
ENUMGRID honestly: it is an integration + measurement contribution, not a new
algorithm, and its evaluation is deliberately bounded (few environments, small
corpora) with every limit stated. The contribution is the discipline and its
measurement, reproducible end-to-end.

---

## 1. Introduction

### 1.1 Motivation

A practitioner scanning a network wants three things at once: *what is here*
(discovery), *what is it running* (service/version detection), and *what is wrong
with it* (vulnerability correlation). Existing tools each do a slice well — `nmap`
for services, Fing for inventory, Nessus/OpenVAS for deep vuln assessment, Nuclei
for active proof-of-concept confirmation — but the practitioner still stitches them
together by hand, and the stitched result tends to launder uncertainty: a CVE
inferred from a banner version is presented with the same visual weight as one
confirmed by a probe. On a back-ported distro build, that laundering produces a
confident false positive. In an LLM-assisted workflow it gets worse: a fluent
model will *invent* a plausible CVE id to answer "what's exploitable here?"

ENUMGRID is built on the premise that for a security tool, **an invented finding
is categorically worse than a missing one** — a missed detail is recoverable, a
fabricated CVE that sends an analyst down a wrong path is not — and that a scanner
should therefore *quantify and bound its own over-claiming* as a headline
property, not bury it.

### 1.2 The gap

Most scanners report recall-like coverage ("N vulnerabilities found") and are
silent on their false-positive and — in the LLM era — hallucination behaviour.
Where precision is discussed it is rarely *measured* against an adversarial corpus
with closed-world scoring, and the *primary* live path (a CPE→NVD query, not an
offline table) is almost never precision/recall-evaluated at all. ENUMGRID treats
those omissions as the contribution surface.

### 1.3 Contributions

1. A **two-tier enumeration platform** ([§3](#3-system-design)) that runs the same
   scan engine unprivileged-first, from a single-file CLI and a FastAPI/React
   dashboard, with runtime privilege auto-adaptation.
2. An **honesty discipline** ([§4](#4-the-honesty-discipline)) — confidence
   banding, `Unknown` labelling, a never-simulated data path, and provenance
   manifests — operationalised so it can be *measured*, not merely asserted.
3. A **measurement suite** ([§6](#6-evaluation)) that scores each layer with
   closed-world precision/recall, Wilson confidence intervals, cross-environment
   macro-averaging, and multi-run CIs for the nondeterministic LLM — all through
   the *same code paths as the product*, all reproducible in CI.
4. Two findings that only an honest harness surfaces: the **CPE-dictionary drift**
   that breaks a live-NVD query for `vsftpd` ([§6.5](#65-cve-matching--the-primary-live-nvd-path)),
   and a real **substring false positive** (`httpd` ⊂ `lighttpd`) that the
   precision corpus caught and locked out with a regression test
   ([§6.4](#64-cve-matching--offline-precision-corpus)).

### 1.4 Scope and honest positioning

This is an **engineering + measurement** paper. The individual techniques
(ping/ARP/TCP discovery, `nmap -sV`, CPE→NVD lookup, KEV/EPSS prioritisation, LLM
summarisation) are established; the contribution is their integration and the
discipline imposed on the result. On novelty alone this is a strong **Master's
dissertation** and a credible **tool/demo or workshop paper**, not a top-tier
research-venue submission. We say so plainly, and the evaluation is scoped to what
it can honestly support (see [§7](#7-threats-to-validity)).

---

## 2. Background and Related Work

### 2.1 The two schools of vulnerability detection

CVE detection tools fall into two schools, and the distinction drives our
evaluation design:

- **Version-match** (nmap's `vulners` NSE, and ENUMGRID's CPE→NVD path): map a
  detected product/version to its known CVEs. High recall, but a back-ported fix
  makes it over-report — a candidate false positive.
- **Active-PoC** (Nuclei): send a probe that *confirms* the bug. High precision,
  but only covers vulnerabilities someone wrote a template for, and only fires when
  the exploitable configuration — not merely the version — is present.

Neither dominates; they trade recall for precision in opposite directions. A fair
evaluation must show *both* alongside the tool under test, which is exactly what
[§6.6](#66-cve-detection-versus-baselines) does on real hosts.

### 2.2 Positioning

| Tool / class | What it does | What ENUMGRID adds relative to it |
|---|---|---|
| **Fing / Angry IP** (asset discovery) | Fast device inventory | Service/version depth, live CVE correlation, honesty labelling on top of inventory |
| **nmap / Zenmap** (port/service scanner) | Authoritative service/version/OS, NSE | Whole-network orchestration, unprivileged auto-adaptation, CVE/KEV/EPSS enrichment around the same engine it invokes |
| **masscan / ZMap** (high-rate scanners) | Breadth at very high packet rates | Not a speed competitor; targets *authorised, local* estates with depth + honesty |
| **OpenVAS / Nessus** (vuln scanners) | Deep authenticated + network vuln assessment | Lighter-weight, unprivileged-first, confidence-transparent; **these remain the stronger vuln scanners** — ENUMGRID is measured *against* them, not claimed to replace them |
| **Nuclei** (active-PoC) | Confirms vulns by probe | Used as an evaluation **baseline** ([§6.6](#66-cve-detection-versus-baselines)) |
| **nmap `vulners`** (version-match) | CVE ids from CPE/version | Same school as ENUMGRID's path; used as a second **baseline** |

ENUMGRID sits between asset-discovery tools (which don't assess vulnerability) and
vulnerability scanners (which don't give a fast, honest, unprivileged inventory).
Its value is the *integration and the honesty discipline*, not out-scanning Nessus
or out-running masscan.

---

## 3. System Design

### 3.1 Two-tier architecture

ENUMGRID ships as (a) a single-file CLI (`purple_recon.py`) for scriptable,
terminal-first use, and (b) a FastAPI backend (~30 modules) driving a React/Vite
dashboard for interactive triage. Both tiers share the same core: a
`ScopeValidator` (authorisation gate), the scan engine, the CVE-correlation
pipeline, and the report/provenance layer. A scan proceeds in two phases —
**Phase 1** multi-method host discovery (ICMP/ARP/TCP), then **Phase 2** `nmap`
service/version enumeration — streamed to the UI over SSE
([Fig. 3](#appendix-a--figure-manifest-redacted)).

### 3.2 Four-signal unprivileged discovery and OS fusion

Without root, ICMP echo and raw-socket OS fingerprinting are unavailable, so a
naive unprivileged scan collapses to a weak TCP-connect ping sweep (the failure
mode we quantify against `nmap -sn` in [§6.2](#62-host-discovery)). ENUMGRID
recovers fidelity by **fusing four independently-available signals**: the ICMP/TCP
reply **TTL** (OS family hint), the IEEE **OUI** from the ARP/neighbour table
(vendor), reverse-DNS / mDNS **hostname**, and the mDNS `model=` record. The fused
inference drives the device-type and OS columns
([Fig. 4](#appendix-a--figure-manifest-redacted)) and degrades to `Unknown` — never
a guess — when the signals disagree or are absent.

### 3.3 Privilege auto-adaptation

Rather than fail or demand root, ENUMGRID rewrites root-only `nmap` flags (`-sS`,
`-sU`, `-O`) to their safe unprivileged equivalents and annotates the residual gap.
When the operator chooses to elevate, the dashboard collects a sudo password that
is validated against `sudo` and **held only in the backend's memory** for the
session — never written to disk, logged, or returned
([Fig. 2](#appendix-a--figure-manifest-redacted)). Elevation is gated to the local
operator (or an admin token when RBAC is enabled).

---

## 4. The Honesty Discipline

The project's thesis is that **no-fabrication can be a first-class, measurable
property** of a scanner. Four mechanisms operationalise it:

1. **Confidence banding.** Every finding carries a band: `confirmed` (actively
   probed, nmap confidence ≥ 7) vs `version` (inferred from a banner/version). The
   UI renders them distinctly and the benchmark scores accuracy *per band*
   ([§6.3](#63-service-port-and-version-detection)), so "high-confidence
   detections are more accurate than low-confidence guesses" is a measured claim.
2. **`Unknown` over guessing.** An unresolved OS, vendor, or version is labelled
   `Unknown`; the matcher never emits a CVE for a version-less banner or an untabled
   product.
3. **Never-simulated data.** There is no mock/demo mode in the evidence path; if a
   scan fails it says so rather than fabricating hosts. (The figures in this paper
   are real runs — [Appendix A](#appendix-a--figure-manifest-redacted).)
4. **Provenance.** Each scan carries a provenance manifest; golden-file tests fix
   the parser→model→report pipeline byte-for-byte
   ([§5](#5-implementation)).

The same discipline extends to the LLM copilot: the context block feeds the model
the *real* CVE identifiers from the scan, and a deterministic guard flags any id
the model emits that is not in the scan — measured in [§6.8](#68-llm-triage-copilot).

---

## 5. Implementation

The backend is Python/FastAPI (~30 modules: scanner, CVE correlation across
NVD/`vulners`/OSV, KEV/EPSS triage, report/PDF, auth with per-IP throttling,
structured logging). The frontend is React/Vite/TypeScript. Engineering rigour is
part of the credibility argument, not the research claim: the repository carries
**1,307 automated tests** (Python 1,101 — CLI 197 + backend 726 + evaluation 178;
frontend 206), CI-gated line-coverage floors (100% on load-bearing modules), clean
SAST (`bandit`) and dependency audit (`pip-audit`), an SBOM, and a digest-pinned
non-root Docker image. Critically, the evaluation harnesses call the **same code
paths as the product** (the detection benchmark calls `scanner._service_scan`; the
offline CVE benchmark calls `vulndb.lookup_offline_cves`; the live-NVD benchmark
calls `cve.parse_nvd`), so the measured numbers are ENUMGRID's own, not a
re-implementation's.

---

## 6. Evaluation

### 6.1 Methodology

- **Ground truth.** On the pinned docker testbed
  ([`evaluation/docker-compose.yml`](../evaluation/docker-compose.yml),
  [`ground_truth.json`](../evaluation/ground_truth.json)) the expected
  ports/services/versions/planted-CVEs are known exactly, enabling true
  precision/recall. Off-testbed (real LANs) we use the **union of tools** as a
  ground-truth proxy — a host no tool sees is invisible to the metric, so
  off-testbed recall is an **upper bound**, stated as such.
- **Closed-world scoring.** For the offline CVE corpus, each banner pins the *exact*
  CVE set expected: any extra id is a false positive, any missing id a false
  negative.
- **Uncertainty.** Binomial proportions carry **Wilson 95% CIs** (correct at the
  0/1 boundary); cross-environment results are **macro-averaged** (each network =
  one sample) with a 95% CI *across* environments; the nondeterministic LLM is run
  multiple times with mean ± CI.
- **Two layers per harness.** All scoring math is pure and unit-tested (runs in CI
  with no Docker/network); the live runners are operator-run. A missing baseline is
  reported `unavailable`, never "found nothing".

The environments are: a real home `/24` (`172.16.2.0/24`, unprivileged) and the
9-host synthetic testbed (`172.28.0.0/24`, brought up on a colima VM).

### 6.2 Host discovery

Three runs on the real `172.16.2.0/24` LAN, unprivileged
([`benchmark_172-16-2.json`](../evaluation/results/benchmark_172-16-2.json)):

| Tool | Recall (mean ± 95% CI) | Precision | Hosts found (of 18 union) | Time |
|---|---:|---:|---:|---:|
| **EnumGrid** | **0.98 ± 0.04** | 1.00 | 17.7 | 22.7 s |
| `nmap -sn` (unpriv.) | 0.06 ± 0.00 | 1.00 | 1.0 | 51.2 s |

An unprivileged `nmap -sn` sees **one** host on this ICMP-filtered consumer LAN;
ENUMGRID's four-signal discovery sees ~18×. Pooling this LAN with the testbed
([`pooled_recall.json`](../evaluation/results/pooled_recall.json), n = 2 envs):

| Tool | Recall (mean ± 95% CI across envs) | `172.16.2.0/24` | `172.28.0.0/24` |
|---|---:|---:|---:|
| **EnumGrid** | **0.99 ± 0.02** | 0.98 | 1.00 |
| `nmap -sn` | **0.53 ± 0.93** | 0.06 | 1.00 |

The honest headline is **`nmap -sn`'s enormous CI**: it is *environment dependent*,
crippled on the filtered LAN yet perfect on the clean testbed, whereas EnumGrid is
consistently high. **n = 2 (one real LAN + one synthetic testbed) is small and
reported as such** — [`COLLECTING_NETWORKS.md`](../evaluation/COLLECTING_NETWORKS.md)
is the turnkey runbook to widen it with more authorised networks.

### 6.3 Service, port, and version detection

Against the 9-host testbed through `scanner._service_scan`
([`detection_172-28.json`](../evaluation/results/detection_172-28.json)):

| Metric | Result |
|---|---|
| **Open ports** | precision **1.00**, recall **1.00**, F1 **1.00** (9 TP, 0 FP, 0 FN) |
| **Service-name accuracy** | **0.89** (8/9; the mongo banner is the one low-confidence miss) |
| **Version-string accuracy** | **0.83** (5/6 versioned ports) |
| **Planted-CVE recall** | **1.00 (3/3)** |
| **Unexpected CVEs** | **56**, surfaced for review, **not** scored as FPs (a rolling image's full CVE set is unknowable a priori) |

Split by confidence band: **high** (conf ≥ 7, n = 8) — service accuracy **1.00**,
version **0.83**; **low** (n = 1) — service **0.00**. The single low-confidence
detection is the single service miss: the banding *predicts* the error, which is
the point of measuring it.

### 6.4 CVE matching — offline precision corpus

The highest-stakes claim — attach the *right* CVE to the *right* version, and
*never a wrong one*. A 33-case adversarial corpus
([`cve_corpus.json`](../evaluation/cve_corpus.json)) run through the real offline
matcher with closed-world scoring
([`cve_precision.json`](../evaluation/results/cve_precision.json)):

| Metric | Value | 95% Wilson CI |
|---|---:|:---:|
| **Precision** | **1.000** | [0.816, 1.000] |
| **Recall** | **1.000** | [0.816, 1.000] |
| **F1** | **1.000** | — |

0 false positives, 0 false negatives, across categories `exact` (16), `boundary`
(8), `wrong-product` (4), `backport` (1), `control` (4). The corpus embeds the
traps that break naive matchers: version-range boundaries (2.4.49 matches, 2.4.51
must not), substring collisions, magic-version collisions, and a RHEL backport.

> **A real bug this caught.** Building the corpus surfaced a genuine false positive:
> the matcher's substring keyword match let `"httpd"` match inside `"lighttpd"`, so
> a patched lighttpd was flagged with Apache's path-traversal CVE. The fix
> (whole-token matching in `vulndb._kw_hit`) is locked in by a regression test.

The 0.816 Wilson lower bound is reported honestly: it reflects that 17 positive
matches is a modest sample, not that any match was wrong. This runs offline and
deterministic in CI, gated at `--min-precision 1.0 --min-recall 1.0`.

### 6.5 CVE matching — the primary live-NVD path

The offline corpus tests the *fallback*. The **primary** path is a version-scoped
CPE query to the live NVD API → `parse_nvd` → top-N by CVSS. `nvd_precision.py`
measures it against the real feed on a 12-case labelled corpus
([`nvd_live.json`](../evaluation/results/nvd_live.json)):

| Metric | Value | 95% Wilson CI | Counts |
|---|---:|:---:|---|
| **Recall** (documented CVEs surfaced) | **1.00** | [0.68, 1.00] | 8/8 |
| **Version-scoping precision** | **1.00** | [0.65, 1.00] | 7/7 excluded, 0 violations |
| **Top-N truncation loss** | **0** | | none dropped by the CVSS cap |

> **Finding — surfaced, not hidden.** The first authoritative run scored recall
> **7/8**. The harness attributed the miss to *absence* (NVD returned 0 rows), not
> truncation. Root cause: NVD indexes the vsftpd 2.3.4 backdoor (CVE-2011-2523)
> under vendor **`vsftpd_project`**, while nmap's fingerprint emits **`vsftpd`** — a
> CPE-dictionary drift. A version-scoped query built from nmap's CPE therefore
> matches nothing. This is a **real construct-validity limitation of the live-NVD
> layer in isolation**, not a defect to bury: it is exactly why ENUMGRID does *not*
> rely on live-NVD alone — the in-scan `vulners` NSE and the offline table both
> recall CVE-2011-2523 independently. With the canonical CPE the live pipeline
> recalls it (8/8); the drift is retained as a documented threat
> ([ACCURACY §10](ACCURACY.md)).

To remove the author-curation ("fit-to-matcher") risk on these numbers,
[`nvd_corpus_heldout.json`](../evaluation/nvd_corpus_heldout.json) is a frozen,
empty held-out template carrying a blind-sampling protocol; the same harness scores
it unchanged (`--corpus`). We expect held-out recall to be *lower* than the curated
1.00 — and report it as-is when run.

### 6.6 CVE detection versus baselines

The "compared to what?" question, three detectors on the same planted hosts, one
from each school ([`cve_baselines_172-28.json`](../evaluation/results/cve_baselines_172-28.json)):

| Tool | School | Planted-CVE recall | Unexpected |
|---|---|---:|---:|
| **nmap-`vulners`** | version-match | **1.00 (3/3)** | **133** |
| **EnumGrid** | version-match (conservative) | **0.67 (2/3)** | **13** |
| **Nuclei** | active-PoC | **0.00 (0/3)** | **0** |

The two schools trade off exactly as theory predicts, now on real hosts:
version-match maximises recall (nmap-`vulners` 3/3) but at **10× the noise** (133
vs EnumGrid's 13); EnumGrid deliberately trades a little recall for far fewer false
alarms; active-PoC (Nuclei) fires **nothing** because the vanilla images expose the
*version* but not the *exploitable config* (e.g. the CVE-2021-41773 PoC needs a
`cgi-bin`/alias the default image omits) — high precision, config-dependent recall.

Two honesties we keep rather than smooth over: EnumGrid's own recall varied
**2/3 ↔ 3/3** between this run and [§6.3](#63-service-port-and-version-detection)
— real live-scan nondeterminism on the incomplete-fix 2.4.50 twin, which is *why*
the project measures run-to-run stability (`--repeat`); and on the *clean* testbed
EnumGrid's discovery merely **ties** `nmap -sn` at 1.00 ([§6.2](#62-host-discovery))
— it dominates only on real ICMP-filtered LANs, and we say so. The heavyweight
scanners (OpenVAS/Nessus) are supported via report-file adapters
(`cve_baselines.py --tools openvas,nessus`), awaiting an operator export.

### 6.7 Scalability

`scalability_benchmark.py` swept `/28 → /24` inside the authorised `172.16.2.0/24`
([`scalability_172-16-2.json`](../evaluation/results/scalability_172-16-2.json)):
discovery time fits **46.5 ms/address + 9.1 s fixed overhead (R² = 0.83)**, a
throughput of ~6.4 addresses/s. Peak-RSS is best-effort and noisy on macOS
(`getrusage` children), so we report the timing fit and flag the memory figure as
indicative only. A larger owned range would give a cleaner fit.

### 6.8 LLM triage copilot

The copilot summarises scan findings and is measured for **grounding** (does it
cite only hosts/CVEs present in the scan) as well as coverage. Five runs of
`copilot_eval.py` against a local Ollama model
([`llama3.2_x5.json`](../evaluation/results/llama3.2_x5.json)):

| Metric | Mean ± 95% CI | Min / Max |
|---|---|---|
| **Grounding** | **1.000 ± 0.000** | 1.00 / 1.00 |
| Coverage | 0.760 ± 0.078 | 0.60 / 0.80 |
| Score | 0.880 ± 0.039 | 0.80 / 0.90 |

**Grounding is perfectly stable at 1.00 across all five runs** — the model
fabricated nothing, five times out of five, because the guarantee is *structural*
(real ids into the context, a deterministic guard on the way out), not sampled. The
only variance is coverage (recall): the residual failure mode of a grounded model
is *silence* on a fact, never *invention* of one — exactly the right trade for a
security tool. A larger 7B model (qwen2.5) reaches coverage 1.00 / grounding 1.00.
A `--self-test` proves grounding collapses to 0 on an adversarial fabricated reply,
so the metric cannot be gamed by fluent-but-false output.

---

## 7. Threats to Validity

- **External (the largest).** Results come from **few environments** — two real
  `/24`s plus one synthetic testbed — on one operator's hardware. Generalisation to
  enterprise, IoT-dense, or cloud-VPC networks is **unestablished**; the discovery
  pool is n = 2. This is the primary route to a stronger paper and is scaffolded but
  not yet closed ([`COLLECTING_NETWORKS.md`](../evaluation/COLLECTING_NETWORKS.md)).
- **Construct.** Off-testbed discovery uses union-of-tools as a proxy, so recall is
  an upper bound. CVE *precision* is scored deterministically on the offline corpus,
  not on rolling images (extras are surfaced, not counted). **CPE-dictionary drift**
  ([§6.5](#65-cve-matching--the-primary-live-nvd-path)) means the live-NVD layer
  alone has recall gaps where nmap's and NVD's vendor strings disagree — measured,
  mitigated by independent layers.
- **Internal.** Live scans are nondeterministic; addressed by stability measurement
  and multi-run CIs rather than pretending determinism. Coverage is **line**, not
  **branch**.
- **Statistical.** With small n the CIs are wide; a "1.00" on a small corpus means
  *"no error observed in this sample"*, not *"error-free in general"* — the corpora
  (33 offline / 12 live CVE cases, 3 planted instances) are small and curated by the
  author, which the held-out template is designed to address.

## 8. Ethics and Legal

- **Authorisation is enforced, not assumed.** `ScopeValidator` hard-refuses
  loopback, multicast, broadcast, link-local, reserved, and (by default)
  public/Internet-routable space — a technical control, part of the contribution.
- **No third-party scanning.** All evaluation targets are the operator's own `/24`
  or containers the operator owns. Active scanning without written authorisation is
  out of scope and refused.
- **Responsible disclosure** for any real vulnerability found on an authorised
  third-party estate; ENUMGRID's own issues go through `SECURITY.md`.
- **Data handling.** Published figures redact identifying fields
  ([Appendix A](#appendix-a--figure-manifest-redacted)); secrets (NVD key, sudo
  password) are owner-only (0600), in-memory where possible, never logged.
- **Dual-use.** ENUMGRID is a *defensive* enumeration tool; the refusal guards and
  the honesty discipline are deliberate mitigations of offensive potential.

## 9. Reproducibility

The testbed is pinned to fixed image tags; all scoring math is pure and
unit-tested, so the published numbers run in CI with no Docker or network. Baselines
are declared (a missing one is `unavailable`, never "found nothing"); the copilot
eval pins models and reports multi-run mean ± CI. Every headline number maps to a
command and an artifact in [Appendix B](#appendix-b--reproduce-every-number) /
[`REPRODUCE.md`](REPRODUCE.md).

## 10. Limitations and Future Work

Ordered by leverage: **(1)** scale the discovery evaluation to 3–5 *distinct*
authorised real networks (runbook ready); **(2)** add a held-out, independently-
sourced CVE corpus (template + protocol ready) to retire the fit-to-matcher risk;
**(3)** add OpenVAS/Nessus baselines (report-file adapters ready) for a broader
precision picture; **(4)** run the pre-registered analyst **user study**
([`USER_STUDY_PROTOCOL.md`](USER_STUDY_PROTOCOL.md)) to test whether the honesty
labelling measurably improves decisions. Items 1–4 are *scaffolded but not
fabricated* — each needs real networks, an independent sampler, an operator export,
or human participants, respectively.

## 11. Conclusion

ENUMGRID does not claim a new algorithm. It claims that a network enumeration tool
can treat **no fabrication as a measurable property** — banding its confidence,
saying `Unknown` instead of guessing, never simulating its data, and measuring the
false-positive/hallucination behaviour of both its deterministic matcher and its
LLM copilot — and it backs that claim with reproducible numbers: precision 1.00 /
recall 1.00 on an adversarial CVE corpus with the one false positive it *did* find
fixed and regression-locked; 0 fabricated CVEs across five copilot runs; 0.99 ± 0.02
unprivileged discovery recall across two environments versus a highly
environment-dependent 0.53 ± 0.93 baseline; and a primary live-NVD path measured to
1.00 recall *with its one real failure mode surfaced and attributed*. The
evaluation is deliberately bounded and every limit is named. The contribution is
the discipline and its measurement.

---

## Appendix A — Figure manifest (redacted)

Figures are **real** runs of an authorised scan (`172.16.2.0/24`, unprivileged) or
the standby UI; the `*-redacted.png` copies (produced by
[`docs/screenshots/redact.py`](screenshots/redact.py)) blur the operator hostname
and MAC column and are the ones to publish.

| Fig | File (publish the `-redacted`) | Shows |
|---|---|---|
| 1 | `command-center-standby-redacted.png` | Full app shell, standby (`0/0 hosts`) |
| 2 | `privilege-elevation-redacted.png` | Sudo elevation dialog + in-memory-only note |
| 3 | `scan-live-redacted.png` | Live scan, Phase 1 at 32%, 8 hosts populating |
| 4 | `scan-complete-redacted.png` | Completed scan, 15/15, OS fusion, IPv6, drift panel |
| 5a | `topology-redacted.png` | Radial topology map |
| 5b | `mobile.png` | Responsive 390px layout (no host data on screen) |
| 6 | `benchmark_multirun_172-16-2.png`, `pooled_recall.png`, `scaling_172-16-2.png` | Generated eval figures |

> **Honest caveat on Figs 3–4.** On this real consumer LAN the discovered hosts are
> firewalled phones/laptops, so **Open Ports / Services / CVEs read `00`** — the
> *true* unprivileged result, not a gap papered over. Populating those columns needs
> a host that actually exposes services (the docker testbed). Nothing is simulated.

## Appendix B — Reproduce every number

```bash
# Offline CVE precision/recall (deterministic, CI-gated)
python evaluation/cve_precision.py --json evaluation/results/cve_precision.json

# Primary live-NVD path (scorer self-check, then real feed)
python evaluation/nvd_precision.py                 # fixture self-check, no network
python evaluation/nvd_precision.py --live --json evaluation/results/nvd_live.json

# Detection accuracy + CVE baselines (testbed up)
docker compose -f evaluation/docker-compose.yml up -d
python evaluation/detection_benchmark.py --json evaluation/results/detection_172-28.json
python evaluation/cve_baselines.py       --json evaluation/results/cve_baselines_172-28.json
docker compose -f evaluation/docker-compose.yml down

# Discovery + cross-environment pooling + scalability + copilot
python evaluation/benchmark.py 172.16.2.0/24 --runs 3 --json evaluation/results/benchmark_172-16-2.json
python evaluation/aggregate_runs.py evaluation/results/benchmark_*.json --json evaluation/results/pooled_recall.json --plot docs/screenshots/pooled_recall.png
python evaluation/scalability_benchmark.py 172.16.2.0/28 172.16.2.0/27 172.16.2.0/26 172.16.2.0/25 172.16.2.0/24 --repeat 2 --json evaluation/results/scalability_172-16-2.json
python evaluation/copilot_eval.py --provider ollama --model llama3.2 --runs 5 --json evaluation/results/llama3.2_x5.json

# All scoring math (no Docker, no network):
python -m pytest evaluation/
```

## References (draft bibliography)

Cited by name; fill in venues/DOIs at submission time.

1. G. Lyon. *Nmap Network Scanning.* (nmap `-sV`, NSE, `vulners`, `-sn`.)
2. ProjectDiscovery. *Nuclei* — template-based active-PoC scanner.
3. Greenbone. *OpenVAS / GVM*; Tenable. *Nessus.* Vulnerability scanners.
4. NIST. *National Vulnerability Database (NVD) API 2.0*; CPE 2.3 dictionary.
5. CISA. *Known Exploited Vulnerabilities (KEV) Catalog.*
6. FIRST. *Exploit Prediction Scoring System (EPSS).*
7. Google. *OSV — Open Source Vulnerabilities* (distro backport ecosystems).
8. E. B. Wilson. "Probable inference, the law of succession, and statistical
   inference." *JASA*, 1927. (Wilson score interval.)
9. Z. Durumeric, E. Wustrow, J. A. Halderman. "ZMap: Fast Internet-Wide Scanning."
   *USENIX Security*, 2013.
10. R. D. Graham. *MASSCAN.* High-rate port scanner.
