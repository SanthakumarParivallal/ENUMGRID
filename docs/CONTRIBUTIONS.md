# Contributions, positioning and threats to validity

> A candid, publication-oriented framing of what ENUMGRID contributes, what is
> genuinely novel against what is established, how the evaluation should and should
> not be read, and the ethical and reproducibility posture. It is written to be
> defensible under examination, and deliberately under-claims.

---

## 1. Contribution statement

ENUMGRID is a systems and measurement contribution rather than a new algorithm. Its
individual techniques (multi-method host discovery, `nmap` service and version
detection, CPE-to-CVE correlation, KEV/EPSS triage, LLM summarisation) are each
established. The contribution lies in how they are integrated and in the discipline
imposed on the result. Three claims are defensible, and they are what the project
should be evaluated on:

1. **Honesty as a property.** A scanner that quantifies and bounds its own
   over-claiming. Findings are confidence-banded (`confirmed` against `version`),
   unresolved fields are labelled `Unknown` rather than guessed, the data path is
   never simulated, and both the CVE matcher and the LLM copilot are measured for
   false-positive and hallucination behaviour as well as recall. Most scanners
   report a single blended verdict and leave their uncertainty implicit.

2. **Unprivileged fidelity.** A four-signal OS and discovery fusion (ICMP-reply TTL,
   IEEE OUI, hostname and the mDNS `model=` record) plus privilege auto-adaptation,
   where root-only `nmap` flags are rewritten to safe equivalents. It recovers most
   of the accuracy of a privileged scan without root, and is explicit about the
   residual gap.

3. **A grounded LLM triage copilot with measured hallucination guards.** Scan-grounded
   summarisation with intent-gated tool arming, and an evaluation harness that scores
   both grounding coverage and the novel-CVE hallucination rate across models and
   repeated runs.

Everything else, including the two-tiered CLI and web architecture, the UX and the
test rigour, is engineering quality that supports these claims without being a
research contribution itself.

---

## 2. Related work and positioning

| Tool / system | Class | What it does | What ENUMGRID adds relative to it |
|---|---|---|---|
| **Fing / Angry IP** | Asset discovery | Fast device inventory (vendor/MAC/type) | Adds service/version depth, live CVE correlation, and honesty labelling on top of the inventory |
| **nmap / Zenmap** | Port/service scanner | Authoritative service, version, OS, NSE | Whole-network orchestration, unprivileged auto-adaptation, and CVE/KEV/EPSS enrichment around the same `nmap` engine it invokes |
| **masscan / RustScan / ZMap** | High-rate port/Internet scanners | Breadth at very high packet rates | Not a competitor on raw speed. ENUMGRID targets authorised local estates with depth and honesty, rather than Internet-scale breadth |
| **OpenVAS / Greenbone, Nessus** | Vulnerability scanners | Deep authenticated + network vuln assessment | Lighter-weight, unprivileged-first, transparent about confidence. These remain stronger, more mature vuln scanners; ENUMGRID is measured against them, not claimed to replace them |
| **Nuclei** | Template-based active-PoC scanner | Confirms vulns by sending a probe | Used as an evaluation baseline (`evaluation/cve_baselines.py`). ENUMGRID's version-match path trades some precision for breadth |
| **nmap `vulners` NSE** | Version-match CVE lookup | CVE ids from detected CPE/version | The same school as ENUMGRID's CPE-to-NVD path, used as a second baseline for head-to-head recall |

**Placement.** ENUMGRID sits between asset-discovery tools, which do not assess
vulnerability, and vulnerability scanners, which do not give a fast, honest,
unprivileged inventory and monitoring experience. Its value is the integration and
the honesty discipline, not out-scanning Nessus or out-running masscan.

---

## 3. Novelty, stated plainly

**What is not novel:** ping, ARP and TCP discovery, `nmap -sV`, CPE-to-NVD lookup,
KEV/EPSS prioritisation, and LLM summarisation. Each exists in prior tools.

**What is defensibly new or under-explored:**
- Treating no-fabrication as a first-class, measurable property of a scanner, with a
  false-positive and hallucination evaluation for both the deterministic CVE matcher
  and the LLM copilot.
- The four-signal unprivileged OS and type fusion, with an explicit
  privilege-adaptation model and a measurement of the unprivileged-against-privileged
  gap.
- A reproducible, grounded-LLM triage eval (grounding coverage, hallucination rate,
  multi-run mean ± CI, free local models) applied to network-scan output.

**Verdict for venue selection:** this is a strong Master's dissertation and a
credible tool, demo or workshop paper. On novelty alone it does not fit a top-tier
research venue (USENIX Security, IEEE S&P, CCS, NDSS), which require a fundamental
advance. Framing it as an engineering and measurement paper around the three claims
above is the position that holds up.

---

## 4. Evaluation: what it supports, and what it does not

The evaluation methodology is sound: true ground truth on the testbed, closed-world
precision and recall, mean ± 95% CI, Wilson CIs, and multi-run treatment of the
nondeterministic LLM. The limits are about scale and baselines rather than design.

| Axis | What is measured | What it supports | Honest limitation |
|---|---|---|---|
| **Discovery** | Recall/precision vs `nmap -sn` on a home `/24` (11 hosts) and a busy `/24` (~15, 3 runs) | ENUMGRID's multi-method discovery beats an unprivileged ping-sweep by a wide, statistically-reported margin | Few environments; small n; `nmap -sn` is a weak baseline; union-as-proxy ground truth off the docker testbed |
| **Detection (ports/services/versions)** | Precision/recall vs a pinned, now **9-host** docker testbed with exact ground truth | True detection accuracy with no false-positive ambiguity | Testbed is small and synthetic; real estates are messier |
| **CVE matching (offline)** | Precision/recall on a 33-case labelled corpus (`cve_precision.py`) | The offline fallback matcher's whole-token behaviour (no `httpd` inside `lighttpd`) | The corpus is small and curated by the author, which risks fitting the matcher, and it tests the fallback rather than the primary live-NVD path |
| **CVE matching (live NVD, primary)** | Documented-CVE recall, version-scoping precision and top-N truncation loss on the live pipeline (`nvd_precision.py`, real `parse_nvd`). Measured live 2026-07-11: recall 1.00 (8/8), scoping 1.00 (7/7), 0 violations | That the primary path (version-scoped CPE query → parse → CVSS-ranked top-N) surfaces documented bugs and excludes patched and other-product CPEs | Corpus labels are author-curated lower bounds, and the run also surfaced a real CPE-dictionary-drift limitation (see §5 here and §10 of ACCURACY), so the live layer alone is not sufficient by design |
| **CVE detection vs baselines** | Planted-CVE recall against nmap-`vulners` and Nuclei on the same testbed (`cve_baselines.py`). Measured 2026-07-11: vulners 3/3 (133 unexpected), EnumGrid 2/3 (13), Nuclei 0/3 | Answers "compared to what?" by showing the two detection schools on real hosts: version-match (high recall, noisy) against active-PoC (exploitability-gated) | The planted-CVE n is still small at 3 instances across 2 hosts, and EnumGrid recall varied between 2/3 and 3/3 across runs because of live-scan nondeterminism |
| **LLM copilot** | Grounding coverage + novel-CVE hallucination, multi-run mean ± CI, across llama3.2 / qwen2.5 | Bounded, reproducible hallucination behaviour | Model versions drift; small task set |

**Claims the evidence does support:** ENUMGRID's discovery substantially and
significantly out-recalls an unprivileged ping-sweep; its detection has no false
positives on a known testbed; its offline matcher is whole-token-precise; its
copilot's hallucination rate is bounded and measured.

**Claims the evidence does not yet support, and which should not be made:** a general
"precision and recall = 1.00" across arbitrary real networks; superiority over a
mature vulnerability scanner such as Nessus or OpenVAS; scalability beyond a `/24`.

---

## 5. Threats to validity

**Construct validity.** Off-testbed discovery uses the union of tools as a
ground-truth proxy, so a host that no tool sees is invisible to the metric and recall
is an upper bound on that axis. Planted-CVE recall is a true metric. CVE precision is
deliberately not scored on rolling images, where extras are surfaced without being
counted, and is instead measured separately and deterministically on the 33-case
offline corpus. **CPE-dictionary drift on the live-NVD path:** the vendor token
nmap's fingerprint emits does not always equal NVD's canonical vendor. A real
`--live` run found vsftpd indexed as `vsftpd_project` in NVD but as `vsftpd` by nmap,
so a version-scoped query missed CVE-2011-2523. The live-NVD layer alone therefore
has recall gaps wherever the two dictionaries disagree. This is measured rather than
hidden, since `nvd_precision.py` surfaced it, and it is mitigated by the independent
`vulners` and offline layers. See [`ACCURACY.md`](ACCURACY.md) §10.

**Internal validity.** Live scans are nondeterministic (races, network state);
this is addressed by run-to-run stability measurement (`--repeat`) and multi-run CIs
rather than by pretending a scan is deterministic. Coverage is line coverage, not
branch coverage: 100% line coverage bounds "code never executed in test", not "all
logic paths correct".

**External validity.** This is the largest threat. Results come from few
environments, two real `/24`s and one synthetic testbed, all on one operator's
hardware, and generalisation to enterprise, IoT-dense or cloud-VPC networks is
unestablished. The CVE
corpus and testbed are small. Broadening both is the primary route to a stronger
paper (`evaluation/benchmark.py --runs N` aggregates additional environments with CIs).

**Statistical validity.** CIs are reported, but with small n they are wide. A "1.00"
figure on a tiny corpus means no error was observed in that sample, not that the
result is error-free in general, and the write-up says so.

---

## 6. Ethics and legal

- **Authorisation is enforced, not assumed.** The `ScopeValidator`, shared by the CLI
  and the backend, hard-refuses loopback, multicast, broadcast, link-local, reserved
  and, by default, public or Internet-routable space. It is a technical ethical
  control rather than a disclaimer, and is itself part of the contribution.
- **No third-party scanning.** All evaluation targets are either the operator's own
  `/24` or containers the operator owns (`evaluation/docker-compose.yml` is
  "authorised by construction"). Active scanning of networks without written
  authorisation is out of scope and refused by the tool.
- **Responsible disclosure.** Any real, previously-unknown vulnerability discovered
  while scanning an authorised third-party estate must be disclosed to its owner;
  ENUMGRID's own vulnerabilities go through [`SECURITY.md`](../SECURITY.md).
- **Data handling.** Scan output can contain hostnames, MACs and vendor OUIs;
  figures published from real runs should redact identifying fields (see
  [`docs/screenshots/README.md`](screenshots/README.md)). Secrets (NVD key, sudo
  password) are owner-only (0600), in-memory where possible, and never logged.
- **Dual-use.** ENUMGRID is a defensive asset-mapping and enumeration tool, and the
  refusal guards and the honesty discipline are deliberate mitigations of its
  offensive potential. A dissertation or paper should carry an explicit ethics
  statement to this effect.

---

## 7. Reproducibility

- **Pinned testbed.** `evaluation/docker-compose.yml` uses fixed image tags so the
  ground truth is stable run-to-run, and `evaluation/ground_truth.json` records the
  exact expected ports, services, versions and planted CVEs.
- **Deterministic scoring.** All metric math (`benchmark.py`, `detection_benchmark.py`,
  `cve_precision.py`, `cve_baselines.py`, `copilot_eval.py`) is pure and unit-tested,
  so the published numbers run in CI with no Docker and no network.
- **Baselines are declared.** For discovery: `nmap -sn`, `arp-scan`, `netdiscover` and
  `masscan`. For CVEs: `nmap-vulners` and `nuclei`. A missing baseline is reported as
  unavailable, never as having found nothing.
- **LLM determinism.** The copilot eval pins models and reports multi-run mean ± CI.
  Publish the exact model versions, temperature and prompts alongside results, since
  model updates will move the numbers.
- **Provenance.** Each scan carries a provenance manifest, and golden-file tests fix
  the parser, model and PDF pipeline byte-for-byte.

---

## 8. What would raise the bar (roadmap to a stronger paper)

1. **Scale the evaluation** to 5 or 10 diverse real networks (enterprise, IoT, cloud VPC).
   *Harness ready:* `evaluation/aggregate_runs.py` pools per-network `benchmark.py --runs N`
   results into a cross-environment recall figure (mean ± 95 % CI across environments) + a
   plot. *A fresh 3-run pass on `172.16.2.0/24` (2026-07-11) reconfirmed EnumGrid recall
   **0.98 ± 0.04** vs `nmap -sn` **0.06** unprivileged* ([`../evaluation/results/benchmark_172-16-2.json`](../evaluation/results/benchmark_172-16-2.json)),
   and `aggregate_runs.py` **pooled three environments** (two real LANs + the colima testbed)
   → EnumGrid **0.97 ± 0.04** vs `nmap -sn` **0.49 ± 0.54** across environments
   ([`../evaluation/results/pooled_recall.json`](../evaluation/results/pooled_recall.json)).
   But n = 3, two real LANs plus one synthetic testbed, is still small. Real external
   validity needs several distinct authorised real networks, which must not be fabricated.
   *Turnkey scaffolding (2026-07-11):* [`evaluation/COLLECTING_NETWORKS.md`](../evaluation/COLLECTING_NETWORKS.md)
   is a three-command-per-network runbook + authorisation checklist that feeds `aggregate_runs.py`;
   each authorised network the operator adds tightens the cross-environment CI.
   Also enlarge the CVE corpus with held-out, independently-sourced cases to remove the
   fit-to-matcher risk. [`evaluation/nvd_corpus_heldout.json`](../evaluation/nvd_corpus_heldout.json)
   is a frozen, empty template carrying the blind-sampling protocol, and `nvd_precision.py --live
   --corpus …` scores it unchanged. Both are scaffolding rather than results, and both still
   need the operator's real networks or an independent sampler.
2. **Meet or beat a real vuln scanner.** *Done (2026-07-11):* brought the 9-host testbed up
   on a colima VM and ran `cve_baselines.py`, giving nmap-`vulners` 3/3 (133 unexpected),
   EnumGrid 2/3 (13 unexpected) and Nuclei 0/3 (active-PoC, exploitability-gated). The
   two-schools tradeoff is now shown on real hosts ([`../evaluation/results/README.md`](../evaluation/results/README.md)).
   *Remaining:* a larger planted set, plus OpenVAS and Nessus for a broader precision
   picture. The report-file adapters are now built (`cve_baselines.py --tools openvas,nessus` parses an
   exported GVM/Nessus report via `ENUMGRID_OPENVAS_REPORT` / `ENUMGRID_NESSUS_REPORT`, scoring
   the real report host-by-host; unavailable, never "found nothing", when no report is supplied),
   so adding those heavyweights is an operator export + one flag away.
3. **Precision and recall on the primary CVE path.** Evaluate the live-NVD CPE match,
   not only the offline fallback. *Done (2026-07-11):* `evaluation/nvd_precision.py --live`
   scored recall **1.00 (8/8)**, version-scoping precision **1.00 (7/7)**, 0 truncation
   losses against the real NVD feed ([`../evaluation/results/nvd_live.json`](../evaluation/results/nvd_live.json)),
   and surfaced the CPE-dictionary-drift limitation now documented in §5. The scorer +
   real `parse_nvd` remain CI-tested on NVD-2.0 schema fixtures. *Remaining:* enlarge the
   corpus with held-out, independently-sourced CPEs to reduce the author-curation risk.
4. **Scalability study:** timing and memory against address-space size. *Done (2026-07-11):*
   `evaluation/scalability_benchmark.py` swept `/28` to `/24` inside the authorised
   `172.16.2.0/24` and fit discovery time at **46.5 ms/address + 9.1 s fixed overhead
   (R² = 0.826)**, ~6 addresses/s ([`../evaluation/results/scalability_172-16-2.json`](../evaluation/results/scalability_172-16-2.json),
   plot `docs/screenshots/scaling_172-16-2.png`). Peak-RSS is best-effort/noisy on macOS
   (`getrusage` children). *Remaining:* a larger owned range for a cleaner fit.
5. **User or expert study** (optional). Do the honesty labelling and the copilot triage
   measurably improve an analyst's decisions against a raw scanner? That would be a
   genuine, publishable HCI-for-security contribution. *Pre-registered protocol now written:*
   [`docs/USER_STUDY_PROTOCOL.md`](USER_STUDY_PROTOCOL.md) fixes the hypotheses (calibration,
   triage speed, over-trust), a within-subjects counterbalanced design, an n ≈ 34 power
   analysis, and the analysis plan before any data is collected. It still has to be run with
   real human participants under ethics approval, and it must not be simulated.

---

*This document is intentionally self-critical: if an examiner or reviewer raises a
gap, it should already be named here.*
