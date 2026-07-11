# Analyst user-study protocol (pre-registration)

> A **pre-registered** protocol for the one evaluation ENUMGRID cannot produce
> from harnesses: does the honesty labelling + grounded copilot *measurably
> improve an analyst's decisions* versus a raw scanner? This is the genuine
> HCI-for-security contribution flagged in [`CONTRIBUTIONS.md`](CONTRIBUTIONS.md)
> §8.5. It is written **before** any data is collected so the analysis cannot be
> fitted to the result. It requires human participants — it must be **run**, not
> simulated. **Do not fabricate participants, responses, or outcomes.**

## 1. Research questions & hypotheses

- **RQ1 (calibration).** Do ENUMGRID's confidence bands (`confirmed` vs `version`)
  and `Unknown` labels improve analysts' *calibration* — i.e. do they act on
  high-confidence findings and verify low-confidence ones?
  - **H1:** analysts using the labelled UI have a **lower false-action rate**
    (acting on an unverified `version`/`Unknown` finding as if confirmed) than
    those using an unlabelled view of the same scan.
- **RQ2 (copilot triage).** Does the grounded copilot summary speed up triage
  without inducing over-trust in fabricated content?
  - **H2:** analysts with the copilot reach a correct prioritisation **faster**
    (time-to-decision) with **no increase** in acted-upon fabricated facts
    (expected 0, given the structural grounding guarantee — see
    [`COPILOT.md`](COPILOT.md)).
- **RQ3 (trust).** Does exposing uncertainty *reduce* subjective trust, or
  *increase* it (well-placed trust)? Measured, not assumed.

## 2. Design

- **Within-subjects, counterbalanced.** Each participant completes triage tasks
  in two conditions — **(A) labelled + copilot** and **(B) raw** (labels hidden,
  no copilot) — on **matched but distinct** scan datasets, order counterbalanced
  (Latin square) to cancel learning effects. A washout task separates conditions.
- **Materials.** Real scan outputs from the authorised testbed + LANs (the same
  data behind the eval harnesses), including deliberate traps: a back-ported build
  that *looks* vulnerable (`version` band), an `Unknown`-OS host, and a genuine
  planted CVE (`confirmed`). No mock data.
- **Blinding.** Participants are not told which condition is "the tool's"; the
  facilitator scoring outcomes is blind to condition where feasible.

## 3. Participants

- **Target n.** Power analysis: to detect a medium within-subjects effect
  (dz ≈ 0.5) at α = 0.05, power 0.80, paired t-test → **n ≈ 34**. Recruit **≥ 34**;
  report the achieved power. A pilot (n ≈ 5) validates task timing and is
  **excluded** from confirmatory analysis.
- **Inclusion.** Practising security analysts / pentesters / sysadmins with
  ≥ 1 year of network-security experience. Record experience as a covariate.
- **Recruitment.** Professional networks, university security groups; no
  compensation tied to a particular outcome.

## 4. Tasks & primary/secondary measures

Each task: "here is a scan of an authorised estate — decide which findings to act
on now, which to verify, and which to defer, and justify."

| Measure | Type | Definition |
| --- | --- | --- |
| **False-action rate** (H1, primary) | accuracy | fraction of `version`/`Unknown` findings acted on as if confirmed |
| **Time-to-decision** (H2, primary) | efficiency | seconds from task start to submitted prioritisation |
| **Acted-upon fabricated facts** (H2, safety) | safety | count of decisions justified by a fact not in the scan (expected 0) |
| **Prioritisation correctness** | accuracy | agreement with an expert-panel gold ranking (Kendall's τ) |
| **Subjective trust / workload** (RQ3) | survey | post-condition Likert + NASA-TLX |

## 5. Analysis plan (fixed in advance)

- **H1 / prioritisation:** paired t-test (or Wilcoxon signed-rank if non-normal)
  on per-participant condition differences; report effect size (dz) + 95 % CI.
- **H2 time:** paired test on median time-to-decision; **safety** reported as exact
  counts (not averaged away) — any non-zero acted-upon fabricated fact is called
  out individually.
- **Multiplicity:** two primary hypotheses → Holm–Bonferroni correction.
- **Covariate:** experience level entered in a secondary mixed model.
- **Stopping rule:** fixed n (no optional stopping); analysis run once, after
  collection completes.

## 6. Ethics & data handling

- **Approval.** Obtain IRB / ethics-board approval before recruiting; this
  document is the submitted protocol.
- **Consent.** Informed consent; participation voluntary and withdrawable without
  penalty.
- **Data minimisation.** Store only task responses + timings + de-identified
  demographics; no scan data leaves the study machine; participant ids are
  pseudonymous. Scan materials contain no third-party PII (own/authorised estates,
  redacted per [`screenshots/README.md`](screenshots/README.md)).
- **Dual-use.** Participants triage findings; they do not exploit anything.

## 7. Threats to validity (named up front)

- **Construct:** the gold prioritisation is an expert-panel judgement, not ground
  truth — report inter-rater agreement.
- **External:** lab triage ≠ on-call triage under real pressure; state the gap.
- **Internal:** learning/fatigue across conditions → counterbalancing + washout.
- **Experimenter bias:** pre-registration (this file) + blinded scoring mitigate
  fitting the analysis to the result.

---

*Status: protocol only. No data collected. Publishing any result from this study
requires actually running it under the approved ethics process above.*
