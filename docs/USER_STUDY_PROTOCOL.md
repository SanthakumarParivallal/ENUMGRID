# Analyst user-study protocol (pre-registration)

> A **pre-registered** protocol for the one evaluation ENUMGRID cannot produce
> from harnesses: does the honesty labelling + grounded copilot *measurably
> improve an analyst's decisions* versus a raw scanner? This is the genuine
> HCI-for-security contribution flagged in [`CONTRIBUTIONS.md`](CONTRIBUTIONS.md)
> §8.5. It is written **before** any data is collected so the analysis cannot be
> fitted to the result. It requires human participants, so it must be **run**, not
> simulated. **Do not fabricate participants, responses, or outcomes.**

## 1. Research questions and hypotheses

- **RQ1 (calibration).** Do ENUMGRID's confidence bands (`confirmed` against
  `version`) and `Unknown` labels improve analysts' calibration, meaning do they act on
  high-confidence findings and verify low-confidence ones?
  - **H1:** analysts using the labelled UI have a **lower false-action rate**
    (acting on an unverified `version`/`Unknown` finding as if confirmed) than
    those using an unlabelled view of the same scan.
- **RQ2 (copilot triage).** Does the grounded copilot summary speed up triage
  without inducing over-trust in fabricated content?
  - **H2:** analysts with the copilot reach a correct prioritisation **faster**
    (time-to-decision) with **no increase** in acted-upon fabricated facts
    (expected 0, given the structural grounding guarantee; see
    [`COPILOT.md`](COPILOT.md)).
- **RQ3 (trust).** Does exposing uncertainty reduce subjective trust, or
  *increase* it (well-placed trust)? Measured, not assumed.

## 2. Design

- **Within-subjects, counterbalanced.** Each participant completes triage tasks in
  two conditions, (A) labelled with copilot and (B) raw, meaning labels hidden and no
  copilot, on matched but distinct scan datasets, with order counterbalanced
  (Latin square) to cancel learning effects. A washout task separates conditions.
- **Materials.** Real scan outputs from the authorised testbed + LANs (the same
  data behind the eval harnesses), including deliberate traps: a back-ported build
  that *looks* vulnerable (`version` band), an `Unknown`-OS host, and a genuine
  planted CVE (`confirmed`). No mock data.
- **Blinding.** Participants are not told which condition is "the tool's"; the
  facilitator scoring outcomes is blind to condition where feasible.

## 3. Participants

- **Target n.** Power analysis: to detect a medium within-subjects effect
  (dz ≈ 0.5) at α = 0.05, power 0.80, a paired t-test needs n ≈ 34. Recruit at least 34;
  report the achieved power. A pilot (n ≈ 5) validates task timing and is
  **excluded** from confirmatory analysis.
- **Inclusion.** Practising security analysts, pentesters or sysadmins with
  ≥ 1 year of network-security experience. Record experience as a covariate.
- **Recruitment.** Professional networks and university security groups, with no
  compensation tied to a particular outcome.

## 4. Tasks, and primary and secondary measures

Each task: "here is a scan of an authorised estate; decide which findings to act
on now, which to verify, and which to defer, and justify."

| Measure | Type | Definition |
| --- | --- | --- |
| **False-action rate** (H1, primary) | accuracy | fraction of `version` or `Unknown` findings acted on as if confirmed |
| **Time-to-decision** (H2, primary) | efficiency | seconds from task start to submitted prioritisation |
| **Acted-upon fabricated facts** (H2, safety) | safety | count of decisions justified by a fact not in the scan (expected 0) |
| **Prioritisation correctness** | accuracy | agreement with an expert-panel gold ranking (Kendall's τ) |
| **Subjective trust and workload** (RQ3) | survey | post-condition Likert plus NASA-TLX |

## 5. Analysis plan (fixed in advance)

- **H1 / prioritisation:** paired t-test (or Wilcoxon signed-rank if non-normal)
  on per-participant condition differences; report effect size (dz) + 95 % CI.
- **H2 time:** a paired test on median time-to-decision. Safety is reported as exact
  counts rather than averaged away, and any non-zero acted-upon fabricated fact is called
  out individually.
- **Multiplicity:** two primary hypotheses, so a Holm-Bonferroni correction.
- **Covariate:** experience level entered in a secondary mixed model.
- **Stopping rule:** fixed n, with no optional stopping, and the analysis run once, after
  collection completes.

## 6. Ethics and data handling

- **Approval.** Obtain IRB or ethics-board approval before recruiting. This
  document is the submitted protocol.
- **Consent.** Informed consent, with participation voluntary and withdrawable without
  penalty.
- **Data minimisation.** Store only task responses, timings and de-identified
  demographics; no scan data leaves the study machine; participant ids are
  pseudonymous. Scan materials contain no third-party PII (own/authorised estates,
  redacted per [`screenshots/README.md`](screenshots/README.md)).
- **Dual-use.** Participants triage findings. They do not exploit anything.

## 7. Threats to validity (named up front)

- **Construct:** the gold prioritisation is an expert-panel judgement rather than
  ground truth, so report inter-rater agreement.
- **External:** lab triage is not on-call triage under real pressure. State the gap.
- **Internal:** learning and fatigue across conditions, handled by counterbalancing
  and a washout.
- **Experimenter bias:** pre-registration (this file) and blinded scoring mitigate
  fitting the analysis to the result.

---

*Status: protocol only. No data collected. Publishing any result from this study
requires actually running it under the approved ethics process above.*
