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
