# AI Copilot: Design, Grounding Guarantees, and Evaluation

> Dissertation section. Describes the ENUMGRID AI copilot: its architecture, the
> guarantees that keep it from fabricating security findings, and a reproducible
> evaluation of those guarantees. Every claim below is backed by code in
> `backend/copilot.py`, `frontend/src/lib/markdown.js`, and
> `evaluation/copilot_eval.py`, and by the real results in
> `evaluation/results/`.

## 1. Motivation and threat

A network-enumeration tool that also *explains* its results is only useful if the
explanations are true. A large language model that invents a host, a port, or —
worst of all — a CVE identifier, turns a defensive tool into a source of false
positives. For a security context the failure mode is asymmetric: a fluent,
confident, wrong answer is more dangerous than no answer. The copilot is
therefore designed around a single governing principle inherited from the rest of
the platform: **never present anything that is not real.** Where the scanner says
"Unknown" rather than guess an OS, the copilot must say "the scan does not show
that" rather than invent one.

## 2. Design

### 2.1 Grounding by construction

The copilot never answers from parametric memory alone. On every turn the
frontend serialises the *current on-screen scan* — hosts, open ports, detected
services and versions, CVE findings and their severities — into a compact context
block, and that block is the only authoritative source the model is given. The
system prompt (`SYSTEM_PROMPT`, `backend/copilot.py`) instructs the model to
answer strictly from that context and, critically, to *decline* when the context
is silent: it must "never invent hosts, ports, CVEs, or severities" and, if the
scan does not contain the answer, "say so plainly." Grounding is thus a property
of the input contract, not a hoped-for behaviour.

### 2.2 Free-by-default, provider-portable backend

The copilot supports four providers behind one interface —
`("ollama", "gemini", "anthropic", "openai")` — and defaults to the two that cost
the operator nothing:

* **Ollama** (`_DEFAULT_PROVIDER = "ollama"`, in `_KEYLESS`): a fully local model
  (e.g. Llama 3.2, Qwen 2.5). Scan data never leaves the machine, and no API key
  is required.
* **Gemini**: Google AI Studio's free tier.

Anthropic Claude and OpenAI remain available for operators who have a key. Ollama
and Gemini both speak the OpenAI wire protocol, so they share one streaming code
path with a per-provider `base_url`; only the two genuinely different SDKs
(Anthropic, OpenAI-native) diverge. This makes the "free path" a first-class
citizen rather than a degraded fallback, which matters for reproducibility: the
evaluation below runs entirely on local Ollama models that any reader can pull.

### 2.3 Honest degradation

Availability is reported truthfully. `status()` performs a fast TCP check and an
`/api/tags` probe of the local Ollama server, so a provider is reported `ready`
**only** when its chosen model is actually installed and the server is up. If the
model backend is unreachable, the chat returns a real error ("run `ollama
serve`", or the upstream provider's actual HTTP error) — it never emits a
plausible-looking fake reply. This mirrors the scanner's contract: a failure is
surfaced, never simulated.

### 2.4 Small-model hardening (findings from live testing)

Testing against a real 3-billion-parameter local model (Llama 3.2) surfaced three
failure modes characteristic of small models, each fixed at the design level:

1. **Tool-happiness.** The model would call the `propose_scan` tool instead of
   answering an analytical question. Fix: the tool is *intent-gated* — it is only
   offered to the model when the operator's latest message actually expresses
   scan intent (`wants_scan()` / `_SCAN_INTENT_RE`). For "which host is most
   exposed?" the tool is simply not on the table, so the model must answer.
2. **Pseudo-tool-call text.** The model would emit JSON that *looked* like a tool
   call as its prose answer. The same intent-gating removes the temptation.
3. **CVE fabrication.** At default sampling temperatures the model invented
   plausible CVE identifiers. Three complementary fixes: (a) sampling temperature
   is pinned low (`_TEMPERATURE = 0.2`); (b) the context block now lists the
   **real CVE ids** (with severity + host) via `build_context_block`, so the model
   has genuine identifiers to cite and never needs to invent one to answer "name
   the CVEs"; and (c) a deterministic guard (`ungrounded_cves`) compares every CVE
   id in a generated summary against the ids actually in the scan and appends an
   integrity note for any that are not — so a fabricated id can never reach the
   PDF report unflagged. Feeding the real ids in was the decisive change: it took
   the 3B model's grounding from 0.80 to 1.00 (see §4.3).

### 2.5 Safe rendering

Model output is Markdown, rendered by a bespoke, escape-first
Markdown→HTML converter (`frontend/src/lib/markdown.js`) rather than a general
library. It HTML-escapes input first, allow-lists URL schemes
(`http`/`https`/`mailto`), auto-links CVE identifiers to their NVD entry, and uses
private-use-area sentinels to avoid formatting collisions. Its unit tests assert
that `<script>`/`<img>` payloads and `javascript:` URLs are neutralised. So even a
compromised or misbehaving model cannot inject active content into the operator's
browser.

## 3. Grounding guarantees, summarised

| Guarantee | Mechanism | Where |
| --- | --- | --- |
| Answers only from the current scan | Serialized scan context + system prompt | `copilot.py` `SYSTEM_PROMPT` |
| Declines when the scan is silent | Explicit "say so plainly" instruction | `copilot.py` `SYSTEM_PROMPT` |
| No unsolicited scans | `propose_scan` intent-gated | `copilot.py` `wants_scan`, `_SCAN_INTENT_RE` |
| Low fabrication | Sampling temperature 0.2 | `copilot.py` `_TEMPERATURE` |
| No fake availability | TCP + `/api/tags` readiness probe | `copilot.py` `status`, `ollama_probe` |
| No silent fallback | Real error surfaced on backend failure | `copilot.py` streaming paths |
| No active-content injection | Escape-first, scheme-allow-list renderer | `markdown.js` (XSS-tested) |

## 4. Evaluation

### 4.1 Metric

The harness `evaluation/copilot_eval.py` scores each answer on two axes against a
fixed scan fixture (a `172.16.2.0/24` result set):

* **Coverage** — did the answer mention the facts a correct answer should
  (the exposed host, the real CVE, the right service), crediting accepted
  paraphrases (e.g. "Log4Shell" for CVE-2021-44228)?
* **Grounding** — a strict binary that collapses to 0 if the answer cites *any*
  host or CVE that is not in the scan context. This is the anti-hallucination
  metric: a fluent but fabricated answer scores 0 on grounding regardless of how
  much real material it also contains.

The blended `score` is their mean. Crucially, grounding detects **novel**
fabrications — any CVE-shaped token not present in the context counts against it —
so the model cannot be rewarded for confident invention.

### 4.2 Metric sanity (`--self-test`, no model required)

Before trusting any model, the scorer is validated against two reference sets:

| Reference replies | Coverage | Grounding |
| --- | --- | --- |
| Grounded (ideal) | 1.00 | 1.00 |
| Hallucinated (adverse) | 0.00 | 0.00 |

Result: **`metric sanity: PASS`** — grounding is 1.00 for perfect answers and
0.00 for fabricated ones, confirming the metric is not gameable by fluency. This
check is deterministic and needs no provider, so it runs in CI.

### 4.3 Model-scaling results (Ollama, local, temperature 0.2)

Same fixture, same five questions, `propose_scan` intent-gated. The table shows
**before → after** the "real CVE ids in the context" fix of §2.4(3):

| Model | Params | Coverage | Grounding | Score | Hallucinated facts |
| --- | --- | --- | --- | --- | --- |
| Llama 3.2 | 3B | 0.80 | 0.80 → **1.00** | 0.80 → **0.90** | 1 → **0** |
| Qwen 2.5 | 7B | 0.60 → **1.00** | **1.00** | 0.80 → **1.00** | **0** |

**Finding.** Before the fix, grounding rose with model scale — the 7B model
fabricated zero facts while the 3B invented one out-of-context CVE. After the fix
(giving the model the real identifiers), **both models stop fabricating
entirely**: grounding is 1.00 for both and the 7B reaches a perfect 1.00 overall.
This is the key result — hallucination here was not an irreducible property of the
small model but a *grounding gap in the prompt*: the model was asked to name CVEs
it had never been shown. Close that gap and the residual failure mode becomes
*silence* on a fact (a coverage miss), never *invention* of one. For a security
tool that trade is exactly right: a missed detail is recoverable; a fabricated CVE
is not. The deterministic guard (§2.4(3)) then backstops the generated PDF summary
so that even a future regression cannot ship an unflagged fabricated id.

### 4.4 Threats to validity

Small local models exhibit run-to-run variance at temperature 0.2, so a single
run's coverage is a noisy point estimate. The harness therefore takes `--runs N`
and reports each headline metric as **mean ± 95 % CI** across N repetitions
(`run_many` / `aggregate_runs`, using the same normal-approximation statistics as
the discovery benchmark), so the reported number carries its own uncertainty
instead of hiding it. Over **five runs** of Llama 3.2 (3B) the measured headline is
**grounding 1.000 ± 0.000** (perfectly stable — zero fabrications, five times out
of five), coverage 0.760 ± 0.078, score 0.880 ± 0.039. The two *guarantees* that
are deterministic — the metric-sanity check (§4.2) and the intent-gating that
prevents unsolicited scans — do not vary run to run, and grounding is stable at
1.00 because it is enforced structurally (real ids in, `ungrounded_cves` guard
out), so the residual variance lives only in coverage. The fixture is a single
synthetic subnet; broadening it to more device types and more adversarial "trap"
questions is the natural next step.

## 5. Reproducing

```bash
# Metric is sound (no model, deterministic — CI-friendly)
python evaluation/copilot_eval.py --self-test

# Real model runs (requires: `ollama serve`, and the model pulled)
ollama pull llama3.2 && ollama pull qwen2.5
python evaluation/copilot_eval.py --provider ollama --model llama3.2 --json evaluation/results/llama3.2.json
python evaluation/copilot_eval.py --provider ollama --model qwen2.5  --json evaluation/results/qwen2.5.json

# Headline number with its uncertainty: repeat N times → mean ± 95 % CI
python evaluation/copilot_eval.py --provider ollama --model llama3.2 --runs 5 \
    --json evaluation/results/llama3.2_x5.json
```

Raw results and the scaling table are in [`evaluation/results/`](../evaluation/results/README.md).
