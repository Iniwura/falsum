# Phase 5M — An executable source-sensitive candidate challenge, with honest model-artifact limits

**Telegraph Season II · Evaluators · SECURITY_REVIEW_GENERAL · 20 November 2026**

## The experiment FALSUM froze before attempting inference

The six-stage real upstream source-test witness chain now includes a *fifth distinct source project* with a new-to-FALSUM-original-model path-guard regression: **facelessuser/pymdown-extensions**.

The original repository's [real upstream stage replay](https://github.com/Iniwura/falsum/actions/runs/44716279199) passed seven jobs (six real pytest executions, one exact source/test/log hash aggregation). For each Python 3.11 and 3.13, its original parent control PASSED, the maintainer-authored security test against the vulnerable parent FAILED for the expected missing exception, and the exact same upstream test on the fixed commit PASSED.

Phase 5M precommitted a short source-sensitive test in standalone commit **5c15c4aaaa66829d543d47354362d66169b595ff** *before the new scoring code or model runtime existed*. Its [frozen original source/model/question protocol](../data/phase5m-preinference-original-lora-pymdown-source-sensitivity.json) has Git blob SHA-1 **b50c6e1ad386f4bbf2faa7dd15ddba35b860f9b3**. The protocol pins the unchanged source pair and original quarantined Telegraph Foundation model SHA-256 **3d269cc080538b6a13ae8e5fbb8526921ffe9689c1a6f62f9a6161a9d4680fbc**.

The test compares the same two possible answers against the *exact original path-guard code* in each historical commit, with no explicit "vulnerable" or "fixed" stage name in the model's task. A third condition omits the source code entirely; it is an **abstention-calibration control**, not a security verdict with independently verified gold.

| Factual condition | Original code guard | Research source fact |
| --- | --- | --- |
| Commit 3d185501… | Raw string prefix only | Sibling path sharing prefix can slip through |
| Commit 63b78357… | Prefix plus directory-separator boundary | Sibling path rejected |
| Code not provided | No guard available | Evidence is insufficient; abstain |

The code-and-answer wording, frozen source Git commits and expected source facts were declared **before** scoring. The public historical code could exist in pretrained corpora and is therefore **not a sealed, blind or statistically valid generalization test**. One source repair is insufficient for a model-performance claim.

## Real model inference blocker — never substitute a different checkpoint

The original model's earlier real scoring results remain **5/8 provisional source-fact matches with only 1/4 complete source reversals**, not independently adjudicated gold. The old research-only LoRA was never registered, and no improved trained model has been built in Phase 5M.

**Actual Phase 5M attempt:** original source verification and synthetic adversarial input tests ran. The real unchanged LoRA execution could not proceed because the original [Phase 3B GitHub Actions artifact from run 41304788714](https://github.com/Iniwura/falsum/actions/runs/41304788714), containing the required 6.8 MB exact safetensors checkpoint, is no longer available through GitHub's artifact listing or download interface. The older original Phase 2U model artifact from run 41283929744 is also unavailable. The original model package is not present in the public repository or releases.

The **official real inference is therefore NOT verified**, and no Phase 5M neural score, correctness claim or trained-model gain can be reported. Later Phase 4H score reports retain real historical float32 observations but not the original reusable model weights.

[Source-sensitive original-model scorer](../src/falsum/phase5m_real_source_sensitive_model.py) contains the real tokenizer/source identity and official manifest/score safeguards. The [CI model-availability gate](../.github/workflows/phase5m-original-model-source-sensitivity.yml) retrieves the old artifact listing on every relevant run. It **only runs the six genuine Foundation ONNX/WASI score inputs when the exact original checkpoint is available**, otherwise publishes a machine-readable unavailable status and marks the actual inference job skipped. A green source/availability workflow must not be described as a completed neural run.

This is a blocked optional research experiment, not a release requirement for the public evidence-material path. No new model was substituted. Restoring the identical checkpoint would permit a repeat without changing the frozen protocol.

## Useful work that DOES run without any model API, credentials or checkpoint

The new [public original-source context evaluation CLI](../src/falsum/phase5m_source_context_candidate.py) lets an outside developer or separate evaluator submit **actual A / B / ABSTAIN decisions** on three public, source-grounded questions. Two conditions contain the original upstream guard from the historical source; one intentionally omits source evidence. Question labels are opaque, all answer options are identical across revisions, and the exported challenge excludes the reference answers and revision *role*.

The script validates a candidate's exact challenge SHA-256, exact three unique IDs and order, allowed answer classes, optional short rationale, and no injected gold/registration claims. It regenerates the reference from FALSUM's precommitted source protocol and the authenticated original test lock. It reports:

- Exact match against the **researcher-constructed open-book source facts**, separately from qualified human accuracy.
- Both correct source-revision decisions and complete changed-fact A-to-B reversal.
- Whether a candidate abstains when there is no source code.
- Three-class confusion matrix and simple constant-answer baselines.

There is **one reference of each class** in this *tiny diagnostic*. Always-A, always-B and always-ABSTAIN each match exactly **1/3**, with **zero full parent-to-fix reversals**. These deterministic baselines are not models or human external validations. No candidate's predictions have been received merely because the harness and sample test fixtures are working.

### Use the installed CLI

Python 3.11+, no wallet, model key, paid API or third-party secret:

~~~bash
git clone https://github.com/Iniwura/falsum.git
cd falsum
python -m pip install --no-deps -e .

# Export public source questions and a blank response file:
falsum score-source-context export \
  --questions-out source-context-questions.json \
  --template-out my-real-predictions.json

# Honest, simple source-blind controls:
falsum score-source-context baseline \
  --strategy always-ABSTAIN \
  --out always-abstain-result.json

# After you run your own model/reviewer, fill each null 'choice'
# with A, B or ABSTAIN and optionally explain why.
falsum score-source-context score \
  --predictions my-real-predictions.json \
  --out my-model-source-context-score.json
~~~

Blank answer fields are intentionally **not scorable**. All reports are write-once. When given a filled caller file, the scorer identifies it as **external *unverified* candidate predictions**, not as an independent expert assessment or proof of ML model improvement. Exact reference correctness on three public authored questions cannot establish security-review generalization. A separate model test must authenticate the specific candidate's actual runtime/model SHA and inputs if it wants to claim real inference.

The [adversarial tests](../tests/test_phase5m_source_context_candidate.py) and [public-scoring CI](../.github/workflows/phase5m-public-source-context-scorecard.yml) check forged candidates, altered prompt/file identities, incomplete exports, source-omitted unsupported confidence and the unambiguous constant baselines.

## Strict judge-facing interpretation

Phase 5M is a *reproducible evaluation-material interface* on an extra original upstream source repair. It allows a real developer to compare model responses against source/test evidence **with an explicit missing-evidence condition**. It is not a new network evaluation pool, trained evaluator adapter, verified third-party model submission, independent AppSec gold label, new Anjoman Eligible row, production exploit, expanded five-source web UI, or official H2 final entry.

The genuinely valuable next scientific experiment is to run **multiple independently selected source-project-disjoint cases with a frozen, actually available candidate model** and independent source adjudication, report conditional coverage and weaknesses, and compare against source-blind and explicit-evidence baselines. Do not turn a short script, one public fix, or a zero-model-score CI run into a winning-accuracy claim.

**No demo, outgoing social post, model registration, wallet action or hackathon submission has been made.**
