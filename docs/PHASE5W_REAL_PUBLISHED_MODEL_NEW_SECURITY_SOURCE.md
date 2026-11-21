# Phase 5W — Genuine published-model challenge on four new original source projects

**Telegraph Protocol Season II · Evaluators / SECURITY_REVIEW_GENERAL · November 21, 2026**

## What this tests

FALSUM now has four previously unused security-fix project families with [original authenticated Git code and upstream test files](PHASE5U_NEW_PROJECT_DISJOINT_SOURCE_COVERAGE.md), plus [actual focused vulnerable→patched source execution probes](PHASE5V_ORIGINAL_FOUR_SECURITY_RUNTIME_REVERSALS.md).

The next outstanding question was whether a genuine external author-published model could correctly adapt its answers when original code changed. **Phase 5W actually runs the original published Qwen2.5-0.5B-Instruct model** against all 24 newly authenticated project-disjoint security source conditions.

This is a factual evaluation, **not a trained FALSUM model or proof of better Telegraph miner selection**.

## Exact frozen protocol

The model choice was frozen **before running any Phase 5W model inference** in [the Git-blob-pinned preregistration](../data/phase5w-preregistered-published-model-new-source.json). Original preregistration Git blob SHA-1: `c8ce938f914ec8c1c481ff193d6c3db98aa86ed0`.

- Model: [Qwen2.5-0.5B-Instruct](https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct).
- Original immutable publisher Git revision: `7ae557604adf67be50417f59c2c2f167def9a775`.
- Original model weights `model.safetensors` SHA-256: `fdf756fa7fcbe7404d5c60e26bff1a0c8b8aa1f72ced49e7dd0210fe288fb7fe`.
- Runtime: pinned CPU-only PyTorch, Transformers, Hugging Face Hub, tokenizers, safetensors. Greedy decoding. No few-shot examples. 12-token output ceiling and 1,024-token input ceiling; oversized source inputs fail, never truncate silently.
- Question source: exact 24 public original Git-source conditions from Phase 5U, including **16 source-present questions** and **8 source-omitted controls**, with code revision and answer-option position counterbalanced.
- Primary outcome: how many of the **four complete affected/fixed plus answer-position reversals** are correct. Report separate source-present reference matches and no-source abstentions. Retain the **raw unedited completions**, even if every response is incorrect or ABSTAIN.

## Three comparisons

| Candidate | Evidence type | Expected score before inference |
| --- | --- | --- |
| Original published Qwen 0.5B | Genuine model execution; original weights fingerprinted; 24 forward passes | **Not assumed**; require successful actual CI and inspect outputs |
| Prompt-only source-blind answer slot control | Disclosed synthetic deterministic baseline | Mathematically 16/24 reference matches, 0/4 full reversals |
| Always ABSTAIN | Disclosed synthetic deterministic baseline | 8/24 reference matches, 0/4 full reversals |

The deterministic source-blind 16/24 bound applies only to a **prompt-only method with the source masked**, not to an attacker who can find public Git history or this casebook.

The previously verified Qwen2.5-0.5B model did poorly on a different historical four-project benchmark. This phase does not presuppose improvement; it measures performance on **genuinely new project examples**, with results preserved even if worse than either control.

## Reproduction

This stage runs through [the original model evidence GitHub Actions workflow](../.github/workflows/phase5w-real-new-source-publisher-model.yml). It downloads all **16 upstream source and test Git file versions**, verifies their exact original SHA-1, then downloads and checks the publisher model weights SHA-256 and runs 24 actual CPU forwards.

~~~bash
# Inside the repository, with original pinned CPU-only model dependencies installed:
PYTHONPATH=src python -m falsum.phase5w_original_new_source_model infer \
  --out original-24-qwen-completions.json

PYTHONPATH=src python -m falsum.phase5w_original_new_source_model audit \
  --raw original-24-qwen-completions.json \
  --out original-24-qwen-source-score.json
~~~

The verifier checks exact original source-challenge SHA, model publisher/revision, model weight hash, 24 model response records, order, parsing and raw output tokens. **The report's own metadata cannot cryptographically attest model execution on its own**; the independently inspectable GitHub Actions CPU job and preserved original artifact are the practical evidence of real execution. The local unit tests use clearly labelled synthetic prediction envelopes to validate refusal of forged metadata and **are not** evidence of a genuine forward pass.

A report can only be created at a previously unused file path, without overwriting the raw completions. Code or prompt changes after preregistration are not permitted without an openly declared new study version.

## What the result cannot prove

- These cases use authentic, *publicly known* historical source facts and a researcher-authored reference answer key. They are not private hidden holdout or independent qualified AppSec expert ground truth.
- Phase 5V's separate isolated probes **actually ran the eight original historical code revisions**; Phase 5W does **not** rerun entire upstream project test suites.
- A model matching references is not proof of deployment exploitability or universal program safety.
- A difference against a synthetic baseline is not automatically a gain in Telegraph's live miner selection, ranking or revenue. No registered network evaluator, new paid request, outside developer adoption or trained model is implied.
- Model failure is a meaningful negative diagnostic. Never claim a higher model score or FALSUM training improvement without independently supported evidence.

**Phase 5W release gate:** only claim numerical genuine model results after all three offline-contract suites and the real publisher-inference job successfully complete. No official hackathon submission or demo is made by this phase.

## Actual original model outcome verified

[**The genuine original GitHub Actions inference run**](https://github.com/Iniwura/falsum/actions/runs/44903712350) completed successfully across **all four jobs** (Python 3.11, 3.12, 3.13 contract validation and the actual 24-pass immutable Qwen CPU runner).

| Method | Matches to author-derived public reference /24 | Source-present /16 | No-source abstention /8 | Complete source + answer-position reversals /4 |
| --- | ---: | ---: | ---: | ---: |
| **Genuine original Qwen2.5-0.5B-Instruct** | **8** | **0** | **8** | **0** |
| Disclosed synthetic prompt-only source-blind baseline | 16 | 8 | 8 | 0 |
| Disclosed synthetic always-ABSTAIN baseline | 8 | 0 | 8 | 0 |

**All 24 original model raw completions were exactly `ABSTAIN`.** That includes the 16 conditions where the actual original Git source was present. It is a **negative result** for model source reasoning, and **eight matches fewer than the disclosed 16/24 source-blind synthetic control**. It does not demonstrate model improvement. The primary complete four-way source/option reversal metric is 0/4 for every method.

The result is reproducible with the original model publisher revision and the entire original raw completion artifact; no outputs were selectively discarded or reinterpreted as a positive.

- Original Actions artifact ID: **14707515234**.
- Original artifact ZIP SHA-256: `b073487d6b7990460f4795f80f427d5a31d9aad934456563f6ffda1c1d571673`.
- Original 24 raw completions JSON SHA-256: `42c4ba407d34e40bc9f51d9916aac80ea3f38bd401726774950d7143dac293af`.
- Original model diagnostic JSON SHA-256: `13ba0f26fee41519f5482a601ab47b9161494577b8b8ba3ce70f54ddc2f9cda2`.
- [Permanent measured original evidence index](../evidence/phase5w-2026-11-21-real-qwen-new-security-source-failure.json).

**Judge interpretation:** This source-sensitive evaluation material reveals that a genuine small published model can achieve credit for eight missing-source abstention conditions while learning nothing from the 16 source-provided revisions. The stronger claim is the reproducible detection of the limitation and a falsifiable four-way test, *not* superior model accuracy or live network ranking improvement. The original public source/expected answers remain author-selected, not independently certified AppSec gold.
