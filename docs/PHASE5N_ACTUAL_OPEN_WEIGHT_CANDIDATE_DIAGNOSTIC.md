# Phase 5N: Real published model against frozen original upstream source evidence

**Telegraph Season II · Evaluators · SECURITY_REVIEW_GENERAL · November 20, 2026**

## Goal and honest scope

FALSUM has six verified original upstream security repair-test stages across five original projects. The original quarantined ModernBERT/Telegraph Foundation LoRA failed its recorded source sensitivity study (5/8 provisional source facts, 1/4 correct pair reversals), and its original stored checkpoint has expired. Phase 5N does not retrain or substitute that original model.

The new experiment uses an independently published, open-weight **Qwen/Qwen2.5-0.5B-Instruct** model, operated by FALSUM's own GitHub Actions, to answer the exact three already-frozen Phase 5M public source-context questions. The model is authored by an unrelated publisher, but its inference is **researcher-operated, not independently adopted or externally submitted**.

Source reference: [real pymdown-extensions historical upstream regression](https://github.com/Iniwura/falsum/actions/runs/44716279199). Six genuine upstream original Python regression processes and an aggregate source/test/commit-log check passed.

## Actual verified result: the small model failed source-sensitive judgment

[Successful original 20 November 2026 model execution](https://github.com/Iniwura/falsum/actions/runs/44739535866) loaded real published Qwen/Qwen2.5-0.5B-Instruct weights at immutable revision 7ae557604adf67be50417f59c2c2f167def9a775, with safetensors SHA-256 fdf756fa7fcbe7404d5c60e26bff1a0c8b8aa1f72ced49e7dd0210fe288fb7fe. Raw outputs and actual source scoring are preserved in [original artifact 14629742992](https://github.com/Iniwura/falsum/actions/runs/44739535866/artifacts/14629742992), ZIP SHA-256 fc3ba6c1a36fe2373d40637bb59ed3968b318ed2ca7035a5bbb45515168af1da.

The **actual answers were ABSTAIN, ABSTAIN, ABSTAIN**. The model gave three parseable choices, but achieved only **1/3 researcher-defined public source-reference matches**, **0/2 source-provided fact matches**, **0/1 correct parent/fixed source reversal** and correctly abstained on the one source-omitted condition. It therefore **did not beat the constant-ABSTAIN baseline (1/3)** on this particular public exercise. Negative results are reported without retuning the frozen prompt. This is real researcher-operated inference, not independently submitted third-party adoption, independent expert gold, or evidence of improvement.

[Permanent evidence index](../evidence/phase5n-2026-11-20-real-open-weight-model-negative.json) records the original GitHub Actions provenance, ZIP/file digests, exact original model revision and all three raw answers. One publicly known repair and a constructed source-reference key do not establish general security model accuracy, whether positive or negative.

## Preregistered before inference

[Original Phase 5M source-question protocol](../data/phase5m-preinference-original-lora-pymdown-source-sensitivity.json) Git blob SHA-1: b50c6e1ad386f4bbf2faa7dd15ddba35b860f9b3. No source question, historical revision, answer text or reference label was changed for the new model.

Separate [Phase 5N model-selection, instruction and inference policy](../data/phase5n-published-small-model-prediction-protocol.json) was committed in [aad0cac9e2bdb89ab395d2bb5d8398f62bc27016](https://github.com/Iniwura/falsum/commit/aad0cac9e2bdb89ab395d2bb5d8398f62bc27016) BEFORE any inference. Lock Git blob SHA-1: dddd564b4276c4f4ee7f60058594eda1d7cfbbae. It freezes:

- Original three public prompts: vulnerable parent code, original fixed code, and deliberately absent code.
- The published model identifier Qwen/Qwen2.5-0.5B-Instruct, with no FALSUM training or prompt tuning.
- CPU-only standard transformers inference, trust_remote_code=False, safetensors-only model, deterministic greedy generation, maximum 12 tokens, input cap 1024.
- Resolve the published model's current immutable 40-character Hugging Face revision before downloads; fetch all files at that exact SHA, record per-file model/tokenizer/config SHA-256.
- Exact expected response format A, B or ABSTAIN; preserve any invalid response as INVALID and count it wrong. Never coerce guesses or unparseable text to expected answers.
- Original public research-source reference labels, not independent human expert gold. Zero verified third-party developer adoption, network registration, new eligible rows or official H2 submission.

## Reproduce actual model scoring

The [Phase 5N workflow](../.github/workflows/phase5n-published-model-real-predictions.yml) runs source/protocol/forged-evidence tests under Python 3.11–3.13. A separate CPU job installs pinned packages, downloads and loads the real published weights, generates three genuine responses, audits every raw completion and archives model and inference evidence.

Commands for the real test (with CPU PyTorch, transformers, huggingface_hub, tokenizers and safetensors installed):

~~~bash
PYTHONPATH=src python -m falsum.phase5n_published_candidate_runner prepare --out frozen-inputs.json

PYTHONPATH=src python -m falsum.phase5n_published_candidate_runner execute --inputs frozen-inputs.json --out actual-completions.json

PYTHONPATH=src python -m falsum.phase5n_published_candidate_runner audit --inputs frozen-inputs.json --actual actual-completions.json --out actual-model-report.json
~~~

The runner uses write-once files, verifies the original source-task SHA and model-choice lock, and rejects missing or forged claimed real model outputs. Passing synthetic unit tests alone **does not prove any model was loaded or scored**; cite the actual GitHub-hosted inference job and its archived model outputs.

## Measure all failures, including invalid replies

The report includes every raw model response, selected answer or INVALID, exact immutable model commit, per-model-file SHA-256, source-fact matches (0–2), complete code-revision reversal, abstention on the source-omitted case, and constant A/B/ABSTAIN baselines (1/3 each by construction).

Even a perfect three-question result would not prove security-model generalization. There is only **one openly published source repair** with **researcher-constructed** gold-like reference labels, and public source/model information can be exploited by simple shortcuts. A model authored by an outside provider and run by FALSUM does **not** count as independent developer consumption, external integration, trained Telegraph evaluator improvement, expert adjudication or proof of ranking quality.

This is a public evaluation-material diagnostic. It is NOT a new registered Telegraph model, a network-sourced evaluation mission, third-party adoption, an accepted Anjoman contribution, official submitted H2 entry, or hackathon award. The original LoRA remains unchanged and unavailable; no demo was started.
