# Phase 2L — What the first REAL model learned (30 October 2026)

## Reproducible evidence

- [Completed official CPU training and actual model-scoring run](https://github.com/Iniwura/falsum/actions/runs/41124535661)
- Training source revision: `f8f9d57dc9dbb02b9069193d252d27ee1bcdc9a7`
- Training pipeline: pinned official Telegraph V2 kit at `5fa5d68bbcf76aaa2093c5d0578f53462bc0e36e`
- Architecture: `answerdotai/ModernBERT-base`, real trainable LoRA adapter, one CPU epoch
- Training set: 52 research-only GHSA answer preferences; 6 validation and 6 separate test comparisons
- All labels are automatically constructed, **not independently AppSec reviewed**.
- Research artifact `QUARANTINED-FALSUM-MODEL-RESEARCH-NOT-SUBMITTABLE`, 7-day retention (expires 6 November 2026). The actual checkpoint contains `adapter_model.safetensors`.
- Adapter file-manifest SHA-256 (files, not training provenance): `e9c186616c301f4dc9094864fab1a9c98cd20e46a7df3256fcf2ead38d6cb30d`

## Measurements

| Evaluation | Correct | Total | Measured |
| --- | ---: | ---: | ---: |
| Official V2 trainer's held-out synthetic version-range pairs | 5 | 6 | 83.33% (upstream `PASS`) |
| FALSUM full-context draft PR training partition | 3 | 6 | 50% |
| FALSUM full-context draft PR validation partition | 1 | 4 | 25% |
| FALSUM full-context draft PR holdout partition | 2 | 2 | 100% |
| Same model, answer-only validation ablation | 2 | 4 | 50% |
| Same model, answer-only holdout ablation | 1 | 2 | 50% |

The two PR contexts of each rule family reuse **exactly the same candidate answers** with reversed correct labels. A scorer must attend to the actual PR context, rather than the apparent quality of the answer, to get both right.

**Both contexts correctly ranked: 1/6 rule families.** The sole fully correct family was `node-tls-validation` (holdout). The other five failed at least one context: `django-debug`, `django-secret`, `ssrf-redirect`, `github-token`, `github-secret`.

The holdout covers only ONE PR family (two cases). Its nominal 100% score is not evidence of deployment robustness. The 83.33% upstream number measures a DIFFERENT, narrow, source-grounded comparison task, and cannot substitute for real repository security review.

## What Phase 2L adds in code

`src/falsum/pilot_decision.py` consumes three raw, actual run documents: the official trainer's `result.json`, the genuine `COUNTERFACTUAL-MODEL-RESULT.json` and the training dataset's audit manifest. It checks the intent and split lineage; the official test count; finite raw model scores; per-case versus aggregate accuracy; exact two-context family accounting; answer-only ablation counts; and artifact SHA-256 declaration. Contradictory or missing evidence is rejected.

The output is deliberately and permanently **`BLOCKED_RESEARCH_ONLY`**, even if a future research pilot scores perfectly. It refuses to confuse an upstream data-quality PASS, the adapter's local file digest, or speculative labels with human validation, eligibility, ONNX/WASM execution, or registration permission.

The Actions workflow now generates and archives a `PILOT-DECISION.json` report when both model results exist. If training says success but the real scoring report is missing, the job fails instead of advertising a misleading green run. Offline unit tests probe adversarially mutated metrics and quarantine flags.

## Actual next experiments

1. **Get independent AppSec reviewers** to evaluate a diverse source-grounded corpus. Do not automatically promote the fictional PR cases or claim verified correctness.
2. Train on verified *context-sensitive* security decisions from training-only repositories. Freeze case family, project, and source boundaries before training; do **not** insert validation or holdout examples into training.
3. Evaluate the same unchanged, separate PR challenge plus a materially larger, independently reviewed holdout. Record wrong-way counterfactual flips, number of family pairs correct, and answer-only control performance.
4. Only after credible task accuracy and external data verification, export the model through the official ONNX FP32 → WASI WASM V2 path and validate end-to-end node inference and Telegraph eligibility.

This phase proves a REAL model can be trained using the official pipeline **and** that its security-review generalization is currently weak. It does not prove a valid network evaluator.
