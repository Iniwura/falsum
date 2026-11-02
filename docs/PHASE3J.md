# Phase 3J — Original real model scored against two known historical runtime families

**Purpose:** Determine, with genuine official Telegraph Foundation runtime scores, whether the **existing unchanged** FALSUM ModernBERT LoRA responds appropriately when a security-relevant historical framework fact changes. This is a *diagnostic experiment*, not a new trained model, blind evaluation set or official scoring contribution.

## What is frozen

The real environment evidence was independently produced by two GitHub Actions workflows:

- [Phase 3H installed Starlette 0.26.1 vs 0.27.0](https://github.com/Iniwura/falsum/actions/runs/41409503521): historical same-prefix sibling static file returned 200 in 0.26.1 and 404 in 0.27.0. Three negative/normal controls remained unchanged.
- [Phase 3I installed Requests 2.30.0 vs 2.31.0](https://github.com/Iniwura/falsum/actions/runs/41410209502): historical credentialed HTTPS `rebuild_proxies` added a proxy auth header before the fix, and did not after; four synthetic controls remained unchanged.

Both comparisons are already publicly studied. They are **not project-disjoint, untouched blind holdouts**. The task and better-answer expectation are authored from known runtime observations and have **no independent human expert adjudication**.

For each library, Phase 3J fixes two candidate response strings byte-for-byte and asks two context questions, one historically affected and one patched. If the reward model is responding to the relevant fact rather than generic wording, its preferred answer should reverse when the version and observed behavior change. Eight exact input strings are tokenized using the SHA256-verified official Foundation tokenizer. Input/question/answer fingerprints, model package SHA256, and engine SHA256 are validated before scoring.

## Actual model experiment

The [Phase 3J workflow](../.github/workflows/phase3j-real-model-two-families.yml) uses the official Telegraph `telegraph-wasm-baseline` toolchain pinned at `1ed063e2f0066cfaf0e124d66ec6a17b7a6121fd`, downloads the unchanged original **rank-8**, 6.8 MB FALSUM model from the successful Phase 3B experiment, verifies its SHA256 `3d269cc080538b6a13ae8e5fbb8526921ffe9689c1a6f62f9a6161a9d4680fbc`, then loads the official 599MB shared Foundation ONNX and WASI engine. It calls genuine `adapterbuild lora` eight times with **two repeated inferences** per input, recording exact float32 model scores and per-context preference margins. Results are compared with the runtime-derived *provisional* preference and summarized even if they fail: the CI is required to preserve negative observations.

The Phase 3D model previously **failed both** aiohttp fact-reversal families. Phase 3J tests whether that failure extends to Starlette and Requests in the *unchanged model*. Phase 3J does **not** correct the old model, does **not** update training data, and cannot independently prove generalizable model judgment.

## Research and safety gates

- The source runtime evidence record, exact upstream fix identity, observed behavior and no-label status must match unchanged source files.
- Candidate answers are byte-identical within each family across contexts; fabricated improvements by rewriting the candidates per task fail checks.
- Missing, malformed, duplicated, non-finite, or tampered official runtime scores fail authenticity checks.
- Positive or negative model preferences are recorded as observed; a failure is never hidden by a green *evidence collection* CI run.
- No actual exploit, real credential, third-party application, private source or live network security test is involved.
- **Independent human labels: 0. Accepted Anjoman rows: 0. Registered evaluators: 0.** Even 2/2 observed reversals here would not permit registration; the original Phase 3D release veto stays binding.

## Reproduction

Offline input and output contract tests (do not require downloading the 599 MB Foundation):

```bash
PYTHONPATH=src:tests python -m unittest discover -s tests -p test_phase3j_model_diagnostics.py -v
```

The complete model run is specified and pinned in [the Phase 3J Actions workflow](../.github/workflows/phase3j-real-model-two-families.yml), including the official runtime and model file identities. The full generated tokenizer-input and score artifacts are uploaded to GitHub Actions for review. Those temporary artifacts and CI run summaries, **not local test mock scores**, are the evidence for real inference.

## Actual verified result — 2 November 2026

[**Successful real model scoring CI**](https://github.com/Iniwura/falsum/actions/runs/41411984601) loaded the original SHA-verified LoRA on the official Foundation. Eight distinct inputs were each scored twice; **16 actual inferences** produced reproducible float32 score bits. [Permanent run-by-run evidence](../evidence/phase3j-2026-11-02.json) preserves all eight scores and the computed margins. The model scored correctly in only **2/4 researcher-provisional contexts** and **failed both 2/2 expected preference reversals**:

| Known family | Actual model preference in affected context | Actual model preference in patched context | Correctly reverses? |
| --- | --- | --- | --- |
| Starlette static-file containment | Outside-path exposed (matches observation) | Outside-path exposed (contradicts patched observation) | **No** |
| Requests HTTPS proxy authorization | Auth absent (contradicts affected observation) | Auth absent (matches observation) | **No** |

These are **real model measurements**, not unit-test mock scores. Green CI means the original model ran and the measurements are authentic; **the observed model judgment is poor**. This confirms the original Phase 3D 0/2 counterfactual weakness across two additional previously studied libraries. **Do not register this LoRA**; no independent expert-reviewed labels, verified blind holdout, accepted Anjoman rows or live evaluator registration exist at this checkpoint.

## The next decision

- If the original LoRA again fails counterfactual reversals, retire or retrain that checkpoint instead of polishing more static verification infrastructure.
- If it reverses both, the next prerequisite is still an **untouched, project-disjoint evaluation**, independent expert adjudication, accepted Anjoman evaluation material and the protocol's registration checks.
- In neither outcome may this run alone be described as accuracy certification, production readiness or a hackathon-qualified submission.
