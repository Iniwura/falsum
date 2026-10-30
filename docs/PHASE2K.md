# Phase 2k — Actual research-model pilot (quarantined)

**Objective:** For the first time, try training the **real official ModernBERT LoRA reward-model path**, not just a dummy scorer or a dataset format checker. The pilot is bounded and **NOT a submission**, and its data remain explicitly unreviewed and synthetic.

## How it runs

`.github/workflows/research-model-pilot.yml` runs on the Phase 2k push and can be manually rerun. The pipeline:

1. Fetches the same **32 GHSA advisories at an immutable commit** as earlier corpus builds.
2. Regenerates the complete quarantined dataset and verifies exact source-derived case reconstruction.
3. Builds the evidence-present prompts (published affected-version ranges included). It excludes the 32 missing-evidence controls from training.
4. Rechecks the three JSONL files against the audited corpus, refusing any split mixing, unreviewed-to-reviewed promotion, missing cases, or edited answers.
5. Checks the 52 training comparisons with the **actual official Telegraph V2 `--check-data`** command at pinned kit commit `5fa5d68bbcf76aaa2093c5d0578f53462bc0e36e`.
6. Attempts **one epoch on a GitHub-hosted CPU**, using actual `answerdotai/ModernBERT-base` and a LoRA sequence-classification adapter, with explicit validation (6 draft pairs) and separate holdout (6 draft pairs).
7. If a checkpoint exists, attempts to score the 12 counterfactual code-review challenges with `falsum.model_eval`, comparing full-context scoring against question-ablated scoring.
8. Saves raw official trainer output, true exit codes, environment dependencies, benchmark score report if produced, and any real trained checkpoint as a short-lived **RESEARCH-ONLY** GitHub Actions artifact.

The workflow has a 75-minute CPU timeout, no GPU entitlement, no model publishing, no network registration, no invented accuracy, and no secrets. A genuine upstream evaluation failure (code 1) is recorded as a research result, while tooling errors fail the workflow. A green workflow alone does **not** mean the model passed the evaluation gate. Read `result.json` and its `verdict`, and inspect the original logs.

## Why it is not a final model

- **No independent human review of training cases.** GitHub-reviewed source advisories do not imply the generated answers were independently reviewed.
- The corpus exercises relatively easy version-boundary comparison, not the real range of vulnerable pull-request changes and exploitable deployment preconditions.
- The holdout has only 6 comparisons, so it cannot establish robust generalization. The counterfactual PR set is fictional and small too.
- Training on unreviewed research material cannot make the weights suitable for Telegraph registration or claim Anjoman `eligible` status.
- The official kit uses ONNX FP32 → WASI WASM V2 for live inference, which this pilot does **not** build or publish. It establishes technical feasibility and a first real checkpoint, if the training completes.

## Required next steps

Secure independent AppSec reviews; build a substantially stronger, human-verified, source-grounded training and hidden holdout corpus; rerun training and evaluate on disjoint projects and vulnerability types; verify tokenizer context length and ONNX/WASM inference; register the artifact only after the network accepts the evaluation material and genuine test results support it.

No success is presumed before GitHub Actions produces a real model or report.
