# Evidence availability benchmark (pre-model validation)

**Status: research-only, draft, unreviewed, no model trained and no network submission.**

## Critical failure discovered

Earlier generated tasks included a GHSA number and package version but **did not provide the actual affected-version boundaries**. A model trained on those tasks would have to memorise advisory IDs or guess. Passing the upstream shortcut-quality gate does not repair missing task evidence. This update retains the original research corpus for reproducibility but adds a second evidence-present benchmark suitable for testing conditional reasoning.

## What changed

Run the existing source acquisition, then ground each pair in the actual pinned OSV advisory bytes:

```bash
PYTHONPATH=src python -m falsum.advisory_corpus data/advisory-queue.json --out /tmp/falsum-research
PYTHONPATH=src python -m falsum.grounded_eval data/advisory-queue.json \
  /tmp/falsum-research/DRAFT-ONLY-corpus.json --out /tmp/falsum-grounded
```

The new builder first calls `audit_reproducibility` to verify *every original case* against original source bytes. For each task it then publishes the relevant OSV `introduced` and `fixed` events, explicitly identified as affected-version metadata and **not** proof of deployment exploitability. It preserves all original chosen/rejected labels and split groupings. Multiple stable, contiguous event ranges are included; unsupported syntax, missing source snapshots, unknown statuses, complex/reordered events, or ambiguous/oversized evidence cause a hard failure rather than invented labels.

`DRAFT-grounded-train.jsonl` contains 52 source-present triplets, while validation and holdout each contain 6. There are also 32 separate *missing-evidence controls*, one per advisory. These ask whether a positive finding can be justified without the underlying range; they are **diagnostic controls**, not a normal train/export split.

The present-source benchmark can be checked with Telegraph's pinned V2 `--check-data` in GitHub Actions. A passing style/length gate is not a training-success or judgment-accuracy result. In particular, the pair answers still use a restricted `inside` / `beyond` formulation rather than realistic full security reviews.

## Real scoring protocol

`falsum.grounded_eval.evaluate_scores(rows, scores)` receives *actual model scores* as `{case_id: (chosen_score, rejected_score)}` and fails closed for missing IDs and non-finite values. It reports a pairwise accuracy by independent train/validation/holdout split, counting ties as 0.5. No score values are invented, and the harness reports no accuracy without real scores. Keep holdout adversary/source groups untouched during training and tuning.

A trustworthy pre-submission scorecard must include a model identity and weights digest, exact tokenizer and 512-token truncation, a frozen corpus digest and independent reviewer dispositions, baseline comparison, per-split metrics, and error analysis including missing-evidence controls. The official live evaluator needs ModernBERT LoRA → ONNX FP32 → WASI WASM plus actual node ranking; the Python diagnostics here are **not** a supported Telegraph runtime.

## Current blockers to winning

1. **Independent experts must review the gold cases.** GitHub-reviewed advisories do not constitute independent evaluation of our preference pairs.
2. **Get realistic PR tasks** with code diffs, dependency manifests, exploit preconditions and secret/configuration evidence. Artificial lockfile tasks alone cannot establish useful rankings.
3. **Train and benchmark ModernBERT**, compare with controls, verify tokenizer/conformance, package ONNX FP32 WASM, test batch scorer, and demonstrate real onchain acceptance.
4. **Source-absent hallucination traps** need genuine expert labels and should be scored independently from source-present cases.
5. **Security Review pool activation** still depends on genuinely independent eligible contributors; no fake voters or wallets.

No new model, independent review, or accepted pool is implied by this repository change.
