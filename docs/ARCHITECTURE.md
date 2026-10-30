# FALSUM architecture and execution gates

**Target:** `SECURITY_REVIEW_GENERAL` (child); `SECURITY_REVIEW` (adapter family). The [official bounty](https://github.com/telegraphprotocol/bounties/issues/96) asks for both independent preference material and a live scoring adapter. The separate five-independent-contributors pool rule is a dependency outside our sole control.

## Phase 1 — implemented

- Offline evidence-ledger schema, manual review metadata and integrity-hash field.
- Deterministic dataset-quality checks: basic provenance, duplicate IDs/negatives, answer-length balance, prompt similarity, cross-split advisory leakage, missing references.
- Explicitly gated V2-compatible JSONL triplet export for reviewed cases only.
- Python stdlib-only unit tests and GitHub Actions test workflow.

## Phase 2 — not implemented

- Real advisory snapshots with fetched source bytes and hash verification; version and deployment applicability verification; independent security review.
- Gold preference material across diverse ecosystems and realistic security tasks; train and held-out advisory group partitioning.
- Conformance with Anjoman evaluator upload eligibility and legal/ethical review of material.

## Phase 3 — not implemented

Integrate the [official V2 kit](https://github.com/telegraphprotocol/telegraph-wasm-baseline), pin its commit and dependency versions, run the upstream `--check-data`, then train LoRA reward model on `answerdotai/ModernBERT-base` with `### Task:\n<prompt>\n\n### Answer:\n<answer>` input. Evaluate on withheld advisories and compare with non-ML baselines, verify original tokenizer output and 512-token limit. Export ONNX FP32, bake WASI module, package with `go run ./cmd/adapterbuild`.

## Phase 4 — not implemented

Validate binary hash, Wasm ABI v2 `onnx_f32`/judgment class, finite inference scores, per-case and batch endpoint, public network registration and real promotion result. The scoring runtime has no live network access. A model without an eligible pool remains pending, not active.

## Phase 5 — not implemented

Transparent first-party usage demonstration, genuine network traces, reproducible setup, documentation, 2–5-minute demo, live UI after core functionality is sound.

## Honest release gates

- Never publish test-only examples as eligible material.
- No fake exploitability verdicts or unsupported severity claims.
- Do not claim model accuracy without frozen evaluation data and recorded outputs.
- Do not claim an active scorer without an explicit network result.
- Preserve a fallback target if Security Review's independent contributor requirement cannot be satisfied.
