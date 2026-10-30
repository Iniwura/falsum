# Phase 2g — Ground-truth integrity and independent blinded review

**Status: implemented, but not reviewed, trained, submitted, or registered.**

The prior gate established that 52 generated version-boundary pairs could clear Telegraph's *shortcut* detection. That does **not** mean they represent realistic security review quality or that any answers were independently verified. This phase fixes a specific integrity weakness and creates a review process that can collect genuinely independent judgments.

## 1. Reconstruct every pair from immutable source bytes

The previous validator checked that source checksums matched and that a package version was classified correctly. It did **not** reject a malicious edit to an answer's wording, a reversed chosen/rejected pair, a modified prompt, an altered source URL, or a missing case. `falsum.review_gate.audit_reproducibility` now regenerates all 64 rows from the original research queue and SHA-256-verified GHSA snapshots, then compares the complete output including the draft status, source references, case ordering, splits, and all answers.

Reproducibility is a *data-integrity* guarantee, **not** a claim that the upstream advisory has been independently confirmed or that the answer is suitable for the real network.

## 2. Blinded review packets

Run after obtaining or regenerating the pinned corpus:

```bash
PYTHONPATH=src python -m falsum.review_gate data/advisory-queue.json \
  /path/to/DRAFT-ONLY-corpus.json --audit-only

PYTHONPATH=src python -m falsum.review_gate data/advisory-queue.json \
  /path/to/DRAFT-ONLY-corpus.json \
  --reviewer-out /tmp/falsum-review-questions \
  --private-key-out /tmp/falsum-private-answer-key
```

Share **only** `/tmp/falsum-review-questions/`, never the private key directory. A fixed hash of each case ID assigns the correct answer to A or B, so reviewers cannot assume A is better. They must independently inspect the primary source at its pinned URL and record their source quote, explanation, identity, and review date. They may mark a case *uncertain*. This packet does not automatically endorse reviewer identity, accept responses as true, or promote any draft row to reviewed.

Both directories must be separate and located **outside** the source corpus directory. Existing nonempty output folders are refused rather than silently overwritten. Private answer keys are not committed or uploaded to the public repository or CI artifacts.

## 3. CI gate

The GHSA research workflow now executes the deterministic reconstruction audit against the *actual* 32 downloaded, pinned advisory files, not just mocked fixtures. The official Telegraph V2 shortcut gate remains a separate check. The GitHub Actions test matrix also runs adversarial tests to verify that forged pairs and missing material fail closed.

## Remaining competitive blockers

- **Human accuracy:** independent reviewers must audit exact advisory context, affected versions, claim qualification, and plausible alternative answers. No independent reviews recorded.
- **Realistic security tasks:** the generated corpus currently consists of invented dependency lockfiles; it has no verified, realistic multi-file PR security-review responses or operational secret/misconfiguration cases.
- **Held-out power:** the current 6 validation and 6 holdout pairs are too small to justify a competitive accuracy claim; review groups must remain independent.
- **Tokenization:** the actual ModernBERT token limit is 512 tokens. Tokenizer conformance and feature truncation have not yet been tested against the final reviewed corpus.
- **Live model:** no ModernBERT checkpoint, ONNX FP32 export, WASM artifact, evaluator endpoint, onchain registration, active pool, or network acceptance has been demonstrated.
- **Contributor pool:** enough *genuinely independent* eligible contributors remain an external dependency; no fabricated identities or multiple wallets should be used to bypass this.

**Decision:** Do not train or submit the model merely because an artificially generated draft dataset clears length/lexical shortcut checks. First obtain credible review and real-world evaluation examples.
