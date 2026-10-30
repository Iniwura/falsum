# Phase 2e — upstream-gate preflight and corpus readiness

## Verified contract

The official [Telegraph V2 training kit](https://github.com/telegraphprotocol/telegraph-wasm-baseline/tree/5fa5d68bbcf76aaa2093c5d0578f53462bc0e36e) is pinned to `5fa5d68bbcf76aaa2093c5d0578f53462bc0e36e` for the diagnostic CI job. Its source file `wide_runtime/train_adapter.py` defines the following actual initial data gate:

- Any one rejected answer may not be more than **2%** of training rows. Even with all distinct negatives, fewer than 50 rows necessarily fail.
- At least 80% unique rejected answers and at most 1% identical chosen/rejected pairs.
- Prefer-the-longer-or-shorter-answer baseline must be at most 65%.
- Rejected-answer training/evaluation leakage must stay within 10%.
- The official gate tests answer-only surface/style discrimination at most 65%; this needs NumPy and is **not** reproduced in the local stdlib-only preflight.

The local preflight is an *early-warning mirror*, not a substitute for running `--check-data`. Only the CI job runs the genuine gate. The gate can still pass on low-quality data; its thresholds are necessary, not sufficient.

## Current measured state

- **12 hypothetical, draft-only application-security comparisons.** Six are assigned to `train`, four to `validation`, two to `holdout`.
- Four curated security-guidance excerpt snapshots verified locally against pinned commit URLs/digests. They are not full original documents and do not establish security claim truth.
- **Zero independent human reviews** and no Anjoman-eligible cases have been proven.
- **Six training pairs** in the scenario casebook, so the 2% cap is mathematically impossible to satisfy regardless of preference quality. Even all 12 would still be insufficient.
- The other draft CVE ledger remains a separate research asset. It has not been merged into or approved for the training corpus.

## Repeatable commands

```bash
PYTHONPATH=src python -m falsum audit-scenarios data/draft-scenarios.json
PYTHONPATH=src python -m falsum preflight data/draft-scenarios.json \
  --diagnostic-dir build/draft-only
PYTHONPATH=src python -m unittest discover -s tests -v
```

The diagnostic directory is gitignored. It intentionally writes `DRAFT-ONLY-NOT-FOR-TRAINING.jsonl` and `STATUS-NOT-ELIGIBLE.json` so that an actual upstream parser can check format and statistics **without legitimizing those rows as training or network material**. Do not use it with the normal training command, publish it, or upload it as eligible material.

CI checks out the pinned upstream kit, installs NumPy, runs `--check-data` on that diagnostic file and **expects exit code 1 (FAIL)**. An unexpected pass or tool error fails CI because either outcome would invalidate the documented checkpoint.

## Research and implementation priorities

1. **Independent domain review:** have a real reviewer assess the complete pinned primary-source context and the exact preferred/rejected answer for each claim. Keep immutable evidence and signed/dated reviewer rationale. Never invent reviewers or mark an AI-generated judgment as independent human review.
2. **Coverage:** develop at least **50 genuinely distinct, reviewed training pairs**, with room for rejected material and preferably more than 50. Examples should span CVE applicability, credentials, deployment conditions, identity boundaries, webhooks, TLS, CI permissions and injection risks. Do not manufacture superficial mutations just to reach 50.
3. **Splits:** reserve entirely distinct advisory/source/rule families for independent validation and holdout; never tune on the final holdout.
4. **Diagnostics:** monitor long-answer shortcuts and answer-only style cues. Run the exact official gate after all material is reviewed. Check tokenizer conformance and truncation with the actual ModernBERT tokenizer before GPU training.
5. **Network:** pursue independent material contributors for `SECURITY_REVIEW_GENERAL` and verify eligible status and pool activation separately. Local gate results cannot replace live acceptance.

## No false claims

A passing upstream dataset gate would **not** prove domain correctness, generalized model accuracy, an activated evaluation pool, or a live WASM adapter. This checkpoint does not train or register anything.
