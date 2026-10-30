# Phase 2i: Counterfactual PR review benchmark

**A scoring challenge, not human-reviewed training material.** The 12 PRs are fictional, written for security-review research. They are not actual vulnerability disclosures or incidents. Each scenario points to a real pinned upstream security-guidance excerpt; the excerpts support general security guidance but do not independently establish a hypothetical PR's facts.

## Why this matters

The previous GHSA research set focuses on package version boundaries. Telegraph's `SECURITY_REVIEW_GENERAL` also needs code and configuration review. Moreover, the existing 12 application-security questions were too easy: a lightweight answer-only Naive Bayes model trained on six chosen/rejected answer pairs ranked **4/4 validation and 2/2 holdout** correctly **without reading any question, code, or source**. That is a harmful answer-style shortcut, not impressive security reasoning.

## What changed

Twelve small, explicitly hypothetical code changes are bound to the 12 source-linked scenarios in `data/draft-scenarios.json`. They cover:

- Django production vs local-only debug and live signing keys vs documentation placeholders.
- Server-side requests following untrusted redirects vs bounded partner routes.
- GitHub Actions `pull_request_target` running untrusted PR code with `write-all` vs `pull_request` test jobs with `contents: read`.
- Encoded production token logging vs protected deploy-only token use.
- Disabled TLS certificate verification in production payment clients vs local test fixtures.

The casebook checksum, pinned-excerpt digests, task text, label lineage, rule-family split, and credentials are checked before evaluation. The `pull_request_target` example deliberately avoids assuming that a fork's ordinary `pull_request` workflow always receives a write token. No credentials, customer details, or real attack targets are present.

For every rule family, two *different contexts* are paired with the **same two candidate answers**. The preferred answer reverses between the contexts. As a result, the answer-only model scores **50%** on both validation and holdout because it cannot learn a context-independent preferred style. The benchmark forces a genuine scorer to read the question and proposed change to outperform this shortcut.

| Partition | Rule families | Cases | Old answer-only result | New counterfactual result |
| --- | ---: | ---: | ---: | ---: |
| Train | 3 | 6 | Used to fit | Used to fit |
| Validation | 2 | 4 | 4/4 | 2/4 (50%) |
| Holdout | 1 | 2 | 2/2 | 1/2 (50%) |

**These percentages are not statistically meaningful model accuracy.** The paired, duplicated candidate answers also violate the official training kit's negative-uniqueness gate. The counterfactual test set must **never** be treated as the final training set or submitted to Anjoman as eligible rows. It's a small diagnostic benchmark for detecting shortcut dependency.

## Run

```bash
PYTHONPATH=src python -m unittest discover -s tests -p test_pr_benchmark.py -v
PYTHONPATH=src python -m falsum.pr_benchmark data/draft-pr-benchmark.json \
  --source-casebook data/draft-scenarios.json --report-out /tmp/falsum-pr-diagnostic.json
```

`baseline_diagnostic` measures original easy answers. `counterfactual_diagnostic` uses the exact swapped candidate answers. Neither is a trained ModernBERT adapter or live Telegraph score. All cases are `draft`, with no independent review recorded.

## Competitive next gates

1. Independent AppSec reviewers review every context, precise code semantics, source guidance, and candidate answer. `uncertain` must be a valid judgment; no invented approvals.
2. Expand to hundreds of *realistic, unique, independently reviewed* code/PR/dependency tasks from distinct projects and ecosystems. Avoid copied answer templates and split by actual originating project, not just scenario category.
3. Train ModernBERT on a separate, source-reviewed training set after the upstream `--check-data` gate passes. Keep these 12 paired contexts out of training as an adversarial benchmark.
4. Evaluate model scores on the independent holdout, ONNX/WASM reproducibility, and the live Telegraph network. No model or network promotion is claimed.
