# Phase 2M — Context-training A/B experiment (research only)

**Hypothesis:** The official security-version-boundary trainer can achieve a high score on six synthetic advisory holdouts while ignoring the actual question context in security code review. Appending a small, explicitly source-linked **TRAIN-only** set of paired PR reversals might improve its contextual ranking. This is a controlled research hypothesis, not an assertion of quality.

## Control and intervention

- **Control**: 52 automatically generated, unreviewed GHSA training comparisons; 6 GHSA validation and 6 distinct GHSA test comparisons; official ModernBERT-base LoRA, 1 CPU epoch. [Initial measured control](https://github.com/Iniwura/falsum/actions/runs/41124535661).
- **Intervention**: SAME 52 GHSA training comparisons, plus **six** fictional PR comparison rows from only three PR **training** families (`django-debug`, `django-secret`, `ssrf-redirect`). Total 58 training pairs.
- **Frozen official evaluation**: The same 6 GHSA validation and same 6 GHSA holdout inputs.
- **Frozen PR diagnostics**: Both runs score the same hypothetical PR benchmark. Four validation PRs cover GitHub Actions cases; two holdout PRs cover TLS. **No PR validation/holdout case is incorporated into the augmented training JSONL.**
- **Training and model**: Same pinned upstream official kit, model backbone and one-epoch CPU settings. The official data-quality gate must pass on the 58 actual training rows before training starts.

Source integrity and split isolation are audited by `src/falsum/context_curriculum.py` and adversarial unit tests. The generated curriculum manifest fingerprints the original pilot, PR benchmark, casebook and output JSONL. The process refuses changed original training bytes, duplicate negatives, duplicate prompts, split leakage or claims of eligibility.

## How to inspect

- The [context variant workflow](../.github/workflows/research-context-pilot.yml) saves a separate, quarantined artifact with the real trained adapter, official trainer result, score-by-case PR report, and fail-closed `PILOT-DECISION.json`.
- Reproduce with a source-built `PILOT-QUARANTINE-MANIFEST.json` and matching GHSA train JSONL:

```bash
PYTHONPATH=src python -m falsum.context_curriculum \
  --advisory-train /tmp/pilot/grounded/DRAFT-grounded-train.jsonl \
  --pilot-manifest /tmp/pilot/PILOT-QUARANTINE-MANIFEST.json \
  --pr-benchmark data/draft-pr-benchmark.json \
  --casebook data/draft-scenarios.json \
  --out /tmp/CONTEXT-TRAIN.jsonl \
  --manifest /tmp/CONTEXT-MANIFEST.json
```

## Measured result (30 October 2026)

The real [A/B workflow](https://github.com/Iniwura/falsum/actions/runs/41126779406) finished successfully, using the actual official V2 ModernBERT trainer. Its quarantined checkpoint and evidence were uploaded as artifact `13011655915`.

| Measure | Control: 52 | Intervention: 58 |
| --- | ---: | ---: |
| Official data-quality shortcut gate | PASS | PASS |
| Official synthetic GHSA test | 5 / 6 (83.33%) | 6 / 6 (100%) |
| Full-context PR validation | 1 / 4 (25%) | 1 / 4 (25%) |
| Full-context PR holdout | 2 / 2 (100%) | 2 / 2 (100%) |
| Counterfactual rule families both correct | 1 / 6 | 1 / 6 |
| Answer-only PR validation | 2 / 4 (50%) | 2 / 4 (50%) |

This is **no improvement** on the primary PR judgment task despite a better official six-case advisory result. Five PR families still fail at least one context reversal. Training with only six additional fictional PR preferences does not establish credible cross-domain generalization. An official test PASS is not a license to submit this unreviewed research model.

The next iteration should **not** repeatedly tune against the same 4 validation / 2 holdout PRs or fabricate more weak labels. Expand to independently verified, realistic project-separated PR cases and obtain genuine blind expert judgments first.

## Interpretation rules

The headline comparison is **full-context PR validation accuracy** and **number of paired families correctly reversed**. An answer-only ablation is retained to detect style shortcuts. The GHSA official test result must be reported separately, never substituted for code-review performance.

The PR validation partition has just four fictional examples and the holdout just two. Repeatedly using the holdout to select among models would invalidate any claim that it is an independent final evaluation. Even a large improvement cannot authorize registration without independent AppSec review, credible held-out project diversity, a proven ONNX/WASM V2 path, and actual Telegraph eligibility. This experiment is not an eligible data contribution.

**Status:** See the GitHub Actions run for the actual result. Do not infer a score from a green workflow: the workflow may be green when a legitimate official model-evaluation failure is merely recorded, and the data remains research-only.
