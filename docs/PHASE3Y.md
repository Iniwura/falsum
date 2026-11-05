# Phase 3Y — actual model scores on harder source-grounded counterfactuals

**Research diagnostic, not evaluator registration.** The current FALSUM checkpoint remains quarantined. No training, automatic source-label approval, network contribution, new production UI or user-facing claims change.

## Why this is useful

Previous [Phase 3J](PHASE3J.md) real official Foundation scoring failed to reverse preferences in **both** known Starlette and Requests fact-changing groups. [Phase 3X](PHASE3X.md) then executed exact pinned upstream Axios and Django source functions and generated 18 harder comparisons, but did **not** score the model on them.

Phase 3Y measures the **same original SHA-verified LoRA** against eight predeclared Phase 3X binary comparisons: four source-fact counterfactual pairs. This is the first actual old-model scoring experiment on these harder source-derived conditions, not another handwritten demo score.

| Counterfactual group | Fixed comparison | Correctness basis |
| --- | --- | --- |
| Axios absolute target with strict baseURL | Parent vs fixed helper | Executed pinned URL-building helper; destination origin only |
| Axios protocol-relative target with strict baseURL | Parent vs fixed helper | Executed pinned URL-building helper; destination origin only |
| Django 3,601-digit input | Parent vs fixed intcomma | Bounded subprocess: recursion error vs returned value |
| Django 12-digit output leading comma | Parent vs fixed intcomma | Bounded subprocess: isolated source-function first character |

Each pair retains identical A/B candidate texts while source revision or observed behavior changes. A and B both occur four times as the provisional source-supported response; trivial constant A or B therefore scores 4/8. The **two Phase 3X ABSTAIN** conditions are excluded: a forced two-answer model cannot demonstrate calibrated abstention on unsupported deployment claims.

## Real execution requirements

[Workflow](../.github/workflows/phase3y-real-hard-model-diagnostic.yml) downloads the original **real** Phase 3X source-execution artifact from GitHub run `41874616439`. The schema checks do not pretend that synthetic unit fixtures are source execution. It then downloads the quarantined *original* model from run `41304788714`, checks exact SHA256, fetches and verifies the official ModernBERT Foundation / ONNX / WASI files, and builds the immutable pinned Telegraph Go scoring tool. The official tokenizer creates 16 task/answer inputs without truncation, each scored with two identical repeated inferences. The audit checks model identity, Foundation loaded, score float32 bits, repeat agreement, question/answer bytes, source reports, token framing and every release veto.

The input generator and evidence analyzer share one CLI:

```bash
# With authenticated Phase 3X source JSON and exact official tokenizer.json:
PYTHONPATH=src python -m falsum.phase3y_hard_model_probe \
  --axios /path/to/axios-probe.json --django /path/to/django-probe.json \
  --tokenizer /path/to/official/tokenizer.json --out /tmp/FROZEN-KNOWN-HARD-INPUTS.json

# After actual official score engine has populated ID/OFFICIAL-SCORE.json files:
PYTHONPATH=src python -m falsum.phase3y_hard_model_probe \
  --axios /path/to/axios-probe.json --django /path/to/django-probe.json \
  --inputs /tmp/FROZEN-KNOWN-HARD-INPUTS.json --scores-dir /tmp \
  --out /tmp/ACTUAL-KNOWN-HARD-MODEL-RESULTS.json
```

**Do not treat `test_phase3y_hard_model_probe.py` as a model-quality score.** Its model scores and token arrays are synthetic *parser fixtures*, explicitly distinct from the real CI run. The runner's **actual** output is the only place to look for real observed model preferences. Even green CI indicates data integrity, never successful model quality.

## Honest interpretation and next release gate

The real observations may be positive or negative. Record the full 8-case count, each of four changed-fact reversals, constant-choice baselines, all failures and the reproducible workflow URL. These remain **known public projects**, not project-disjoint blind examples; the source expectations are researcher-provisional rather than independently adjudicated security labels. No certified accuracy, third-party application adoption, security exploitation, eligible new Anjoman rows or live evaluator can be claimed.

The original model quality veto is unconditional. To release a model later, first obtain external human review and a *new sealed, project-disjoint* set, compare model and baseline on exactly the same withheld material, and demonstrate reliable contextual reversals. The separately reported 20 Anjoman-eligible user-contributed material rows remain unchanged and confidential.