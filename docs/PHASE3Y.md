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

The real observations were negative and are now pinned permanently below. All failures are retained without changing any model-release permission. These remain **known public projects**, not project-disjoint blind examples; the source expectations are researcher-provisional rather than independently adjudicated security labels. No certified accuracy, third-party application adoption, security exploitation, eligible new Anjoman rows or live evaluator can be claimed.

The original model quality veto is unconditional. To release a model later, first obtain external human review and a *new sealed, project-disjoint* set, compare model and baseline on exactly the same withheld material, and demonstrate reliable contextual reversals. The separately reported 20 Anjoman-eligible user-contributed material rows remain unchanged and confidential.
## Verified original-model outcome — 5 November 2026

[Real, successful official scoring run](https://github.com/Iniwura/falsum/actions/runs/42105873138) · [Original 70-file source/input/model-score artifact](https://github.com/Iniwura/falsum/actions/runs/42105873138/artifacts/13450729962) · [Permanent 16-score-bit evidence record](../evidence/phase3y-2026-11-05-real-model-failure.json).

The original SHA-256-verified research LoRA completed **16 unique scorer inputs and 32 repeat-verified actual Foundation ONNX/WASI inferences**. The model's preference matched source-executed *researcher-provisional* expectations in **4/8 conditions**, against **4/8 for constant A and 4/8 for constant B**. The model failed all **4/4 required changed-fact preference reversals**. The same source reports, tokenized inputs, audit and 16 bit-exact scores were independently repeated in [another successful workflow](https://github.com/Iniwura/falsum/actions/runs/42105797771).

| Source-grounded changed fact | Parent preference / expected | Patched preference / expected | Full reversal |
| --- | --- | --- | --- |
| Axios absolute target, strict base origin | A / A | A / B | Fail |
| Axios protocol-relative target, strict base origin | A / A | A / B | Fail |
| Django 3,601-digit isolated intcomma | A / B | A / A | Fail |
| Django 12-digit leading-separator observation | B / A | B / B | Fail |

These are **not** independent AppSec labels, blind held-out projects, deployed vulnerabilities or trained model accuracy statistics. One Django formatting observation is isolated function behavior under localization-disabled conditions, not an assertion that a released Django application is exploitable. The score mismatch pattern indicates an inability to condition rankings on these version changes; it does not diagnose a model's internal mechanism.

### Tamper-resistant reproduction

```bash
# Confirm the committed failure record, including the exact original f32 bits:
PYTHONPATH=src python -m falsum.phase3y_recorded_evidence \
  --ledger evidence/phase3y-2026-11-05-real-model-failure.json

# After downloading the exact 5 November GitHub Actions ZIP above:
PYTHONPATH=src python -m falsum.phase3y_recorded_evidence \
  --ledger evidence/phase3y-2026-11-05-real-model-failure.json \
  --archive /path/to/falsum-phase3y-original-artifact.zip
```

The audit checks the ZIP hash, member hashes, 16 genuine score packets, frozen tokenizer inputs, exact source-derived case provenance, score margins, model identity, 0/4 reversals, both trivial baselines and permanent registration veto. CI additionally reruns the official scorer and requires the resulting source/input/score packets to match the archived record. No claim of 4/8 network evaluator accuracy is made.

**Decision:** do not register either LoRA or present this as an improved evaluator. Prioritize acquiring independently adjudicated evidence, freezing a truly project-disjoint evaluation set *before model tuning*, and comparing candidate models against the same set with context-reversal, ABSTAIN, error severity and evidence-citation metrics. Until then, the reproducible failure and the previously contributed 20 eligible Anjoman preference pairs are separate truthful deliverables.
