# FALSUM - final judge storyboard (3:30)

**Prepared, not recorded or submitted.** The walkthrough is public-safe: it
uses pinned source metadata and generated summaries, never raw provider
response bodies, receipts, payment headers, private keys or hidden material.

## 0:00-0:20 - name the problem

"FALSUM is Evaluator material for `SECURITY_REVIEW_GENERAL`. It prevents a
security-review result from treating a paid HTTP response, advisory identifier
or caller label as proof. Every decision is bound to the exact provider target,
authenticated source identity, version interval and evidence status."

Show the repository and the limitation: this is evaluation material, not a
security clearance or a trained-model claim.

## 0:20-0:55 - run a genuinely fresh public holdout

```bash
PYTHONPATH=src python -m falsum.cli audit-fresh-provider-holdout \
  --out /tmp/falsum-fresh-holdout.json
```

Show the provider-tree commit and frozen protocol hash; Django 3.2.0 with 66
reported references, 38 canonical source records, 27 applicable and 39
fail-closed unknown/insufficient; and lodash 4.18.1 with zero advisories.
State that paths were selected from public tree metadata before response
inspection, so this is not blind model holdout or human gold.

## 0:55-1:35 - inspect one bound decision

Open one JSON row and show its identifier, canonical advisory path, immutable
Git blob SHA, exact `PyPI:django@3.2.0` target, FALSUM decision and baseline
decision. Do not open raw provider fixtures or print payment/receipt fields.

Point to fixed-exclusive, last-affected-inclusive and unsupported-range tests.
The independently implemented baseline agrees on all 66 rows. This proves
repeatable source-bound evaluation, not superiority over the baseline.

## 1:35-2:05 - show the previously measured bounded improvement

```bash
PYTHONPATH=src python -m falsum.cli audit-evaluator-measurement \
  --out /tmp/falsum-measurement.json
```

Show the prior bounded result: accept-all displays 12 references including 2
known version-inapplicable instances; the reviewed gate displays 10 and
suppresses both. Say "2/12 known false-positive reduction; 10/10 narrow
reviewed-reference precision," then state that this does not prove recall,
general security accuracy, expert gold, ranking uplift or adoption.

## 2:05-2:35 - run the corrected independent-label holdout

```bash
python -m pip install --no-deps packaging==26.4
npm install --prefix .phase5bn-node --ignore-scripts --no-audit --no-fund semver@7.8.6
PYTHONPATH=src FALSUM_PHASE5BN_NODE_PATH=.phase5bn-node/node_modules \
  python -m falsum.cli audit-corrected-independent-holdout \
  --out /tmp/falsum-corrected-holdout.json
```

Show the independent reference stage, verified registry versions, 22/24 FALSUM
decisions versus 24/24 external-resolver decisions, and the two explicit
unknown disagreements. Show that all 48 answer surfaces are target-specific,
then open the computed case-index, answer-position and answer-token leakage
metrics. State that this corrected result supersedes the historical Phase5BM
perfect result for current certification.

## 2:35-3:05 - demonstrate safety and failure handling

Run the focused adversarial tests. Show that wrong target identity, changed
source bytes, unsupported intervals, duplicate references, caller-supplied
adoption labels and sensitive response fields fail closed. Mention that ACP is
suspended; no buyer, signer, payment, deposit or transaction is used.

## 3:05-3:30 - close with the judge checklist

Show the final score page and say:

> "The corrected strict internal Evaluators assessment is 96/100 under the
> official 40/15/10/10/5/20 rubric, with 38/40 measurement validity and the
> 28/40 technical minimum met. Four points remain withheld: two corrected
> holdout disagreements and no independently verified repeat integration beyond
> the existing external reviews. That gap is real, as are current
> owner-controlled submission actions and a final recording. FALSUM's claim is
> deliberately narrow: source-authenticated, version-aware, fail-closed
> evaluation material that a reviewer can reproduce for a new public input."

## Recording checklist

- Use a clean browser/terminal with no tokens, wallets, private keys, receipt
  headers or hidden prompts visible.
- Keep holdout counts and caveats on screen long enough to read.
- Show the official rules link and repository commit, not a private dashboard.
- State the replay network and cost truth: public GitHub/PyPI/npm retrieval,
  $0, no Telegraph transaction.
- If no recording is made, submit this document as an accessible equivalent
  only after owner approval; do not claim a video exists.
