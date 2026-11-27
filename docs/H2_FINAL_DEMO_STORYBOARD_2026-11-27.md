# FALSUM — final judge storyboard (2:45–3:30)

**Prepared, not recorded or submitted.** The walkthrough is intentionally
public-safe: it uses pinned source metadata and generated summaries, never raw
provider response bodies, receipts, payment headers, private keys, or hidden
evaluation material.

## 0:00–0:20 — name the problem

“FALSUM is Evaluator material for `SECURITY_REVIEW_GENERAL`. It prevents a
security-review result from silently treating a paid HTTP response, advisory
identifier, or caller label as proof. Every display decision is bound to the
exact provider target, authenticated source identity, version interval, and
safe evidence status.”

Show the repository landing page and the one-sentence limitation: this is
evaluation material, not a security clearance or a trained model claim.

## 0:20–0:55 — run a genuinely fresh public holdout

```bash
PYTHONPATH=src python -m falsum.cli audit-fresh-provider-holdout \
  --out /tmp/falsum-fresh-holdout.json
```

Show only the summary:

- provider tree commit and frozen protocol hash;
- Django 3.2.0: 66 reported references, 38 canonical source records, 27
  applicable, 39 fail-closed unknown/insufficient;
- lodash 4.18.1: zero reported advisories.

Say explicitly: the two paths were selected from public tree metadata before
response inspection; the result is not a blind model holdout or human gold.

## 0:55–1:35 — inspect one bound decision

Open the JSON report and select one Django row. Show its reported identifier,
canonical advisory source path, immutable Git blob SHA, exact `PyPI:django@3.2.0`
target, FALSUM decision, and baseline decision. Do not open the raw provider
fixture or print its payment/receipt fields.

Point to the boundary test in
`tests/test_phase5bj_fresh_provider_holdout.py`: `fixed` is exclusive,
`last_affected` is inclusive, and unsupported ranges abstain. Then show that
the independently implemented baseline agrees on all 66 rows. This proves
repeatable source-bound evaluation, not superiority over the baseline.

## 1:35–2:05 — show the previously measured improvement

```bash
PYTHONPATH=src python -m falsum.cli audit-evaluator-measurement \
  --out /tmp/falsum-measurement.json
```

Show the bounded prior result: accept-all displays 12 references including 2
known version-inapplicable instances; the reviewed gate displays 10 and
suppresses both. State “2/12 known false-positive reduction; 10/10 narrow
reviewed-reference precision,” then immediately state what it does not prove:
recall, general security accuracy, expert gold, ranking uplift, or adoption.

## 2:05–2:35 — demonstrate safety and failure handling

Run the focused adversarial tests. Show that wrong target identity, changed
source bytes, unsupported intervals, duplicate references, caller adoption
labels, and sensitive response fields fail closed. Mention the preserved ACP
provider/event binding only as optional future work; no ACP browser, buyer,
signer, payment, deposit, or transaction is used in this demo.

## 2:35–3:00 — close with the judge checklist

Show the final score page and say:

“The strict Evaluators assessment is 90/100 today under the official
40/15/10/10/5/20 rubric, with 34/40 measurement validity and the 28/40
technical minimum met. The missing points are real
external verification, current owner-controlled submission actions, and a
final recording—not hidden features. FALSUM's claim is deliberately narrow:
source-authenticated, version-aware, fail-closed evaluation material that a
reviewer can reproduce for a new public input.”

## Recording checklist

- Use a clean browser/terminal with no tokens, wallets, private keys, receipt
  headers, or hidden prompts visible.
- Keep the two holdout counts and all caveats on screen long enough to read.
- Show the official rules link and repository commit, not a private dashboard.
- Mention network and cost truth: this local replay uses public GitHub sources
  and costs $0; it does not execute a new Telegraph purchase.
- If the recording is not made, submit this document as the accessible
  equivalent only after owner approval; do not claim a video exists.
