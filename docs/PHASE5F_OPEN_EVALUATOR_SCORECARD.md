# Phase 5F — Open-book security evaluator prediction scorecard

**FALSUM · Telegraph Season II · Evaluators · SECURITY_REVIEW_GENERAL · 20 November 2026**

FALSUM's five-source verifier already establishes whether narrow historical source-test claims are supported, contradicted or require abstention. Phase 5F adds a genuine developer-facing **candidate prediction format and repeatable scoring harness**. A developer can inspect questions, use their own evaluator to answer, and score those predictions against the original public upstream regression evidence. No wallet, paid inference, secrets, network account or private labels required.

**The challenge is public, author-selected and open book.** It is not independent human AppSec gold, a sealed holdout, arbitrary natural-language review scoring, or a registered Telegraph adapter.

## Source-locked challenge

The tool regenerates the historical five-stage source data from the four original Koa/Hono/LangChain proof receipts plus the exact originally archived Flask GitHub Actions proof ZIP from [run 44524997174](https://github.com/Iniwura/falsum/actions/runs/44524997174). The old four-case witness index is not rewritten.

For each actual historical fix stage, the challenge contains two exact Git revisions (parent and fixed), four typed security claims (regression passes, regression fails, production exploit confirmed, universal application safety), and two supplied proof conditions (original SHA or deliberately forged SHA). This makes **80 unique questions** with original Git source/test links and real CI proof. No answers are included in the question export, but the code and public source-test results can be consulted. This is **not blind**.

## Why 75% raw agreement can still be poor evaluation

60 of 80 deliberately constructed conditions are ABSTAIN: invalid SHA or claims beyond the actual test scope. An evaluator that always abstains matches 60/80 = **75% raw agreement** without recognizing any of the 20 known source-test PASS/FAIL facts.

| Declared trivial baseline | Raw agreement | Macro recall of three classes | Fully correct source-stage reversals | Unsupported confident replies |
| --- | ---: | ---: | ---: | ---: |
| Always ABSTAIN | 75% | 33.3333% | 0/5 | 0 |
| Always SUPPORTED | 12.5% | 33.3333% | 0/5 | 60 |
| Always CONTRADICTED | 12.5% | 33.3333% | 0/5 | 60 |

These are **synthetic constant-choice baselines, not results from a real model**. The scorecard gives the three-class confusion matrix, each class's recall, macro recall, exact-match ratio, total unsupported confident claims, unnecessary abstentions on established source facts, and source-sensitive complete parent/fix reversals (four exact original-receipt PASS/FAIL decisions per patch stage).

## Try it with Python 3.11+

~~~bash
git clone https://github.com/Iniwura/falsum.git
cd falsum
python -m pip install --no-deps -e .

falsum score-source-predictions export \
  --challenge-out source-challenge.json \
  --template-out my-predictions.json
~~~

The first file contains the **80 no-answer questions**. The second contains 80 stable question IDs with **null** verdict fields. Use a real separate evaluator or editor to supply one of SUPPORTED, CONTRADICTED or ABSTAIN in each prediction row. Preserve the original question IDs, order, and challenge SHA-256. An untouched template is intentionally unscorable.

~~~bash
falsum score-source-predictions score \
  --predictions my-predictions.json \
  --out my-source-scorecard.json

falsum score-source-predictions baseline \
  --strategy always-abstain \
  --out always-abstain-baseline.json
~~~

The score command **regenerates the reference from pinned original public source proof**, rather than accepting a caller-submitted reference answer key. Every run is write-once. Rejected inputs include missing predictions, unexpected fields, changed challenge hash, duplicated JSON keys, reordered IDs, unrecognized verdict classes and invalid original source evidence. The caller's responses are tagged as **unverified external candidate predictions** even when they match all references. Synthetic baselines remain separately marked.

## Usefulness and limits

The scorecard gives developers a practical way to evaluate whether their own tool distinguishes test facts, false confident assertions and evidence-limited abstention. These 80 conditions are deliberately narrow, constructed from **real historical upstream tests**, not independent human review prompts. A high score is not proof that a model is generally accurate at security review or outperforms the original quarantined Foundation LoRA. That model's previously observed negative results are unchanged.

The official [Telegraph H2 rules](https://hackathon.telegraphprotocol.com/rules) accept Evaluators contributions through evaluation material or an adapter, with technical value, repeatability, and meaningful developer activation important to judging. Phase 5F helps a new developer reproduce the contribution; it does not invent third-party adoption, outreach or external human AppSec labels. Genuine source-specific feedback and independent disagreement can be posted to [the open review invitation](https://github.com/Iniwura/falsum/issues/25) when available. FALSUM's public release freshness remains separately tracked in [issue #61](https://github.com/Iniwura/falsum/issues/61).

**Truthful current boundaries:** independent verified human expert gold = 0; new Telegraph network evaluator registration = false; actual third-party model submission to this scorecard = none; official H2 main entry = not yet filed; new trained-model improvement = not established.

## Auditable implementation

[Python source](../src/falsum/phase5f_evaluator_scorecard.py) · [adversarial input and score tests](../tests/test_phase5f_evaluator_scorecard.py) · [three-Python CI](../.github/workflows/phase5f-open-source-evaluator-scorecard.yml) · [Flask proof archive](PHASE5C_AUTHENTIC_FLASK_FIFTH_WITNESS.md).

The defensible contribution is an **honest, class-sensitive and reproducible harness for measuring supplied structured judgments against original upstream source-test evidence**, not a claim to have solved general security-review evaluation.
