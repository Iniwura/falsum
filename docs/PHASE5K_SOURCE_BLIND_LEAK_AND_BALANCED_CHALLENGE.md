# Phase 5K — We falsified our own 80-item benchmark

**FALSUM · Telegraph Season II Evaluators · SECURITY_REVIEW_GENERAL · 20 November 2026**

## Actual scorecard validity failure found

The original [Phase 5F open-book prediction scorecard](PHASE5F_OPEN_EVALUATOR_SCORECARD.md) has genuine original upstream source-test provenance, but the exported *question metadata* reveals the reference class for every item. An extremely simple source-blind rule reconstructs **80/80 correct verdicts (100% exact-match agreement, 100% macro class recall, all 5 historical parent/fix reversals)** without reading any actual Git source, test or running a model.

The rule only uses the public fields *revision*, *claim_type*, and *receipt_integrity*: a tampered execution receipt or unsupported production/global-safety claim must ABSTAIN; an original receipt at a fixed revision supports test PASSES and contradicts test FAILS; at a parent revision, it does the opposite.

This is a **serious benchmark validity defect**, NOT a vulnerability in the underlying source-integrity checker. Anyone can run a metadata-only program and claim perfect "security-review evaluation" even though it did not review code. **Do not report the original 80 challenge score as evidence of learned-model quality, semantic source understanding, generalization or expert-validated gold.** The original 80 public source evidence tests and historical research remain unchanged for reproducibility.

[Working attack and balanced scorecard implementation](../src/falsum/phase5k_source_blind_scorecard.py) · [adversarial tests](../tests/test_phase5k_source_blind_scorecard.py) · [3-Python CI](../.github/workflows/phase5k-source-shortcut-and-balanced-challenge.yml).

## Stronger public evaluation material: 30 balanced source-role-neutral questions

The new v2 challenge selects **30** security-review judgments derived from the same five authenticated real historical upstream source-test stages, balanced across **10 SUPPORTED, 10 CONTRADICTED and 10 ABSTAIN**.

Each original fix stage provides the four exact parent/fixed PASS/FAIL factual claims and two calibration controls (unsupported deployed exploitability and forged execution receipt). It contains a full immutable Git SHA, exact original upstream source and test links, actual recorded upstream test CI, and the supplied receipt digest.

Unlike Phase 5F, v2 **does not reveal whether an individual commit is the parent or the fix**. It presents source slots A and B, with three stages using A as parent and two B as parent. It uses opaque stable hashed item IDs and no explicit outcome labels. The candidate has to inspect the source/test history to distinguish factual outcomes, not merely decode an openly stated revision role.

**This is still public, author-selected and deterministic — not a sealed or independent holdout.** The complete generator and original source mapping remain available in the repository; a sufficiently informed shortcut can recover them from public materials. The source-role masking eliminates the simplest universal answer column, but cannot prove complete resistance to source-blind shortcuts. The quiz is reproducible and useful for teaching evidence-calibrated source review, not yet a measured improvement in security-review model quality.

### Disclosed baseline comparisons, not model performance

| Synthetic shortcut, no original source reading | Original 80-item exercise | Revised 30-item exercise |
| --- | ---: | ---: |
| Answer directly from explicit parent/fixed metadata | **80/80 = 100%** | Not directly applicable: explicit role removed |
| Always ABSTAIN | **60/80 = 75%** | **10/30 = 33.33%** |
| Always SUPPORTED | **10/80 = 12.5%** | **10/30 = 33.33%** |
| Always CONTRADICTED | **10/80 = 12.5%** | **10/30 = 33.33%** |
| Always assume slot A is the vulnerable parent, and use disclosed statement/receipt fields | Not directly applicable | **22/30 = 73.33%, 3/5 full source reversals** |

All scores above are **synthetic deterministic controls, not actual model runs**. Balanced references prevent the misleading trivial 75% always-abstain result from Phase 5F. A simple slot assumption still scores much better than chance because the public evidence allows shortcuts. The resulting scorecard reports exact agreement, macro three-class recall, complete before/after reversal accuracy, unsupported confidence, and unnecessary abstention on established original source facts.

## Run the real reproducible attack and revised challenge

Python 3.11+; no credentials, paid API, wallet, pretrained model, secret cases or remote inference are required.

~~~bash
git clone https://github.com/Iniwura/falsum.git
cd falsum
python -m pip install --no-deps -e .

# Reproduce the 100-percent original metadata-only shortcut
falsum score-source-balanced audit --out metadata-answer-leak.json

# Export the improved no-answer questions and unfilled 30-row candidate file
falsum score-source-balanced export \
  --questions-out balanced-source-questions.json \
  --template-out candidate-responses.json

# Run a disclosed source-blind shortcut against the balanced challenge
falsum score-source-balanced baseline \
  --strategy slot-a-is-parent \
  --out slot-assumption-control.json

# After an actual developer or evaluator supplies a decision on each question:
falsum score-source-balanced score \
  --predictions candidate-responses.json \
  --out candidate-source-results.json
~~~

The exported prediction template has 30 null verdict fields; fill each one with SUPPORTED, CONTRADICTED or ABSTAIN before scoring. An untouched template is intentionally not scorable. The scorer independently regenerates its reference from source-locked public upstream tests and the real archived Flask GitHub Actions ZIP, never from a caller-chosen answer key.

Inputs reject unknown labels, forged challenge SHA, truncated/reordered/duplicate IDs, extra authoritative labels or unapproved status. Score reports distinguish **unverified candidate responses** from **disclosed synthetic baselines**. Even a real outside prediction file is not independently certified human AppSec gold, and a perfect author-derived reference file cannot prove learned-model accuracy.

## Competitive interpretation

The contribution is a **falsifiable benchmark-design finding** plus a lower-friction, balanced public source-review challenge. It has stronger measurement discipline than claiming that 80 constructed source consistency checks were an evaluator accuracy score.

**Still unproven:** blind generalization to newly selected project-disjoint cases, independent expert judgments, actual outside evaluator submissions to this challenge, network scorer registration, improved reward-model predictions, qualified developer adoption, official H2 final entry.

The original Foundation LoRA negative results (5/8 provisional source matches, 1/4 correct complete reversals) remain unchanged and quarantined. The historic 20/20 Anjoman Eligible observation is separate from security-review source-test accuracy and does not by itself prove organizer acceptance.

A future first-place-quality evaluation claim needs frozen model/protocol, new source-project-disjoint cases, genuine independent judgments or outside model predictions, strong source-blind baselines and transparent failure reporting. All five cases here were previously examined by FALSUM. This new quiz is not a private model test.

**No demo, public social-post claim, registered evaluator or main hackathon submission was created.**
