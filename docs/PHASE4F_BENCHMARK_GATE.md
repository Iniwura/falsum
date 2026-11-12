# Phase 4F — independent-review census and benchmark release gate

**Telegraph Season II / Evaluators / SECURITY_REVIEW_GENERAL | November 12, 2026**

## Goal

FALSUM's next competitive test is whether its security-review material withstands independent security experts, not whether its own fixture tests pass.

Phase 4E reverified **seven previously studied public upstream security fixes**, each with a source-file patch, a regression-test patch and two researcher-authored answer candidates. It generated **fourteen letter-order presentations, not fourteen different security cases**. Phase 4F now collects actual GitHub review-claim metadata and makes a **fail-closed benchmark release decision**.

## What gets counted

- **Source-verified material:** seven real upstream project source/test security-fix case candidates. Exact pinned commits, blobs and patch evidence are checked by the pre-existing Phase 3F verifier and the Phase 4E generator.
- **Form-valid GitHub review claims:** actual issues from the public FALSUM repository, checked by Phase 3W for canonical source/test/advisory citations, human GitHub account metadata, duplicate author checks and independence declarations.
- **Still NOT expert gold labels:** a GitHub account, source links and a self-attestation cannot by themselves establish actual security correctness, author independence or professional expertise.
- **Still NOT real model predictions:** the existing original LoRA scored six different GHSA version cases in Phase 4A. It has not scored this seven-case reviewer pack.
- **Still NOT a sealed holdout:** all seven cases were previously researched publicly, and may have influenced model development.

The live workflow will report how many public, format-valid independent-review *claims* actually exist. It must record unresolved reviewer disagreements and ABSTAIN responses without silently choosing the researcher's preferred answer. All expert-validated gold labels, new eligible Anjoman rows and trained-model improvements remain zero or unknown until separately evidenced.

## Real CI and artifact

[Phase 4F live-source, live-GitHub-issue workflow](../.github/workflows/phase4f-review-evidence-gate.yml) verifies the actual upstream source/test commits, regenerates seven published case candidates and fourteen A/B placements, audits real GitHub issues, and produces a machine-readable source-linked reviewer register. It retains all original source and reviewer evidence reports for 90 days.

The unit tests intentionally mock upstream Git and reviewer issues. They test adversarial handling of spoofed reviewers, forged gold labels, contradictory evidence, duplicate claims and altered answer placements. **Mock tests are not independent review.**

## Reproduce

Requires Python 3.11 or later and public GitHub API connectivity. From the repository root:

~~~bash
PYTHONPATH=src:tests python -m unittest discover -s tests -p test_phase4f_review_evidence_gate.py -v

PYTHONPATH=src python -m falsum.phase3f_multifamily_material \
  --old-queue data/real-fix-queue.json \
  --train-queue data/real-fix-train-candidates.json \
  --catalog data/phase2w-applicability-rules.json \
  --out /tmp/falsum-verified-source.json

PYTHONPATH=src python -m falsum.phase4e_counterbalanced_reviews \
  --input /tmp/falsum-verified-source.json \
  --out /tmp/falsum-counterbalanced-cases.json

PYTHONPATH=src python -m falsum.phase3w_review_intake \
  --out /tmp/falsum-public-review-claims.json

PYTHONPATH=src python -m falsum.phase4f_review_evidence_gate \
  --source-pack /tmp/falsum-counterbalanced-cases.json \
  --review-audit /tmp/falsum-public-review-claims.json \
  --out /tmp/falsum-review-benchmark-readiness.json
~~~

Existing output paths are never overwritten by these tools. Use fresh output names for repeated runs.

## Request genuine independent AppSec review

[Read all seven source-backed questions](REVIEW_ONE_CASE.md) · [Submit one independent review](https://github.com/Iniwura/falsum/issues/new?template=independent-seven-review.yml) · [Review invitation](https://github.com/Iniwura/falsum/issues/25).

Please read the actual pinned source patch, regression test and advisory; choose A, B or ABSTAIN with precise immutable citations; describe the exact security precondition, deployment uncertainties and any candidate overclaims. Negative results and disagreements are welcome.

An independent human must separately inspect the review's factual correctness and reviewer expertise/independence. A format-valid GitHub form is **not** automatically accepted gold or network-eligible training material. No privately held Anjoman labels, row hashes or account credentials are published.

## Future benchmark: explicit no-leakage quality gates

**Before a future measured model improvement is claimed:**

1. Freeze a **new project-disjoint** test set, not these seven previously researched cases or the already known Phase 3Y/4A cases, before prompt tuning and inference. Publish protocol and hash commitment; avoid pretraining-contamination claims without evidence.
2. Get independent, source-backed AppSec expert adjudication. Resolve disagreements explicitly, allow ABSTAIN, and document any factual corrections.
3. Use a fixed model checkpoint and genuine official Telegraph Foundation scorer; archive all candidate scores, hashes, provenance and failures.
4. Compare a candidate with constant-A, constant-B and appropriate abstention baselines on **the exact same gold-labeled set**. Record project-wise accuracy and counterfactual reversals as well as any confidence intervals supportable by the small sample.
5. Do not train on or leak frozen evaluation cases. Do not register an evaluator before the separate official adapter requirements and independent performance gates are met.

**Current source-grounded model accuracy, baseline accuracy, position-swap stability and relative improvement all remain unknown (null), not zero and not 100%.** A seven-case reviewer pack with zero independently verified labels cannot produce a meaningful winning-quality score.

This phase improves **honest measurement readiness**, not a trained LoRA, accepted bounty or completed competition submission. Official Season II deadline: **December 1, 2026 at 23:59 UTC**; November 17 is our internal quality target.
