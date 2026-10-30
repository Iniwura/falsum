# Phase 2N — PR AppSec independent-review packet

This is a practical route to the project's missing human ground truth, not an automated review or model approval.

The existing GHSA review gate can already create separately stored question and answer-key folders. Phase 2N extends the same discipline to the **12 fictional pull-request code-review cases**.

## Generate a genuinely blind packet

From the repository root:

```bash
PYTHONPATH=src python -m falsum.pr_review_packet \
  --benchmark data/draft-pr-benchmark.json \
  --casebook data/draft-scenarios.json \
  --public-out /tmp/falsum-pr-questions \
  --private-out /tmp/falsum-pr-key
```

Share **only** `/tmp/falsum-pr-questions` with an external, independently identifiable AppSec reviewer. **Never share or commit the private answer-key directory.** Both paths must be outside the repository, disjoint, and nonexistent before generation.

The public packet includes each hypothetical PR diff, its deployment context, two candidate answers labeled A and B in deterministically shuffled order, pinned primary-source guidance links, and blank fields for a reviewer to document the rationale, conditions, uncertainties, source passage, GitHub identity and date. The source benchmark and all checksum-linked source excerpts are reverified before generation.

The private key contains the original *proposed draft* preference and its train/validation/holdout group. Those are NOT independently verified answers; independent reviewers can disagree or mark a pair `uncertain`. Their own judgment must be recorded before the private labels are compared. Neither automated scorer results nor LLM-written assertions count as independent review.

## Acceptance boundary

- No current reviewer or case is promoted automatically.
- A source link alone cannot prove deployed exploitability.
- Reviewer identity and reasoning need independent verification.
- No reviewer approvals, eligible Anjoman rows, accepted Telegraph module, or live evaluator have been claimed.
- The current small synthetic corpus is still insufficient for credible real-world generalization.

Tests check that the public packet contains no hidden answer label, both outputs are physically disjoint, overwriting and repository-local keys are refused, and tampered casebooks fail validation.

The independent reviewer request remains open at [FALSUM issue #1](https://github.com/Iniwura/falsum/issues/1).
