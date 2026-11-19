# Phase 5B — adversarial developer code review (AI-assisted, NOT independent human certification)

**Scope:** FALSUM's publicly shipped typed source-witness evaluator and its provenance guarantees. **Date:** 19 November 2026. **Role:** adversarial AI-assisted developer/security reviewer, acting at the project owner's request. **Reviewer independence:** NOT external, NOT an independently qualified human review, NOT expert gold.

## What was actually reviewed

Source under `src/falsum/source_review_witness_gate.py` and its original test contract, including the difference between its internally generated 32 source-derived consistency controls and arbitrary user-provided `--requests` JSON. The Phase 5A external GitHub intake was also inspected for possible automatic promotion into human labels; it continues to report zero verified expert labels.

## Finding F5B-01 — ambiguous expected-label provenance

**Severity: medium, evidence-integrity issue; not a runtime exploit.**

In the pre-patch `run()` function, any user-provided item with an `expected` field was emitted as `constructed_expectation` and compared with the deterministic verdict using `matches_source_derived_expectation`. When all caller-chosen labels matched, the report incremented `constructed_fixtures_checked` and `constructed_fixture_matches` as though the source checker had generated those cases itself.

**Reproduction:** Supply a legitimate immutable Koa fixed-source PASS claim with `expected: SUPPORTED` via `examples=[...]`. The previous logic marked this externally supplied label as a constructed expectation; it could report `constructed_fixture_matches: 1`, even though the person calling the tool chose the label. This is a **provenance/measurement labeling flaw**, not evidence that the tool makes incorrect parent/fixed decisions.

**Correction:** The code now distinguishes `INTERNAL_SOURCE_DERIVED_REGRESSION_FIXTURES` (only when the internal suite is generated) from `EXTERNAL_INPUT_UNVERIFIED_CALLER_EXPECTATIONS`. External inputs with an `expected` value get `unverified_caller_expected_verdict` and `matches_unverified_caller_expectation`; their `constructed_fixtures_checked` and `constructed_fixture_matches` are both **zero** regardless of matching or disagreement. Incorrect caller expectations remain visible as disagreement, not a broken authoritative benchmark.

**Regression coverage:** A new matching caller-label test, a deliberately incorrect caller-label test, and a control asserting the original 32 internally derived checks retain their correct and explicit provenance. These use checked-in authentic Phase 4U witness SHA sources, but are not independent new security labels.

## Other inspected boundaries

- The checker accepts only four immutable, previously executed source-fix stages; it cannot judge arbitrary natural-language security reviews.
- Valid source blobs and execution-receipt SHA values are required to support historical test PASS/FAIL claims.
- Unsupported production exploitability and universal-security assertions lead to ABSTAIN.
- The Phase 5A issue-form checker validates citation identity and formatting, but **does not** prove that cited code establishes the reviewer's interpretation or expertise. This boundary is correctly explicit in the code and report.
- No private source, secret, or paid network inference was needed for this review.

## Remaining unresolved technical and evaluation risks

1. There is still no demonstrated independent reviewer assessment and no approved human AppSec gold label.
2. Source-cited historical test correctness is **not** the same as source-semantic evaluator accuracy on unfamiliar, unstructured review text.
3. Four immutable source checks make an effective provenance integrity demonstration, but are insufficient to claim broad generalization.
4. The earlier failed LoRA is unchanged; there is no evidence here of trained-model improvement, Telegraph adapter registration, actual mission-app adoption, new Anjoman rows, or a hackathon entry.
5. A separate real qualified human reviewer may find weaknesses the current AI-assisted examination missed. This review must never be cited as fulfilling that requirement.

## Review outcome

**Real issue found and patched: F5B-01.** This increases evidence-report integrity but does not itself prove superiority to another evaluator or make the submission first place. CI and source-level tests are the acceptance criteria. No formal external penetration test, third-party code audit, human gold labeling or deployed exploit verification is claimed.
