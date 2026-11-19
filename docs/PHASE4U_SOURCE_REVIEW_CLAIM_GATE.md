# FALSUM | Executed-source security review claim gate

**Telegraph Season II · Evaluators · `SECURITY_REVIEW_GENERAL`**  
**Mode: offline, deterministic, source-evidence based. No trained model or registered Anjoman adapter.**

FALSUM's core problem is not a lack of security-sounding advice. It is the gap between **what the code and test results establish** and what a reviewer confidently claims. The evidence gate makes that gap testable. It answers one narrow question: *Does this structured claim about a particular real upstream security regression agree with the exact recorded parent/fixed test execution?*

**[Try the seven example claims](../examples/source-review-witness-claims.json)** · [Source code](../src/falsum/source_review_witness_gate.py) · [Source-verified runtime proof](PHASE4T_ONE_COMMAND_REAL_SOURCE_TEST_PROOF.md) · [Automated test workflow](../.github/workflows/phase4u-typed-security-witness-gate.yml)

## How this actually works

The input is a **typed machine-readable review claim**, not unrestricted natural-language text. For each of four executed security-fix stages (Koa redirect guard, Hono `text/ping` CSRF, and LangChain initial path validation and later symlink target suffix check), a reviewer specifies:

- `case_id`, full historical `upstream_commit` SHA, and `claim_type`.
- The actual `source_blob_sha1`, identical upstream regression `new_security_regression_test_blob_sha1`, and the original `actual_execution_receipt_sha256`.

The checker verifies those values against the [permanent source witness index](../evidence/phase4u-2026-11-18-permanent-four-executed-source-witness-index.json). That index is a compact **derived, non-verbatim record** pinned to the actual [authenticated four-stage Actions artifact](https://github.com/Iniwura/falsum/actions/runs/44356563508). It includes the original CI report SHA-256 so the source report can be checked byte-for-byte while it remains downloadable. The permanent index is **not a replacement for replaying the original four upstream projects**; the original proof remains separately reproducible.

The only supported decisions:

| Typed reviewer claim | Evidenced vulnerable parent | Evidenced fixed commit |
|---|---|---|
| `UPSTREAM_REGRESSION_FAILS` | **SUPPORTED** | **CONTRADICTED** |
| `UPSTREAM_REGRESSION_PASSES` | **CONTRADICTED** | **SUPPORTED** |
| `CONFIRMED_PRODUCTION_EXPLOIT` | **ABSTAIN** | **ABSTAIN** |
| `GUARANTEED_UNIVERSAL_APPLICATION_SAFETY` | **ABSTAIN** | **ABSTAIN** |

A missing or wrong commit, source/test Git blob, case identity or authentic runtime receipt digest yields **ABSTAIN**, never a fabricated support/contradiction verdict. An extra or malformed field, changed source selection, forged source-only claim, or attempt to mark the results as human gold is rejected.

This approach can catch **specific evidence-incompatible security-review statements** and enforce evidence-limited scope without pretending to understand prose or hallucinated application context.

## Reproduce without API keys

The source selection, permanent evidence digest and example inputs are included in the public GitHub repository. Only Python 3.11 or newer is needed:

```bash
git clone https://github.com/Iniwura/falsum.git
cd falsum

PYTHONPATH=src python -m falsum.source_review_witness_gate \
  --index evidence/phase4u-2026-11-18-permanent-four-executed-source-witness-index.json \
  --source-lock data/phase4p-three-project-open-review-lock.json \
  --requests examples/source-review-witness-claims.json \
  --out /tmp/falsum-example-witness-verdicts.json
```

The seven included examples yield **2 SUPPORTED, 2 CONTRADICTED, 3 ABSTAIN**. They cover correct code facts, incorrect before/after claims, false source-digest binding, and claims about production exploitability that historical unit tests cannot establish.

Omit `--requests` and choose another unique output filename to generate **32 deterministic, source-derived test fixtures**: 8 supported, 8 contradicted, 16 abstained. The checker agrees with its own 32 construction expectations **by construction**. That is a regression suite for the checking logic and guards, **not 100% model accuracy**, not independent gold and not a credible basis for release as a hybrid LoRA or network evaluator.

**Adversarial review correction (November 19, Phase 5B):** A user-supplied JSON request may include an `expected` verdict. Such an assertion is now explicitly marked **unverified caller expectation**, whether it agrees with the source-derived result or not. It can never increase `constructed_fixtures_checked` or `constructed_fixture_matches`, because only FALSUM's internally generated 32 controls are considered constructed fixtures. This closes a provenance confusion where caller-chosen labels could previously be presented using the stronger constructed-fixture terminology. Neither internally constructed matches nor matching caller assertions establish machine-learning accuracy, expert human approval or a blind benchmark.

Run adversarial tests across the Python versions with [Phase 4U CI](../.github/workflows/phase4u-typed-security-witness-gate.yml).

## Evidence provenance and limitations

- Original real upstream source-test execution: [Koa and Hono Actions](https://github.com/Iniwura/falsum/actions/runs/44352329150) and [both LangChain patch stages](https://github.com/Iniwura/falsum/actions/runs/44353999011). Each original upstream baseline passed, the newly authored **upstream security regression failed on its vulnerable original branch**, and the same regression passed on the exact fixed revision.
- Aggregate test-run digest and proof-index link: [Phase 4T](https://github.com/Iniwura/falsum/actions/runs/44356563508) and the [permanent SHA-index snapshot](../evidence/phase4u-2026-11-18-permanent-four-executed-source-witness-index.json).
- The source run artifacts expire after GitHub's retention period. Source code, selected SHA pins, permanent digest index and replay workflows remain. Without the original raw artifacts, a third party cannot independently recompute all four historical process-log digests from the permanent index alone; they can re-run the preserved actual upstream tests to create new execution receipts.
- The checker does not inspect an arbitrary application's own security posture; it does not establish that a third-party deployment is exploitable or patched. It cannot parse natural language and has no hidden expert-validated model preferences. It is a deterministic **review evidence process**, not the general `SECURITY_REVIEW_GENERAL` evaluator.
- **Human-independent expert labels: 0.** The prior assistant source-review notes were AI-authored and cannot be counted as external human adjudication. The original experimental LoRA has not demonstrated measured gain and is still unreleased. No new Anjoman Eligible contributor pairs were created by this offline gate; the user's existing 20 Eligible rows are a separate submission with separate provenance.
- No user secrets, paid miner requests, hidden prompts, confidential vulnerabilities, uploaded keys or signing are required.

The strongest claim here is **new reproducible and counterfactual source-execution evaluation coverage**. This is meaningful to an Evaluators track because it gives reviewers a way to distinguish evidenced test facts from wrong or unsupported security conclusions. It is deliberately not overstated as a novel high-performing neural scorer or expert gold benchmark.

**Demo recording remains paused. Official H2 final submission is not filed by this workflow.**
