# Phase 5L — Sixth real upstream security regression, fifth source project

**Telegraph Season II · Evaluators · SECURITY_REVIEW_GENERAL · 20 November 2026**

This is **one additional researcher-selected historical security fix in a source project not covered by the original five-case source-replay workbench**. It is an external project's real upstream-authored code and real maintainer-authored regression test; the source selection was frozen in a standalone Git commit **before the replay implementation and CI**. This is better primary-source verification coverage, **not a blind holdout, independent human gold, learned evaluator accuracy or registered Telegraph model**.

## Public upstream fix and exact original source/test evidence

**Repository:** [facelessuser/pymdown-extensions](https://github.com/facelessuser/pymdown-extensions)

**Advisory:** [GHSA-62q4-447f-wv8h](https://github.com/advisories/GHSA-62q4-447f-wv8h), pymdownx snippets path restriction. The previous implementation compared raw string prefixes of a configured allowed directory and a requested snippet path. A sibling directory sharing that prefix was incorrectly accepted; the maintainer's exact fix requires an actual path boundary. The only test data used here are harmless local "Snippet" fixtures. No customer files, live applications, external secrets or real attack targets are read.

| Verified original source identifier | Fixed value |
| --- | --- |
| Direct vulnerable parent Git commit | 3d185501daaa1424c4a8d42124112c44ef6ab635 |
| Original upstream fixed Git commit | 63b7835776d703d6c339cf2110d9888f676efc0c |
| Vulnerable original pymdownx/snippets.py Git blob SHA-1 | 305c7c0aae68516f4aad77c2430234762e981688 |
| Fixed original pymdownx/snippets.py Git blob SHA-1 | b808d7b929fec0962c4b41ca0a70ed4e696d0fc5 |
| Original parent test module Git blob SHA-1 | 11ef10b8d7c65c23c20f11341b39db2ba8e8699e |
| Original upstream fixed-commit test module Git blob SHA-1 | da1f2cd3c893c1e1257511339ca1e7e706d32bfc |
| Original upstream new harmless fixture Git blob SHA-1 | 528c55e3ae5ab31701e42285503ea9538f175afb |
| Previously frozen case-selection lock Git blob SHA-1 | 79e27d78376dde9cdd9d4e628a95cc3cc7ae63ee |
| Maintainer-written regression selected | TestSnippetsNested.test_restricted_directory_traversal |
| Maintainer-written original parent control | TestSnippetsNested.test_restricted |

The Git hashes were retrieved from public upstream historical file records and frozen before any tests ran. The exact complete test file and harmless fixture come from the maintainer's **original fixed commit**, not an AI-written imitation.

## What the live CI actually must do

[Actual GitHub Actions workflow](../.github/workflows/phase5l-sixth-upstream-original-regression.yml) checks out the public upstream repository at the fixed commit and tests it on Python 3.11 and 3.13. It validates the actual fixed commit's direct-parent relationship, each Git source/test/fixture blob, the active Git worktree, and both raw subprocess outcomes.

For each Python version, three genuinely executed upstream test processes are required:

1. **Parent original behavior:** run the vulnerable parent's pre-existing restricted-snippet test unmodified. It must PASS.
2. **Parent with exact upstream security regression:** place the untouched original fixed-commit maintainer test module and fixture into the vulnerable-parent Git source worktree; execute exactly the new TestSnippetsNested.test_restricted_directory_traversal. It must FAIL for the expected **"SnippetMissingError not raised" assertion**. An import error, setup issue, unrelated assertion, skip or timeout cannot count as a security reproduction.
3. **Original fixed source with exact same upstream regression:** execute that unchanged new maintainer-authored test on the precise fixed Git commit. It must PASS.

All six subprocess logs and SHA-256 hashes are retained as GitHub Actions artifacts. An aggregate job validates six distinct stage/runtime records against the precommitted selection and requires the exact outcomes above. No artifact is valid without its corresponding successful, original, real GitHub Actions run; **passing local synthetic schema tests is not equivalent to upstream execution**.

Real expected per-Python exit matrix:

| Stage | Python 3.11 | Python 3.13 |
| --- | --- | --- |
| Original vulnerable-parent control | PASS (0) | PASS (0) |
| New maintainer security test overlaid on vulnerable-parent code | Expected assertion FAIL (1) | Expected assertion FAIL (1) |
| Exact same upstream test on fixed original source | PASS (0) | PASS (0) |

**Status evidence:** do not cite this original execution as achieved until the linked GitHub Actions run succeeds with all six jobs and the aggregate artifact. The code and lock alone demonstrate a test design, not a completed replay.

## What becomes stronger, and what does not

**If and only if actual CI passes:** FALSUM will have six genuine original upstream source-test regression stages across **five distinct upstream projects**: Koa, Hono, two LangChain repair stages, Flask and this pymdown-extensions regression. This excludes the differently sourced Starlette and Requests installed-library historical method replays from the identical-method count.

This extra stage is **separate from** the earlier public 5-source witness checker and its existing 80 constructed browser outcomes. The new project has not automatically been admitted into that verifier, the browser, the Phase 5F or 5K candidate scorecards, or an actual model-scored novel-case benchmark. The old trained LoRA failed its original recorded evaluation and remains unchanged.

The case was **researcher-selected after consulting a public advisory**. It is new relative to the five authenticated source witness projects but is not a blind test of model generalization, independently chosen gold, externally reviewed code, production exploitation proof, new Anjoman Eligible rows, a registered evaluator or official H2 final entry.

## Reproduction

No wallet, paid API or secret key. To run all original upstream source/test jobs, review and trigger the public [Phase 5L workflow](../.github/workflows/phase5l-sixth-upstream-original-regression.yml), or push this branch with its source/test paths changed. It checks out exactly the pinned upstream Git commit and uses pinned Markdown, PyYAML, pytest and Pygments versions. The FALSUM code verifies the frozen pre-run lock by its Git blob SHA-1 and checks executed logs with SHA-256.

Developer-run **offline test-fixture validation only** (does not fetch or run third-party code):

~~~bash
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_phase5l_pymdown_upstream_replay.py' -v
~~~

A successful real workflow produces six original GitHub Actions process-log artifacts and one combined JSON proof, with one public run ID. Link the actual run ID when reporting completion, and preserve negative or setup failures rather than replacing them with invented records.

### Judgment relevance

This is a genuine increase in **reproducible primary-source repair evidence and source-disjoint coverage**. It is *not* evidence of improvement in actual security-review model predictions, which remains FALSUM's main competitive weakness. A true evaluator comparison would require freezing and running a candidate against independently adjudicated new source cases, declaring source-aware and source-blind baselines, reporting attempted-case coverage separately and preserving all failures. Independent expert reviews and external developer adoption remain unverified.

No video, official submission, wallet action or third-party outreach occurred in this phase.
