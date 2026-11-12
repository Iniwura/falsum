# Phase 4E — counterbalanced security-fix reviewer pack

**FALSUM · Telegraph Season II Evaluators · November 12, 2026**

## First-place objective

Our win condition is independently useful security-review evaluation material, not another polished prototype or another easy CVE-version lookup. The repository already contained **seven real upstream security-fix case candidates** from Phase 3F. This phase rechecks them against immutable published source and regression-test commits, then makes **two position-swapped presentations per case** for fair external review.

This is **seven previously researched upstream cases**, not seven newly accepted submissions. Fourteen presentations are two letter orders of seven cases, **not fourteen independent labels**. The material is public and is not a blind model holdout. There are no independent expert judgments or approved training labels.

## Seven distinct behavior and applicability questions

| Real fix | Reasoning requirement | Pinned upstream source |
|---|---|---|
| Requests | Proxy credentials and redirect reachability | [Fix](https://github.com/psf/requests/commit/74ea7cf7a6a27a4eeb2ae24e162bcc942a6706d5) |
| Jinja | Untrusted template source versus variable input | [Fix](https://github.com/pallets/jinja/commit/065334d1ee5b7210e1a0a93c37238c86858f2af7) |
| Axios | Attacker-controlled absolute URL and effective base URL options | [Fix](https://github.com/axios/axios/commit/02c3c69ced0f8fd86407c23203835892313d7fde) |
| Starlette | Actual path containment versus matching filename prefix | [Fix](https://github.com/Kludex/starlette/commit/1797de464124b090f10cf570441e8292936d63e3) |
| urllib3 | Credential header casing across cross-origin redirects | [Fix](https://github.com/urllib3/urllib3/commit/adb358f8e06865406d1f05e581a16cbea2136fbc) |
| Django | Reachability of unusual unbounded numeric formatting | [Fix](https://github.com/django/django/commit/55519d6cf8998fe4c8f5c8abffc2b10a7c3d14e9) |
| Express | Malformed-URL parser disagreement with redirect allowlists | [Fix](https://github.com/expressjs/express/commit/0b746953c4bd8e377123527db11f9cd866e39f94) |

Every packet includes the exact published fix commit, source-file Git blob and SHA-256 patch hash, regression-test file and hash, advisory URL, review question, two SHA-256 bound researcher-authored answers, source preconditions to challenge, and missing application deployment facts. The upstream fix itself is **not proof of exploitation in another application**.

## Position-bias control

Each of the seven source questions is presented twice:

- Original: answer text 1 in position A and answer text 2 in position B.
- Swapped: the *same exact candidate texts*, with the **same SHA-256 identities**, in opposite positions.

Changing letter alone must never create a new gold label or a new independent case. The pack preserves both opinions as **unadjudicated**, and all training, network eligibility and registration gates as **false**.

The first research question is whether a source-aware evaluator or human reviewer selects the same *answer text* after the letters change. No actual model or expert stability score has yet been measured by generating these variants.

## Reproduce from real upstream commits

Python 3.11+ and GitHub public API access are needed for the full authentic-source check:

~~~bash
PYTHONPATH=src python -m falsum.phase3f_multifamily_material \
  --old-queue data/real-fix-queue.json \
  --train-queue data/real-fix-train-candidates.json \
  --catalog data/phase2w-applicability-rules.json \
  --out /tmp/FALSUM-REVERIFIED-SEVEN-FAMILIES.json

PYTHONPATH=src python -m falsum.phase4e_counterbalanced_reviews \
  --input /tmp/FALSUM-REVERIFIED-SEVEN-FAMILIES.json \
  --out /tmp/FALSUM-SEVEN-REVIEW-PACK.json

PYTHONPATH=src:tests python -m unittest discover -s tests \
  -p test_phase4e_counterbalanced_reviews.py -v
~~~

The unit tests use **synthetic** upstream fixture objects to check refusal-to-train, provenance and letter-swapping invariants. [Dedicated real-source CI](../.github/workflows/phase4e-seven-family-review.yml) separately recontacts eight pinned upstream Git fix commits and verifies the source and regression-test patch objects. It stores the generated pack for 90 days. Neither mock unit tests nor successful Git metadata fetches certify real-world exploitability or accuracy.

## Ask a genuine expert, not a friendly chatbot, to challenge the material

[Read all seven case texts](REVIEW_ONE_CASE.md) · [Open independent GitHub source-review form](https://github.com/Iniwura/falsum/issues/new?template=independent-seven-review.yml) · [Open review invitation](https://github.com/Iniwura/falsum/issues/25)

A reviewer must read an exact source patch, its regression test and the advisory, state whether answer A, B or ABSTAIN is supported, give immutable source and test line citations, and list what deployment facts are unverified. **Negative findings and abstentions are valid.**

For counterbalancing, reviewers may also inspect the two views and compare the candidate text hashes rather than the A/B letters. The existing form expects the **original** A/B order, so the swapped observation belongs in the reasoning, not a silently remapped answer.

A GitHub comment is not automatic proof of expert credentials. FALSUM's existing review-intake parser rejects owner self-reviews and some duplicate claims, but the actual reasoning and reviewer independence require separate checking.

**Current independent expert labels: 0.** The 20 previously account-reported Eligible Anjoman pairs are a separate private contributor flow, not these seven researcher-authored candidates. No additional eligible rows or network models are claimed.

## Winning gates

1. Obtain genuinely independent security-source reviews and resolve disagreements.
2. Measure a meaningful evaluation improvement against a fair baseline on a **new, project-disjoint, independently adjudicated** set; do not reuse these public prompts as hidden test data.
3. Demonstrate the differentiated behavior/applicability material and explain the difference from simple GHSA version lookup.
4. Publish real education/reproduction updates and a clear 2–5 minute live-screen demo.
5. Verify the real Anjoman status, complete the official H2 entry and preserve its receipt by **December 1, 2026 at 23:59 UTC**.

**This phase increases the usefulness and independent reviewability of our existing material. It is not a better trained LoRA, accepted bounty, completed submission or guarantee of first place.**
