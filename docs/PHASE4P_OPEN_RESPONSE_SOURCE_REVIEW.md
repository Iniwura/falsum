# Phase 4P: source-first, open-ended security-review challenges

**FALSUM | Telegraph Season II Evaluators | `SECURITY_REVIEW_GENERAL`**  
**Status: unreviewed research candidates, not independently accepted security gold, not a trained evaluator, and not the 20 existing Anjoman Eligible contributor rows.**  
**No demo produced.**

## Why this differs from the older A/B cases

The [Phase 4O audit](PHASE4O_SHORTCUT_ROSTER_AND_REVIEW_GATE.md) found **13/14 original researcher-preference matches by choosing whichever answer was longer**, and found a second high-scoring question-word-overlap shortcut even after six post-audit rephrasings. That makes repeating the old A/B format an unwise way to claim evaluative rigor.

Phase 4P tests a different format: **open-ended source reasoning**. A reviewer gets an immutable historical fix, the parent source, an actual regression-test change, and a task requiring the mechanism and application preconditions. The challenge offers no A/B answer to guess, no author preference to copy, and explicitly accepts justified ABSTAIN.

## New source projects and exact change evidence

The [source selection was frozen in Git before the new verifier was implemented](../data/phase4p-three-project-open-review-lock.json). It includes **three repositories absent from FALSUM's earlier seven source families and four-project Foundation probe**, spanning three distinct failure modes. The dedicated workflow checks the exact SHA of each public commit, its direct parent, source/test changes, and the **16 historical Git blobs** of the chosen source and test files before and after each fix.

### 1. Koa: unsafe trust in protocol-relative Referrer/Referer

**Case:** `phase4p-koa-referer-redirect`  
**Fix:** [769fd75cc6b30d72493b370b5a3ae2332ca03c5b](https://github.com/koajs/koa/commit/769fd75cc6b30d72493b370b5a3ae2332ca03c5b)  
**Before:** [parent source](https://github.com/koajs/koa/blob/433b20c9e5954113e8d7a23a25e9d5bb750c3034/lib/response.js)  
**After:** [fixed source](https://github.com/koajs/koa/blob/769fd75cc6b30d72493b370b5a3ae2332ca03c5b/lib/response.js) · [changed regression test](https://github.com/koajs/koa/blob/769fd75cc6b30d72493b370b5a3ae2332ca03c5b/__tests__/response/back.test.js) · [advisory](https://github.com/koajs/koa/security/advisories/GHSA-g8mr-fgfg-5qpc)

Questions: Explain the exact `back()` branch behavior before and after the patch for a protocol-relative `Referer` (a string beginning `//`), using source and test line citations. Separately, identify conditions needed to make this observable in a deployed app and what cannot be established from the code alone.

### 2. LangChain Core: path validation and a later symlink follow-up

**Case:** `phase4p-langchain-prompt-path`  
**Initial change:** [27add913474e01e33bededf4096151130ba0d47c](https://github.com/langchain-ai/langchain/commit/27add913474e01e33bededf4096151130ba0d47c)  
**Follow-up:** [0b5f2c08ee256473e368372a803c5c92039c0a4e](https://github.com/langchain-ai/langchain/commit/0b5f2c08ee256473e368372a803c5c92039c0a4e)  
**Source:** [initial path validation](https://github.com/langchain-ai/langchain/blob/27add913474e01e33bededf4096151130ba0d47c/libs/core/langchain_core/prompts/loading.py) · [follow-up symlink/suffix handling](https://github.com/langchain-ai/langchain/blob/0b5f2c08ee256473e368372a803c5c92039c0a4e/libs/core/langchain_core/prompts/loading.py)  
**Tests:** [initial test changes](https://github.com/langchain-ai/langchain/blob/27add913474e01e33bededf4096151130ba0d47c/libs/core/tests/unit_tests/prompts/test_loading.py) · [follow-up symlink tests](https://github.com/langchain-ai/langchain/blob/0b5f2c08ee256473e368372a803c5c92039c0a4e/libs/core/tests/unit_tests/prompts/test_loading.py) · [advisory](https://github.com/langchain-ai/langchain/security/advisories/GHSA-qh6h-p6c9-ff54)

Questions: Explain the exact default path-validation boundary **and why inspecting only the initial change would miss the later source/test change**. Identify what caller control, file-extension checks, symlinks, and trusted opt-in behavior mean for realistic impact. An upstream code fix alone does not prove a live file disclosure.

**Important:** The two commits need not be immediately consecutive in the repository history. The frozen, independently re-fetched Git **source and test blob IDs** prove that the relevant files entering the follow-up stage still had the post-initial-patch contents. Both commits' own direct parents are verified separately. Do not claim the initial patch was the complete final remediation.

### 3. Hono: hyperlink auditing sends `text/ping` POSTs around a CSRF assumption

**Case:** `phase4p-hono-hyperlink-csrf`  
**Fix:** [bf16471913b5199212dac33f5d170f94745dd26a](https://github.com/honojs/hono/commit/bf16471913b5199212dac33f5d170f94745dd26a)  
**Source:** [csrf middleware](https://github.com/honojs/hono/blob/bf16471913b5199212dac33f5d170f94745dd26a/src/middleware/csrf/index.ts) · [changed `text/ping` regression tests](https://github.com/honojs/hono/blob/bf16471913b5199212dac33f5d170f94745dd26a/src/middleware/csrf/index.test.ts) · [advisory](https://github.com/honojs/hono/security/advisories/GHSA-46wx-v44x-9hh2)

Questions: Explain the exact `Content-Type` path for cross-origin `text/ping` before and after the change. Address browser and cookie behavior, handler side effects and configured CSRF policy. Do not claim every `csrf()` deployment was exploitable.

## How a real independent reviewer should participate

Open the [Phase 4P review form](https://github.com/Iniwura/falsum/issues/new?template=independent-phase4p-open-review.yml). Choose **one** case and inspect the **source and regression test at the exact fixed SHA**, plus the preceding source and official advisory. Respond in the review form with:

1. Exact line-linked primary source/test citations and a concise explanation of the mechanism.
2. A distinct account of application preconditions, limitations and any counterexamples.
3. A concise answer to **each** of the two open questions, or a clearly justified **ABSTAIN**.
4. Any disagreement with the advisory, source interpretation or claimed coverage, documented precisely.

No private exploit details, credentials, restricted data, hidden Anjoman preference pairs or privileged production access should be provided. FALSUM must not claim a format-valid GitHub issue constitutes independent professional adjudication. Reviewer expertise/independence, original analysis, conflicting assessments and reproducibility need separate verification.

## Quality evidence and release boundaries

The [Phase 4P CI](../.github/workflows/phase4p-source-open-review.yml) is designed to fail on altered source locks; nonexistent or wrongly parented fixes; fake source/test blob IDs; missing tests; redirected/oversized raw files; duplicate projects; and any attempt to claim a label, trained evaluator, network eligibility or model improvement without real proof.

- Three source-disjoint public upstream projects: **yes**, relative to FALSUM's earlier named and scored sources.
- Four verified historical source+test change stages: **requires the real CI proof**.
- Six open-ended challenges without supplied answer keys: **yes**.
- Independent source expert adjudications: **zero verified**.
- Actual trained-model scoring on this set: **not performed**.
- Statistically valid holdout of model pretraining: **not established**, because all the sources are public and known when this review was prepared.
- Official Anjoman acceptance or new Eligible rows from these questions: **not claimed**.

**Release decision:** This is a more defensible *review challenge format*, not a new gold standard. It strengthens source coverage while preserving the current model-registration and training veto until genuinely independent label and scoring evidence is available.
