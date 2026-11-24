# FALSUM — judge start here

**Telegraph Season II · Evaluators · SECURITY_REVIEW_GENERAL**  
**Evidence checkpoint: November 24, 2026. Submission status: NOT SUBMITTED.**

## The problem

A security-review response can be fluent, paid-flagged and still fail its actual task: it may return unrelated advisories, use the wrong Intent or claim that a vulnerability is fixed without authentic source evidence. In the [independently published PR Guard report](https://github.com/telegraphprotocol/bounties/issues/187), a canonical security-review request about lodash returned an unrelated bulk advisory feed. This is a documented integration failure candidate, **not** proof of faulty onchain settlement, a published benchmark ranking or security exploitation.

**FALSUM's contribution:** reproducible *evaluation material* that tests whether claims follow immutable original source and version evidence, exposes unsupported conclusions, and keeps unlike request/receipt types out of unfair comparisons. This is a source-grounded evaluation testbed, not an improved registered neural evaluator or comprehensive vulnerability scanner.

## The latest measured application result

Two Mission 14 applications, Truvian Shield and Gig Guard, independently published the underlying security-intelligence failure records. FALSUM's [cross-app audit](PHASE5AJ_CROSS_APP_EVIDENCE_AVAILABILITY.md) authenticated seven original Git files and checked 34 decision records and 41 archived receipt joins. The [complete historical scale comparison](PHASE5AK_EXTERNAL_LABEL_BASELINES.md) separately replays 158 decision events, 129 latest labeled contracts and 202 purchases (201 archived SETTLED, one NOT_FOUND). These populations are **not necessarily disjoint**; do not add them to claim a larger unique-case dataset.

| Policy | Vulnerable flagged / 107 | Vulnerable PASS | Vulnerable unknown | Audited controls flagged / 22 |
| --- | ---: | ---: | ---: | ---: |
| Count only | 80 | 8 | 19 | 1 |
| Verdict only | 89 | 0 | 18 | 5 |
| Strict field agreement | 80 | 0 | 27 | 1 |
| FALSUM consumer | 89 | 0 | 18 | 5 |

The bounded policy avoids eight count-only unsafe pass predictions, **ties verdict-only** and increases flags on audited controls. Audited contracts are not certified bug-free; those flags are not verified false positives. PASS is a policy prediction, never security clearance. [Actual successful scale replay](https://github.com/Iniwura/falsum/actions/runs/45356819921). [Cross-app replay](https://github.com/Iniwura/falsum/actions/runs/45356083445). [Open collaboration request](https://github.com/Iniwura/falsum/issues/97) — no outside response or adoption confirmed.

## Try it in five minutes

### 1. Witness a real historical source regression (60–90 seconds)

Open the [public source-evidence workbench](https://falsum-evidence-lab.vercel.app/witness/). Choose one of **five independently authored historical upstream fix stages** across Koa, Hono, LangChain and Flask. Compare the named original vulnerable and fixed source/test evidence. Submit an accurate source-test claim, then change its recorded receipt hash: without authenticated evidence, the checker must abstain.

The workbench's **80 typed outcomes** are deliberately *constructed controls*: 10 SUPPORTED, 10 CONTRADICTED and 60 ABSTAIN. They are **not** 80 external human AppSec gold judgments or a trained-model accuracy score. The source/test history itself is real and immutable-bound.

### 2. Reproduce outside the owner's machine (90 seconds)

[Fork the public repository](https://github.com/Iniwura/falsum) → Actions → **Independent Reviewer Replay - public evidence only** → Run workflow. The Action needs no wallet, secret, paid request or model download. Inspect its public-safe artifact `falsum-public-reviewer-replay` and report exact contradictions using the [independent reproduction form](https://github.com/Iniwura/falsum/issues/new?template=independent-public-reproduction.yml).

It authenticates **12 independently published receipt captures**, **6 historical reviewed GHSA files**, **3 separate Axios/Rack reviewed GHSA files**, and the pinned original cross-app and scale records. The two application reports retain separate provenance and historical receipt status boundaries. Its constructed tests show an applicable Axios advisory, opposing Rack version outcomes, and an `INSUFFICIENT_EVIDENCE` result where prerelease semantics are not supported. It also runs routing and tampered-lock counterexamples.

[Original author-run PR #94 replay (successful)](https://github.com/Iniwura/falsum/actions/runs/45319267361) produced public-safe artifact ID `14885889459`. **An owner-run workflow is not independent adoption.** An outside developer's actual fork run and critique are still awaited.

### 3. Make your own bounded package decision (60 seconds)

From the cloned repository, with Python 3.11+ and a terminal (no package install needed):

```bash
PYTHONPATH=src python -m falsum.cli review-verified-references \
  --ecosystem npm --package axios --version 1.5.0 \
  --reference GHSA-wf5p-g6vw-rhxx \
  --out axios-review.json
```

Expect `VERIFIED_APPLICABLE`. On Windows PowerShell, run `$env:PYTHONPATH = 'src'` first, then omit `PYTHONPATH=src` from the command. The output file must not exist beforehand: FALSUM uses create-only evidence writes.

Try changing the target version to `1.6.0` with a new output filename. Expect `VERIFIED_INAPPLICABLE` **for that one pinned advisory**, not a claim that Axios is secure. Try an unknown GHSA and observe `UNKNOWN_SOURCE`. [Full source protocol and other cases](PHASE5AG_MULTIECOSYSTEM_REVIEWED_REFERENCE_EVALUATOR.md).

### 4. Inspect the negative control (30 seconds)

[Original Qwen raw-code evaluation run](https://github.com/Iniwura/falsum/actions/runs/44852933182): a researcher-run, published Qwen2.5-0.5B-Instruct model returned ABSTAIN on all 12 authenticated public code tasks, matching **4/12** public author-reference answers and **0/4** complete source reversals. A disclosed source-blind rule matches 8/12. FALSUM explicitly published the negative result; this did **not** improve or register a Telegraph scoring model.

## Evidence boundary: what judges can and cannot infer

| Verified, reproducible project evidence | Not established |
| --- | --- |
| Five original historical upstream fix stages on the public witness site; six historical regression stages in CLI/CI | Independent AppSec gold or broad security reasoning correctness |
| Twelve public third-party response captures authenticated by original Git blob identities | Verified paid settlement, equal-request multi-Miner ranking, or real provider accuracy |
| Six historical and three new upstream GitHub-reviewed advisory blobs; bounded per-reference decisions | Complete or fresh advisory feed, arbitrary-package support, or package security clearance |
| 13 source-backed, preregistered **constructed** Axios/Rack cases, plus new adversarial parser checks | New blind holdout, outside model evaluation, or general model recall |
| One-click public fork workflow and author-controlled real CI artifact | A verified outside fork replay, integration, retention or independent reviewer |
| Production Vercel deployment verified at the Phase 5AK checkpoint `8df1942791dc2fcd1b9de4ae5bdf46624839d62a`, READY; **6/6** successful post-merge workflows as checked November 24; see [latest freshness workflow](https://github.com/Iniwura/falsum/actions/workflows/phase5e-live-production-source-freshness.yml) | Browser-time arbitrary model scoring endpoint or official Telegraph network registration |

The historic 12-response audit observed **2** canonical routed requests with matching reported receipt Intents, **2** direct requests with canonical-reported receipts, **6** successful outputs with noncanonical receipt Intents, and **2** failed captures without successful receipts. There are **zero** pairs proving different miners answered the *same exact* canonical request. Do not turn these into a fair ranking. Source Git authenticity does not independently authenticate payment.

## Why this fits the Evaluators track

The [official Season II rules](https://anjoman.ai/dashboard/hackathon/season-2/rules) explicitly permit **evaluation material** as the contribution, even without a registered adapter. Stronger delivery claims need repeated mission-specific results and independent verification. The intended buyer is an application builder using `SECURITY_REVIEW_GENERAL` to screen PRs or dependency updates, especially the Model Economy and Web3/DeFi missions. The public PR Guard fixture is a real external integration *problem*, **not** an accepted FALSUM customer integration.

FALSUM's value is to make unsupported security judgments visible and reproducibly challengeable before an app trusts them. Its bounded abstention and original-source provenance are technical evidence; network ranking improvement, real adoption and qualified expert labels remain unproved.

## Submission checklist — do not silently mark complete

| Requirement | Confirmed as of this checkpoint? |
| --- | --- |
| Public GitHub source and working production URL | Yes |
| Repeatable judge workflow with public error/unknown controls | Yes |
| Honest real Telegraph source integration and public receipt samples | Yes, **historical external data only**, scope limited above |
| Required star of `telegraphprotocol/bounties` from entrant's GitHub account | **Unverified** |
| Final Season II entry and track/mission form receipt | **Not submitted** |
| Required 2–5 minute video or organizer-accepted accessible equivalent | **Not verified** |
| Public updates on three separate dates and public distribution evidence | **Not verified** |
| Verified outside adoption, independent fork use, qualified AppSec gold | **None verified** |
| User-selected showcase permissions and buyer-introduction consent | **Not confirmed** |

**Official deadline: December 1, 2026, 23:59 UTC.** The user must confirm account-dependent fields and showcase permissions; do not submit or make those choices without their instruction.

For deeper reproducibility: [five-minute technical walkthrough](H2_FIVE_MINUTE_JUDGE_REPRODUCTION.md), [independent reviewer guide](INDEPENDENT_REVIEWER_START_HERE.md), [advisory verifier](PHASE5AG_MULTIECOSYSTEM_REVIEWED_REFERENCE_EVALUATOR.md), [form-ready draft](H2_FINAL_ENTRY_DRAFT.md).

This page is a navigable judge path and factual release checkpoint, **not** an acceptance receipt, outside review, advertisement of security clearance or proof that the competition is won.
