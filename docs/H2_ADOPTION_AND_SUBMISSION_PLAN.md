# FALSUM — evidence-led developer activation and final-entry plan

**Updated 21 November 2026.** Telegraph Season II · Evaluators contribution · security-review evaluation material. **Status: NOT SUBMITTED.** This is a living operating plan, not evidence that drafts have been posted or anyone independently adopted the project.

**Official final deadline:** [1 December 2026, 23:59 UTC](https://hackathon.telegraphprotocol.com/rules). The December follow-on challenges do **not** extend that deadline.

## Why the next work is external rather than another internal phase

Telegraph's [official Season II rules](https://hackathon.telegraphprotocol.com/rules) assign **20/100 points** to original technical education (5), ease of adoption (5), organic distribution (5), and community developer activation (5). Separate-date progress updates matter; independent developers actually reproducing, integrating, contributing, or disputing an evaluation result matter more than likes, stars, impressions, or author-controlled CI.

The Evaluators delivery-award selection prioritizes **distinct missions and real app workflows enabled**, then missing mission-critical Intent coverage, then technical quality. A [catalogue label of `SECURITY_REVIEW`](https://hackathon.telegraphprotocol.com/intents?intent=SECURITY_REVIEW) is not automatically interchangeable with historic `SECURITY_REVIEW_GENERAL` receipt/request IDs. FALSUM must not claim a delivered mission/app integration or rank improvement without an independently reproducible mission-specific result.

The project's existing technical archive is real, substantial and rerunnable; the missing evidence is genuinely external **human developer action and acceptance**, not more author-authored tests.

## Verified current build and truth boundaries

| Surface | Verified observation | Evidence |
| --- | --- | --- |
| Phase 5Y | Two publicly published Miner captures for lodash 4.17.15 contain 12 advisory references; independent reviewed-version checks suppress two instances of **one** inapplicable GHSA. Remaining references are only **version-applicable**, not proven exploitable, complete, or currently safe. | [Version applicability study](PHASE5Y_INDEPENDENT_GHSA_VERSION_APPLICABILITY.md) |
| Phase 5Z | One original generic 100-GHSA feed is off-target; two direct public six-reference outputs each contain five version-applicable references and one version-inapplicable reference. This is a **display-only** target-specific filter, not an approved Telegraph ranking. | [External Miner application consumption](PHASE5Z_REAL_APP_ADVISORY_CONSUMPTION.md) |
| Phase 5AA | Offline historical advisory-source bundle validates original GHSA Git blobs; local inputs never inherit external original-Miner provenance, completeness, or current advisory freshness. | [Offline reviewer bundle](PHASE5AA_OFFLINE_REVIEWED_SOURCE_BUNDLE.md) |
| Phase 5AB | Twelve historical outside Git-verified reported-paid capture files: **2** explicit canonical request+receipt, **2** direct request with canonical receipt, **6** HTTP 200 with different receipt Intent, **2** failed without successful receipt. **Zero** identical canonical routed-request pairs across reported independent Miners. No fair network ranking is established. | [Original receipt census](PHASE5AB_EXTERNAL_RECEIPT_COMPARABILITY.md) · [PR #85](https://github.com/Iniwura/falsum/pull/85) |
| Phase 5AC | Zero-key public GitHub workflow checks both original receipt and advisory sources and exports only safe metadata plus a clearly constructed local sample. The **author-controlled** PR run passed; no outside fork action is confirmed. | [Independent reviewer handoff](INDEPENDENT_REVIEWER_START_HERE.md) · [Original workflow run](https://github.com/Iniwura/falsum/actions/runs/44913577378) · [PR #86](https://github.com/Iniwura/falsum/pull/86) |
| Latest `main` | `2b87eaa7a9495617b41bec64b15be6e41e8fb358`; all **6/6** triggered post-merge workflows passed. Previous 5AB main passed **20/20**. | [GitHub Actions](https://github.com/Iniwura/falsum/actions) |
| Vercel production | Last VERIFIED READY production commit `25e87cd585825f12fe515b8555abe39e37eeac6f` (Phase 5AA). Later 5AB/5AC code is in GitHub, **not** yet production at the last read-only inspection. | [Vercel evidence lab](https://falsum-evidence-lab.vercel.app/) |
| Third-party adoption | **Zero confirmed independent FALSUM fork replays, accepted integrations, or expert AppSec reviews as of this update.** An earlier independent PR Guard builder shared raw public fixtures, which are external source data, not a FALSUM integration. | [Review issue #25](https://github.com/Iniwura/falsum/issues/25) · [Original source discussion #38](https://github.com/Iniwura/falsum/issues/38) |
| Official status | Star ownership, Season II registration/track selection and final submission have **not** been independently verified here. No new judge demo video or final entry was submitted. | [Official rules](https://hackathon.telegraphprotocol.com/rules) |

Historical source Git hashes authenticate original published bytes; they do **not** independently prove paid settlement, third-party Miner ownership, answer correctness, expert labels or actual user adoption. Original model-Qwen trial failures and limits must remain visible in final judge material.

## Public outreach: what actually happened

| Event | Real source/date | What it counts as | What it does **not** count as |
| --- | --- | --- | --- |
| PR Guard builder's earlier original fixture sharing | [FALSUM external-source discussion #38](https://github.com/Iniwura/falsum/issues/38) | Original third-party public response data and possible collaboration signal | FALSUM consumer integration, evaluator accuracy improvement, independent expert gold or accepted partner |
| Source-specific technical follow-up to PR Guard maintainer on 21 November | [Public issue comment](https://github.com/Iniwura/falsum/issues/38#issuecomment-7064115527) | **One genuinely posted, targeted technical request** questioning request/receipt semantics; explicitly asks for a counterexample | A reply, completed reviewer reproduction, accepted integration, new external scoring, or endorsement |
| Independent reproduction path opened | [Reviewer guide](INDEPENDENT_REVIEWER_START_HERE.md) and [review form](https://github.com/Iniwura/falsum/issues/new?template=independent-public-reproduction.yml) | Published reusable tutorial and specific invitation for a new tester | Any outside developer actually running or benefiting from it |

**No external reviewer reply has been verified since the targeted 21 November outreach.** A later reply, correction, fork action, or integration must be recorded with its real original URL and independently inspected before it can change the evidence count.

## Three distinct publish-ready public updates

Each is **DRAFT ONLY**. Proposed separate dates are planning targets, **not publication timestamps**. Publish only with genuine access to the account, do not backdate, and disclose Telegraph Season II prize-entry participation. An external post needs its own real URL; the repository text and first-party CI do not count as publishing it to an outside platform.

### Update A — public security evaluation failure and receipt provenance

**Proposed date:** 21 November 2026. **Status: DRAFT, NOT VERIFIED PUBLISHED.**

> A paid response isn't automatically comparable evidence. FALSUM checked 12 original public Telegraph security captures: only 2 had matching canonical request and receipt Intents, and 0 form a same-request multi-Miner pair. [Original source audit](https://github.com/Iniwura/falsum/blob/main/docs/PHASE5AB_EXTERNAL_RECEIPT_COMPARABILITY.md). Telegraph S2 Evaluators prize entry.

**Developer value:** teaches how to avoid treating a folder label, HTTP 200 or claimed payment flag as proof of the same canonical task. Follow-up question: Can someone find an actual same-request pair or a misclassified original receipt?

**Publish URL:** NONE. **Independent replies / reproduction:** NONE CONFIRMED.

### Update B — review the exact affected version, not only a GHSA identifier

**Proposed date:** 23 November 2026. **Status: DRAFT, NOT VERIFIED PUBLISHED.**

> A genuine GHSA isn't necessarily applicable to the package version being reviewed. FALSUM checked 6 reviewed advisories in public lodash 4.17.15 captures: 5 apply and 1 must be suppressed. Reproduce it without paid APIs: [reviewer guide](https://github.com/Iniwura/falsum/blob/main/docs/INDEPENDENT_REVIEWER_START_HERE.md). Telegraph S2 prize entry.

**Developer value:** simple application-design consequence: suppress an out-of-range advisory before displaying it, but never claim the resulting package is universally safe. Ask reviewers to inspect Git-reviewed original version ranges and report a contradiction.

**Publish URL:** NONE. **Independent replies / reproduction:** NONE CONFIRMED.

### Update C — a challenge others can actually run

**Proposed date:** 25 November 2026. **Status: DRAFT, NOT VERIFIED PUBLISHED.**

> Try to break FALSUM's evidence. Fork the repo, run one zero-key GitHub Action checking 12 original Telegraph receipts and 6 reviewed advisories, then report a genuine discrepancy. Failed replays welcome: [independent reviewer form](https://github.com/Iniwura/falsum/issues/new?template=independent-public-reproduction.yml). Telegraph S2 Evaluators prize entry.

**Developer value:** direct, reproducible next action. A reported failure is useful even if no endorsement or independent AppSec gold follows.

**Publish URL:** NONE. **Independent replies / reproduction:** NONE CONFIRMED.

### Reproduction and education link

[**Start here — no keys or paid requests**](INDEPENDENT_REVIEWER_START_HERE.md) provides a GitHub fork workflow, local Python 3.11+ commands, expected original-source counts, negative controls, source-privacy boundaries, and a real public reviewer intake form. Public GHSA and original paid-capture source links are frozen to historical revisions. Screenshots, raw response bodies or summaries without underlying actual URLs do **not** establish independent activity.

## Evidence register: update only on proof

An externally publishable post or article should be recorded only after actual publication. An outside reproduction should be recorded only after validating the real reporter, the actual GitHub run or source cited, and whether the result is independent of the project owner. The following records currently remain **OPEN**:

| Required evidence | Verifiable acceptance record | Current status |
| --- | --- | --- |
| Three meaningful updates on separate dates | Three real URLs with actual publication timestamps, original technically distinct results, prize disclosure | **0 verified external posts** |
| Technical discussion | Relevant real public developer comments and responses, with URLs | **1 targeted contact sent; no confirmed new reply** |
| Independent developer testing | A different human developer's own fork run URL and concrete technical finding | **0 confirmed** |
| Independent AppSec source adjudication | Source-cited security review, qualified/independent reviewer disclosure, limitations and disagreements | **0 verified expert labels** |
| Independent integration/retention | Third-party app/workflow acceptance, repeat use, source code and public evidence | **0 confirmed** |
| Real Telegraph evaluator qualification | Official supported evaluator/material registration, acceptance or independently reproducible network scoring evidence | **Unverified; no ranking improvement claimed** |
| Star requirement | User account is recorded as having starred `telegraphprotocol/bounties` | **Unverified** |
| Official H2 registration | Actual accepted Season II Evaluators registration and Intent | **Unverified** |
| Production parity | READY production deployment with exact matching latest `main` Git SHA and working routes | **Outstanding** |
| Final demonstration | Real 2–5 minute judge-facing recording or organizer-accepted equivalent and access link | **Not made** |
| Official Season II entry | Accepted entry confirmation before 1 Dec 2026 23:59 UTC | **Not submitted** |

**Do not** classify first-party workflow runs, AI/bot comments, synthetic cases, existing public source archives, stars, follows, advertisements, or the PR Guard maintainer being tagged as real independent adoption. Do not offer incentives for engagement or ask people to purchase Telegraph intelligence purely to inflate usage counts.

## Next high-value actions

1. **Outside source correction:** Monitor [issue #38](https://github.com/Iniwura/falsum/issues/38) for a reply to the narrow original receipt-schema question; respond professionally only to actual evidence and correct the research if needed.
2. **Outside reproduction:** Share the [reviewer guide](INDEPENDENT_REVIEWER_START_HERE.md) with relevant developer/security communities via an account actually connected and authorized to post; invite one credible critical run or line-specific counterexample, not vanity likes. Follow applicable posting rules; no spam or impersonation.
3. **Current production:** Keep the existing one-time Vercel Hobby quota-reset release task; only deploy after the free allowance resets, no billing changes or repeated blind retries. Confirm exact READY SHA, not only a green CI badge.
4. **Eligible entry:** Confirm official registration, personal bounties GitHub star and all Evaluators track technical requirements. This cannot be inferred from old Anjoman rows or bounty comments.
5. **Submission-quality technical evidence:** Add genuine and independently reproducible mission-app relevance where it is actually possible; do not retroactively label one package-target demonstration as two fully enabled missions. Preserve the negative Qwen results.
6. **Final demo and submission:** Only after the above evidence is clear, produce the required real walkthrough and enter on the official H2 site **before** the deadline.

**Quality gate:** Winning claims require actual external proof, not internal numerical scores. No score over 90/100 is asserted by this plan.
