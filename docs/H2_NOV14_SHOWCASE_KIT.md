# FALSUM — November 14 integration milestone and community showcase kit

**Prepared 14 November 2026. Draft and audit notes, not evidence of a published Discord/social post or submitted hackathon entry.**

**Track:** Telegraph Season II / Evaluators · **Intent:** `SECURITY_REVIEW_GENERAL` · **Official close:** 1 December 2026 at 23:59 UTC · **Showcase:** 20 November.

## Verified current technical state

- [Phase 4I PR #35](https://github.com/Iniwura/falsum/pull/35) is merged to `main`; [four passing CI jobs](https://github.com/Iniwura/falsum/actions/runs/43537201172) covered the site, Python 3.11–3.13 and responsive Chromium. These are build checks, not outside expert adjudication.
- [Source Comparison](https://falsum-evidence-lab.vercel.app/compare/) shows four **precommitted** public parent/fix source pairs (PyJWT, Werkzeug, MCP Python SDK, Pillow). The unchanged original Foundation LoRA produced genuine scored outputs: **5/8 author-interpreted source fact matches**, **1/4 correct complete revision reversals**, compared with **4/8** for each constant-choice A/B control. Exact recorded float32 bits and source URLs are preserved. The **8/8 source-aware answer key** is correct by construction, not a trained model, an independent accuracy result or a valid model baseline.
- [Earlier model proof](https://falsum-evidence-lab.vercel.app/proof/) is a **different** six-condition task: **3/6** source matches and **0/3** complete reversals from the unchanged model; do not compare the two scores as a trained improvement.
- [Review challenge](https://falsum-evidence-lab.vercel.app/) shows fictional PR tasks verified with real local Python execution during static build; the browser makes **no live model/API/network requests**.
- A separate [signed Anjoman evaluation-material submission](https://github.com/telegraphprotocol/bounties/issues/96#issuecomment-6588168396) reported **20 AI-assisted rows Eligible in the contributor account**. Live row states and final maintainer acceptance have **not been independently verified**. The original issue claim was auto-released 5 November due to a missed /progress cadence. The public /submit comment remains; a hackathon entry has **not** been submitted.
- **0** independently adjudicated AppSec gold labels, **0** proven external mission integrations, **0** registered scoring adapters, **0** verified improvements in trained evaluator accuracy.

## Draft for Telegraph Discord #showcase (NOT POSTED)

**FALSUM | When the source changes, should the security verdict change?**

We're building FALSUM for **Telegraph Season II / Evaluators**, serving `SECURITY_REVIEW_GENERAL`. A security-review evaluator should notice when a real upstream fix changes the relevant security facts, rather than rewarding whichever answer sounds more confident.

We've shipped an interactive source comparison using four pinned public upstream fixes. We tested the **same unchanged Telegraph Foundation LoRA** on their before/after versions. The original model matched **5 of 8 researcher-interpreted source conditions**, but completed only **1 of 4** correct before-to-after reversals. Constant A and B each match 4/8. These are authentic **recorded** model scores with reproducible source and score evidence, **not** evidence of a better trained scorer.

**Try it:** https://falsum-evidence-lab.vercel.app/compare/

**Inspect the method and reproduce locally:** https://github.com/Iniwura/falsum/blob/main/docs/PHASE4I_JUDGE_COMPARISON.md

**Challenge or correct one public source case:** https://github.com/Iniwura/falsum/issues/25

We separately contributed 20 source-referenced, AI-assisted preference pairs to Anjoman and reported them Eligible in the contributor account; maintainer acceptance and network scorer registration are not claimed. We're looking for genuine independent source checks and constructive criticism. You can select a public case, inspect its fixed commit/regression test, and send an A/B/ABSTAIN verdict with exact citations.

This is an entry in the prize-bearing **Telegraph Season II hackathon**. No hidden evaluation prompts or customer material are published.

## Short public technical update draft (NOT POSTED)

We tested an unchanged Telegraph Foundation reward model on real upstream security fixes: PyJWT, Werkzeug, MCP Python SDK and Pillow. In 8 before/after source conditions, the model matched 5 researcher source expectations but correctly reversed its answer for only 1 of 4 fixes. Always-A and always-B each achieve 4/8. FALSUM publishes the actual score bits and pinned code/test/advisory evidence, including negative results. This is **not** independently adjudicated model accuracy or a newly improved adapter.

Try the interactive comparison: https://falsum-evidence-lab.vercel.app/compare/
Reproduce or challenge it: https://github.com/Iniwura/falsum/blob/main/docs/PHASE4I_JUDGE_COMPARISON.md

Building this for Telegraph Season II Evaluators (a prize-bearing hackathon); independent reviewers are welcome: https://github.com/Iniwura/falsum/issues/25

## The 20 November community showcase: proposed 3-minute narrative

1. **Problem (0:00–0:25):** Security conclusions must be evidence-sensitive. Show one public upstream security fix; explain why version or code context matters.
2. **What FALSUM has built (0:25–1:20):** Open /compare/, select PyJWT, switch before/after; then MCP Python SDK to show a missed reversal. Explain the actual 5/8 and 1/4 model results versus constant controls and author-key 8/8 caveat.
3. **Real verification (1:20–2:10):** Open immutable source/test/advisory links and [real model CI](https://github.com/Iniwura/falsum/actions/runs/43530363990); briefly demonstrate original /proof/ or the authored fictional PR challenge. Identify each evidence type and that the public site is static.
4. **Telegraph contribution and boundaries (2:10–2:35):** Show the original [public bounty /submit](https://github.com/telegraphprotocol/bounties/issues/96#issuecomment-6588168396), distinguishing 20 contributor-reported Eligible rows from independently verified acceptance, and research LoRA from a registered module. Never show hidden row content or account secrets.
5. **Developer invitation (2:35–3:00):** Walk through the [judge reproduction steps](https://github.com/Iniwura/falsum/blob/main/docs/H2_EVALUATORS_JUDGE_PACK.md); invite a specific source-cited A/B/ABSTAIN review at [issue #25](https://github.com/Iniwura/falsum/issues/25).

No reenacted wallet signing, fabricated live inference or fake production adoption. Record real browser actions in 1080p+ with legible titles, clean transitions, sound and captions. A finished 2–5 minute video is still needed for the official final submission.

## What the official rules change

The [official H2 rules](https://anjoman.ai/dashboard/hackathon/season-2/rules) reserve **20/100 points** for education, easy developer adoption, organic distribution and **real** outside developer activation. An original update is not automatically an independent review. Judges require actual URL and action evidence. The **14 November milestone is a progress check for Apps & Agents, not an Evaluators disqualification gate**. Evaluator delivery awards favor verified new mission-critical evaluation coverage and impact.

Keep FALSUM in the **Evaluators track**. Do not claim an Apps mission was completed simply because SECURITY_REVIEW can potentially help Exchange, Model Economy and Web3/DeFi.

## Evidence register (fill only after actions actually occur)

| Evidence | Status at document creation | Publication / verification reference |
| --- | --- | --- |
| Phase 4I merged and CI passing | Verified | [PR #35](https://github.com/Iniwura/falsum/pull/35), [CI](https://github.com/Iniwura/falsum/actions/runs/43537201172) |
| November 14 Discord #showcase | **Draft only** | None |
| First public technical update (dated) | **Not verified** | None |
| Second public technical update (different date) | **Not verified** | None |
| Third public technical update (different date) | **Not verified** | None |
| Independent external source review | **0 independently confirmed** | [Open reviewer request](https://github.com/Iniwura/falsum/issues/25), not a completed review |
| Contributor 20-row live state / maintainer acceptance | **Not independently checked** | [Original /submit](https://github.com/telegraphprotocol/bounties/issues/96#issuecomment-6588168396) |
| 20 November public demo URL | **Not recorded or published** | None |
| Final 2–5 minute demo URL | **Not uploaded/verified** | None |
| Official Season II final entry | **Not submitted** | None |

### Unblocked next steps

- Publish the reviewed Discord text **from the participant's own account**; save the genuine message URL.
- Publish two additional meaningful public updates on separate days, preferably with a runnable test or tutorial, and preserve actual URLs. Respond to real feedback without manufacturing engagement.
- Seek at least one genuinely independent, source-cited review; log its verdict, independence, correction and replication result before calling it a gold label.
- Independently check contribution row status with the documented read-only `/api/evalpool/submissions/mine` endpoint; do not publish row contents. Seek maintainer feedback on the existing bounty submission. A released claim does not imply acceptance.
- Confirm H2 registration, `telegraphprotocol/bounties` repository star, official 2–5 minute demo and final H2 form receipt before 1 December 23:59 UTC.

**No additional model or benchmark improvement is implied by creating this document.**
