# FALSUM — final week adoption and technical communication

**12 November 2026 · All social posts below are drafts, NOT verified as published.**  
Track: Telegraph Season II / Evaluators · Intent: SECURITY_REVIEW_GENERAL · Internal quality target: November 17 · Official closing date: December 1, 23:59 UTC.

We earn credibility by publishing useful, reproducible work and inviting real developers to challenge it, not by padding engagement metrics or submitting unverified model claims.

## Current measured evidence

- The contributor reported 20 SECURITY_REVIEW_GENERAL AI-assisted preference pairs as Eligible in Anjoman and filed [a public bounty submission](https://github.com/telegraphprotocol/bounties/issues/96#issuecomment-6588168396); maintainer acceptance has **not** been confirmed. The bounty being claimed by others does not grant them control over our work.
- [Live review challenge](https://falsum-evidence-lab.vercel.app/) executes fictional Python before/after scenarios during its static build. They are not actual network mission deployments.
- [Actual recorded Foundation scoring](https://falsum-evidence-lab.vercel.app/proof/) covers three published affected/patched package pairs and shows original LoRA **3/6** source-fact matches, **0/3** complete context reversals.
- [Offline public-source reference checks](PHASE4B.md): 36 source-derived test inputs (6 supported, 6 contradicted, 24 abstained). Agreement is expected by construction, **not proof of improved ML accuracy**.
- [Independent review request](https://github.com/Iniwura/falsum/issues/25) is open. As of November 12: **0 confirmed independent AppSec reviews or completed partner integrations**. We must not backfill fictional review activity.

## The official judging incentive

The [official rules](https://hackathon.telegraphprotocol.com/rules) score organic growth, education and developer activation on useful public content, adoption friction, original distribution and *actual actions by independent developers*. Publish thoughtful content across multiple dates and preserve real URLs. A social post, like or GitHub star alone is not a measured independent activation.

We are preparing **three useful distinct posts on November 13, 14 and 16**, all before the November 17 internal target. They may be published on X, the relevant Telegraph Discord channels or appropriate developer communities, complying with each platform's rules. The dates are targets only; only timestamps from real published posts count. Disclose that FALSUM is a prize-entry project.

### Public update A — proposed November 13 (the problem and real failure)

FALSUM is a Telegraph Season II Evaluators entry for SECURITY_REVIEW_GENERAL.

We checked the same original reward model against affected and fixed versions of three packages using the official Foundation ONNX/WASI scorer. It got only 3/6 narrow source facts right and **0/3 correct affected-to-fixed reversals**. It picked A every time.

Our point: security evaluations must change when the evidence changes. We published the actual float32 score proofs and pinned GHSA source records, and we blocked the model from registration.

Try the real recorded score explorer: https://falsum-evidence-lab.vercel.app/proof/
Source and method: https://github.com/Iniwura/falsum/blob/main/docs/PHASE4A.md

We're competing for Telegraph Season II prizes, and welcome independent criticism of the result.

### Public update B — proposed November 14 (what can be verified and reproduced)

Security review quality is not about confident phrasing. A patched package version does not automatically prove global application safety, and an affected version does not automatically prove an exploitable deployment.

We built an offline source-checking reference for three pinned GitHub-reviewed advisories. It verifies exact published PyPI versions, rejects contradicted fact claims and **abstains** when evidence is missing or a claim goes beyond its scope.

36 constructed source-check cases: 6 supported, 6 contradicted, 24 abstained. This is deterministic reference-checker coverage, not an ML accuracy benchmark.

Five runnable examples + setup: https://github.com/Iniwura/falsum/blob/main/docs/PHASE4B.md

FALSUM is participating in Telegraph Season II Evaluators. Try breaking a provenance or version claim and tell us where our scope is wrong.

### Public update C — proposed November 16 (invite actual external reproduction)

I'm looking for independent developers to challenge FALSUM's security-review evaluation evidence before Telegraph Season II judging.

Pick one public GHSA case: docling-core, hydra-core or python-multipart. Check the affected release, the fixed version and the two constant A/B answers. If a source record, assumption or wording is wrong, report it with its exact URL. ABSTAIN is welcome when the evidence doesn't justify a security conclusion.

One-click review request: https://github.com/Iniwura/falsum/issues/25
Working interactive challenge: https://falsum-evidence-lab.vercel.app/
Recorded real model scores: https://falsum-evidence-lab.vercel.app/proof/

This is a hackathon prize entry. We won't count an open issue as a completed review; genuine feedback, including negative results, will improve the evaluation material.

## Actual publication evidence register (do not guess URLs)

| Item | Status on 12 Nov | Exact public URL once posted | Genuine responses / actions |
| --- | --- | --- | --- |
| Update A | Draft, unposted | **NONE** | **NONE VERIFIED** |
| Update B | Draft, unposted | **NONE** | **NONE VERIFIED** |
| Update C | Draft, unposted | **NONE** | **NONE VERIFIED** |
| AppSec review or independent reproduction | Requested, not received | [Open issue](https://github.com/Iniwura/falsum/issues/25) | **0 CONFIRMED** |
| Maintainer acceptance of bounty #96 | Pending | [Original /submit](https://github.com/telegraphprotocol/bounties/issues/96#issuecomment-6588168396) | **NONE CONFIRMED** |
| Final H2 submission and video | Not filed, no playable link | **NONE** | **NONE** |

Update this register only with actual observed public source records, post URLs, review reports or official organizer receipts. No fake testimonials, bought likes, backdated posts or self-reviews pretending to be independent.

## Owner actions remaining

1. Confirm the submitting GitHub account has starred telegraphprotocol/bounties, as required by the [official rules](https://hackathon.telegraphprotocol.com/rules).
2. Confirm the Season II official registration and track/Intent selection; a bounty claim is not H2 registration.
3. Publish the three technical updates on genuinely separate dates with authentic links, disclose prize incentive and respond usefully to technical questions.
4. Invite independent review of [GHSA version facts](https://github.com/Iniwura/falsum/issues/25), explicitly allowing negative or abstaining results. Do not fabricate review receipts.
5. Capture the actual 2–5 minute, real-screen video described in [the final storyboard](H2_EVALUATORS_DEMO_STORYBOARD.md). Protect hidden Anjoman prompts and private account data.
6. File the official H2 entry using [the form-ready submission draft](H2_FINAL_ENTRY_DRAFT.md) and preserve the real completion receipt by December 1, 23:59 UTC.

**Engineering can be marked ready on November 17 if all gates pass.** Independently reviewed material, organic distribution and actual official submission depend on real external actions and should never be marked completed automatically.
