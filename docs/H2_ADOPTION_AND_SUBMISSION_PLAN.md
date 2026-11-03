# FALSUM — Season II winning-track adoption and submission plan

**As of 3 November 2026.** This is an action plan, **not evidence that outreach, third-party testing, adoption, an accepted bounty or final submission has occurred**. FALSUM is competing in the **Evaluators** track, focusing on `SECURITY_REVIEW_GENERAL` evaluation material.

## Proven today

- **Network material:** 20 source-referenced, openly AI-assisted preference pairs appear `Eligible` in the contributing Anjoman account. The signed public [bounty /submit comment](https://github.com/telegraphprotocol/bounties/issues/96#issuecomment-6588168396) exists; maintainer verification is not yet confirmed.
- **Public demo:** [FALSUM Evidence Lab](https://falsum-evidence-lab.vercel.app) and [captured JSON proof](https://falsum-evidence-lab.vercel.app/ACTUAL-SYNTHETIC-RUNTIME-PROOF.json), both externally served with HTTP 200 on Vercel. These are **actual Python executions against three fictional local apps**, not production mission integrations or an approved scoring adapter.
- **Independent testers:** [Reproduction request issue #16](https://github.com/Iniwura/falsum/issues/16) is publicly open. There is **no independently verified external reproduction or adoption yet**.
- **Models:** both experimental ModernBERT LoRAs fail full context-reversal checks and must remain unregistered.

## What matters for the prize

Read the [official Season II rules](https://hackathon.telegraphprotocol.com/rules). The Evaluators track has four **$300 verified-delivery awards** ($1,200 total), plus **$500 first place and $300 second place** for excellence ($800 total), per the current official prize table. The **minimum winning score is 70/100**, and the Evaluators-specific technical minimum must also be met. The rules allocate **20 points** to useful education, adoption friction, organic distribution and genuine independent developer actions:

| Part | Max points | FALSUM-specific honest route |
| --- | ---: | --- |
| Useful content and tutorial | 5 | Real demo and source-grounded tutorial, with failure cases and limitations |
| Ease of adoption | 5 | Public site, one-command offline re-run, clear troubleshooting and prerequisites |
| Organic distribution | 5 | At least three meaningful posts on separate dates, shared beyond own immediate team, genuinely answer questions |
| Community activation | 5 | Reproducible independent developer report, useful PR or new separate integration; stars alone are not evidence |

**Do not confuse three fictional mission-inspired tests with three independently enabled external missions.** Real source-pinned coverage and a public working test help technical credibility, but the judges decide whether they fill a missing mission-critical evaluation need.

## Three original public updates to publish on DIFFERENT dates

These are **unpublished drafts**, not evidence of dissemination. The author must actually post them and retain the real URLs. Disclose hackathon participation and prize incentive.

### Update A — 3 Nov 2026: first actual milestone

FALSUM has 20 `SECURITY_REVIEW_GENERAL` evaluation rows marked eligible in Anjoman. Our bounty claim is filed, pending maintainer review.

We also shipped a public Evidence Lab: three executable fictional security-review PR examples showing how a conclusion changes when an authentication or replay condition changes. The examples are safe and synthetic, not external customer audits or a trained model scoring system.

Try it: https://falsum-evidence-lab.vercel.app  
Reproduce or challenge the code: https://github.com/Iniwura/falsum/issues/16

Building in Telegraph Season II Evaluators track, which offers prizes. Feedback and failures are welcome. @Telegraphprotoc

### Update B — suggested 7 Nov 2026: technical breakdown

A source-level security warning and a demonstrated production exploit are not the same. In FALSUM we reproduced historical security behavior for real pinned Starlette and Requests library versions, then built a separate public synthetic PR lab for actor binding, webhook HMAC checking and relayer replay protection.

The test checks that an unsafe action stops **without** breaking the legitimate one. Our original and retrained reward models still fail context-reversal quality tests, so we have not registered either as an evaluator.

Source/methodology: https://github.com/Iniwura/falsum/blob/main/docs/PHASE3Q.md  
Live demo: https://falsum-evidence-lab.vercel.app

This is a Telegraph Season II Evaluators submission project with prize eligibility; negative results are part of the proof. @Telegraphprotoc

### Update C — suggested 20 Nov 2026: community showcase

I am looking for independent developers to reproduce FALSUM's safe security-review evidence experiment for Telegraph Season II's Evaluators track.

You need Python 3.11+ and no account or wallet. Run the three synthetic PR cases, inspect captured before/after states and source fingerprints, then report what you observed. Incorrect, confusing or unreproducible results are useful feedback.

Try the demo: https://falsum-evidence-lab.vercel.app  
Exact reproduction steps: https://github.com/Iniwura/falsum/issues/16

Participation is voluntary. This is a hackathon entry competing for prizes, and we will only count genuine independent work. @Telegraphprotoc

## What should be captured without manipulating outcomes

Maintain links to *actual* public updates, real comments, external reproduction reports and the specific resulting fix PRs or tests. Require independent reviewer identity evidence where reasonable and respect developer privacy. Do not invent users, adoption, ratings, third-party mission workflows, payouts, or reviewer endorsements.

Do not publish hidden Anjoman evaluation questions, exact chosen/rejected answers, source credentials or customer cases. Safe synthetic demonstrations and broad coverage descriptions are permitted.

## Owner-controlled next actions

1. **Confirm registration** on the official [Season II site](https://hackathon.telegraphprotocol.com/). Signing in to Anjoman and filing GitHub bounty `/submit` do **not** prove the separate hackathon registration or final entry was completed.
2. **Publish the first accurate technical update** using a genuinely owned public account, ideally X with `@Telegraphprotoc`, and preserve its actual link. The user controls external publishing and any required prize disclosure.
3. **Record an actual 2–5 minute screen demo** showing the real Vercel site and Anjoman account status with private user fields cropped, plus a reproducible failure case. Do not present the storyboard as an existing recording.
4. **Get independent tests** through GitHub issue #16 and relevant developers; preserve their actual findings, including failures.
5. **Submit the complete Evaluators entry** through the official H2 website by **1 December 2026, 23:59 UTC**. Include demo link, video, GitHub, chosen Intent, real eligibility evidence, reproduction steps, exact limitations, community update URLs, and showcase permissions. GitHub bounty `/submit` is separate.

**The next evidence hinge:** a genuine third-party reproduction or a maintainer review of bounty #96. A positive result would be new, verifiable progress. Until it happens, record both statuses as pending.
