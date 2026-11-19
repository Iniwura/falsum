# FALSUM — Season II submission evidence gate

**Checked against the published Telegraph Season II rules on November 19, 2026.**  
**Submission state: NOT SUBMITTED. No prize eligibility, award or maintainer acceptance is claimed.**

**Track:** Evaluators. **Recorded network Intent:** `SECURITY_REVIEW_GENERAL`.  
**Official H2 deadline:** December 1, 2026, 23:59 UTC. **Internal engineering target:** November 22, without weakening release standards.

Official sources: [Season II rules](https://hackathon.telegraphprotocol.com/rules) · [Evaluators track](https://hackathon.telegraphprotocol.com/tracks) · [Intent catalogue](https://hackathon.telegraphprotocol.com/intents) · [Model Economy mission](https://hackathon.telegraphprotocol.com/missions/model-economy).

## What is actually verified

| Evidence | Status | How to verify |
| --- | --- | --- |
| Four executed upstream security-fix regressions across Koa, Hono and LangChain Core | **VERIFIED — historical source tests** | [Phase 4T consolidated original GitHub Actions result](https://github.com/Iniwura/falsum/actions/runs/44356563508) and [permanent digest index](../evidence/phase4u-2026-11-18-permanent-four-executed-source-witness-index.json) |
| Runnable typed source/security claim checker | **VERIFIED — deterministic structured evidence checking** | [CLI and seven example claims](PHASE4U_SOURCE_REVIEW_CLAIM_GATE.md): 2 supported, 2 contradicted, 3 abstained, including a wrong receipt digest |
| Browser judge experience | **VERIFIED — build, GitHub Chromium CI and Vercel alias** | [Live real-source workbench](https://falsum-evidence-lab.vercel.app/witness/) and [technical reproduction](PHASE4V_REAL_SOURCE_WITNESS_WEB_LAB.md); independent public HTTP reachability from every viewer is not established |
| Corrected operator-reported Anjoman Privy Wallet source rows | **VERIFIED for that public address on November 18: 20 total, 20 Eligible** | [Live public-node readback](https://github.com/Iniwura/falsum/actions/runs/44311491808); the old bounty-comment address showed 0. Operator account association was screenshot-sourced, not cryptographic proof; maintainer acceptance remains unverified |
| Experimental original LoRA improvement | **NOT DEMONSTRATED** | [Actual frozen model score comparison](PHASE4I_JUDGE_COMPARISON.md): 5/8 researcher-source matches, 1/4 complete source reversals, 4/8 constant-choice baselines. Original trained model stays quarantined |
| Independent qualified AppSec gold labels | **ZERO confirmed** | [Independent review invitation](https://github.com/Iniwura/falsum/issues/25) is a request, **not a completed independent review** |
| Registered evaluator adapter or demonstrated live scoring improvement | **NOT CLAIMED** | The contribution route is evaluation material, not a newly deployed scoring service |
| Public-source workload linked to an H2 commercial mission | **PARTIAL — plausible use case, not adoption proof** | The official [Model Economy mission](https://hackathon.telegraphprotocol.com/missions/model-economy) explicitly lists the shared `SECURITY_REVIEW` Intent. FALSUM's network contribution uses the specific `SECURITY_REVIEW_GENERAL` label. That catalogue-to-API naming relationship, direct mission-app consumption, and app workflow acceptance are **not independently proved here** |

### Important distinction: how this entry can qualify

Season II allows an Evaluators entrant to supply **evaluation material, a scorer adapter, or both**. FALSUM is explicitly the first route. The official rules require a *real working contribution*, genuine Telegraph integration evidence, reproducibility on new inputs and failure cases, safe handling of private material, accurate claims, and **a star on `telegraphprotocol/bounties`**. The four source tests and the source-claim evaluator support reproducibility; the network readback supports public eligibility **for an address**. They do not prove organizer acceptance, independent gold accuracy, or an H2 entry receipt.

The H2 main competition has **$7,000** allocated, with Evaluators awarded **$2,000**: four delivery awards at $300 and excellence awards of $500 (1st) and $300 (2nd), as published in the rules. **No prize is guaranteed by registration, a green workflow, or network Eligible status.** For Evaluators, tie-breaks favor proven measurement improvement or valuable new coverage, then validity. The judges may require additional independent review. This audit **does not borrow Apps & Agents' 24/35 technical minimum or mandatory Telegraph purchase** as if it applied to Evaluators; the track-specific threshold must be confirmed in the live selected Evaluators rules.

## Owner-only submission requirements — intentionally unverified

| Requirement | Current evidence state | Why it needs the actual owner |
| --- | --- | --- |
| Season II registration | **LIKELY, NOT FORMALLY CONFIRMED** | The registration form replied “This email is already registered.” This is evidence of an existing email record, **not** an official track-linked entry receipt |
| Star the bounties repository | **UNKNOWN** | Public GitHub tools did not return an authenticated star/owner receipt. Must check [the actual repository's Star control](https://github.com/telegraphprotocol/bounties) while signed in |
| Three distinct meaningful public updates | **NO THREE VERIFIED PUBLIC URLs** | Existing drafts in [the research adoption plan](H2_ADOPTION_AND_SUBMISSION_PLAN.md) are not publication evidence. Separate authentic publication dates may earn distribution points; updates are an **opportunity to score**, not a substitute for technical validity |
| Independent qualified human/AppSec review | **ZERO CONFIRMED** | Cannot be fabricated by a model or by calling AI self-assessment human adjudication. Actual unaffiliated reviewer must inspect and sign their own evidence |
| H2 demo or accessible equivalent | **NOT COMPLETED OR AUTHORIZED** | The published rules ask for a **2–5 minute video or accessible equivalent** showing real input, output and Telegraph integration. The operator explicitly deferred demo/video work; don't create or upload one without a new instruction |
| Official H2 final entry | **NOT SUBMITTED** | Must be filed through the official website using the operator's registered account before the deadline; a GitHub bounty `/submit` comment is **not** an H2 submission |
| Showcase/asset and buyer-introduction permissions | **UNKNOWN** | The official entry requires opt-in choices for public reuse and introductions. These choices belong to the operator |

**Owner action is not currently requested:** continue technical preparation without bothering the owner. When authorizing final submission, the owner should confirm the star, registration, proof/safe share permissions and actual H2 form submission. Do not substitute screenshots for original sign-in access or fabricate confirmations.

## Judge reproduction (existing working artifact, not a video)

Start at [**Real source witness lab**](https://falsum-evidence-lab.vercel.app/witness/). Choose Koa's vulnerable parent and claim its new regression passed: the source-based result is **CONTRADICTED**. Switch to the fixed revision with the same claim: **SUPPORTED**. Corrupt the execution receipt SHA: **ABSTAIN**. Assert production exploitation without deployed evidence: **ABSTAIN**. Repeat with Hono and the two distinct LangChain security fixes.

Run locally from the public repository:

```bash
python -m pip install --no-deps -e .
falsum verify-source-review \
  --index evidence/phase4u-2026-11-18-permanent-four-executed-source-witness-index.json \
  --source-lock data/phase4p-three-project-open-review-lock.json \
  --requests examples/source-review-witness-claims.json \
  --out reviewer-evidence.json
```

Verify the original GitHub-hosted upstream source tests through [this procedure](PHASE4T_ONE_COMMAND_REAL_SOURCE_TEST_PROOF.md). The seven sample outcomes are deliberately source-derived; **they are not model prediction accuracy or independently certified security labels**. No paid Telegraph requests, private evaluation prompts or secrets are necessary to reproduce the public examples.

## Public technical updates — drafts, NOT published

The user retains editorial control over external accounts. These drafts are **not** credited as actual posts, impressions, engagement or organic developer adoption. Publish only on genuine separate dates, with appropriate hackathon/prize-entry disclosure and a meaningful developer invitation; if using X, tag [@Telegraphprotoc](https://x.com/Telegraphprotoc).

**A · The problem and real negative finding (unpublished draft)**

> FALSUM is my Telegraph Season II Evaluators entry for `SECURITY_REVIEW_GENERAL`.
>
> I tested the original research reward model on affected and fixed source revisions. It matched only 5 of 8 researcher-source expectations and got just 1 of 4 complete before/after reversals correct. A constant A/B choice matched 4 of 8.
>
> I kept the failing model out of release. Here is the actual recorded evidence, not a leaderboard claim: https://falsum-evidence-lab.vercel.app/compare/
>
> This is a hackathon prize entry. I welcome technical criticism, especially counterexamples to the original source interpretation.

**B · New reproducible source coverage (unpublished draft)**

> I built a stricter public security-evaluation test for FALSUM using four real upstream fixes across Koa, Hono and LangChain.
>
> I replayed each upstream author's new regression test against the vulnerable parent and fixed code: original functionality passed, the new security test failed on old code for its expected assertion, and it passed on the fix.
>
> The verified CI receipts and source/test hashes are public. Try it without keys: https://falsum-evidence-lab.vercel.app/witness/
>
> I'm competing in Telegraph Season II Evaluators. This is repeatable source-level coverage, not a claim that my trained model is suddenly better.

**C · Invite external reproduction (unpublished draft)**

> Can you break FALSUM's evidence checks?
>
> Choose a real Koa, Hono or LangChain fix and test a claim at its exact Git revision. Try a wrong receipt digest or claim a production exploit without deployed evidence. The verifier should abstain when the source doesn't justify an answer.
>
> Test it here: https://falsum-evidence-lab.vercel.app/witness/
>
> If you reproduce a mistake, send a precise source/test link or a GitHub issue: https://github.com/Iniwura/falsum/issues/25
>
> This is my Telegraph Season II hackathon entry. Independent negative findings count as useful feedback, not as an endorsement.

## Strict completion criteria

**Engineering evidence complete ≠ eligible main entry ≠ winning performance.** The source/test proofs are authentic and reproducible. The missing independent review, unverified owner-only requirements, real developer activation and final H2 entry are not silently passed, and no retroactive posts, attestations, wallets, customers or expert labels are invented.

Stop at the owner gates when it is time to submit. Do not publish a video or file the official entry without the owner's instruction.
