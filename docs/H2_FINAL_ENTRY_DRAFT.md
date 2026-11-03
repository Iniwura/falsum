# FALSUM — Season II Evaluators entry, ready-to-copy working draft

**Status:** NOT YET SUBMITTED. This file is a public-safe **form preparation document**, not an official registration, submission, award, model registration or bounty approval. Replace any `<PLACEHOLDER>` only with genuinely verified information.

**Official deadline:** 1 December 2026, **23:59 UTC**. Submit via https://hackathon.telegraphprotocol.com/ . The contributor's GitHub bounty `/submit` and Anjoman `Eligible` rows are **not** a substitute for the separate hackathon website submission.

## Project identity

- **Name:** FALSUM
- **Track:** Evaluators
- **Intent:** `SECURITY_REVIEW_GENERAL`
- **One-line thesis:** Evaluate security evidence, not model confidence.
- **Project repository:** https://github.com/Iniwura/falsum
- **Live, public-safe runnable evidence site:** https://falsum-evidence-lab.vercel.app
- **Machine-readable captured runtime proof:** https://falsum-evidence-lab.vercel.app/ACTUAL-SYNTHETIC-RUNTIME-PROOF.json
- **Main network contribution:** 20 source-referenced AI-assisted preference pairs appearing `Eligible` in the submitting contributor's Anjoman account, with genuine signed upload and pool rollover.
- **Bounty claim:** https://github.com/telegraphprotocol/bounties/issues/96#issuecomment-6588168396 (posted, maintainer approval pending at last verification)
- **Contact/team/account:** <OFFICIAL_H2_REGISTRATION_DETAILS_FROM_USER>
- **Public share permission:** <USER_CHOICE_FOR_TEXT_IMAGES_VIDEO_AND_BUYER_INTRODUCTIONS>
- **Video URL (real 2–5 minute demonstration):** <ACTUAL_VIDEO_URL_AFTER_RECORDING>

## Main description: suitable for the official H2 form

FALSUM contributes evidence-grounded evaluation material to Telegraph's `SECURITY_REVIEW_GENERAL` Intent. A security response should distinguish a confirmed source-level weakness from a proven reachable application impact, and it should change its conclusion when the relevant runtime facts change. FALSUM uses real historical open-source fix evidence and reproducible regression observations as the basis for that measurement problem.

During Season II we signed and uploaded 20 source-referenced, explicitly AI-assisted preference pairs to Anjoman. The contributor's account shows **20 eligible** rows after the epoch rollover. The public `/submit` GitHub claim is filed, pending independent bounty maintainer review. The exact hidden evaluation questions, answers, row hashes and any private account details are not published.

FALSUM also includes reproducible public evidence: isolated historical Starlette and Requests before/after runtime observations, plus a deployed Evidence Lab showing actual Python execution across three **fictional** security-review PRs: exchange actor binding, agent webhook authenticity and DeFi relayer replay prevention. In these local synthetic fixtures, all three pre-patch undesirable operations occur, all three are stopped by the patch and all three legitimate positive controls remain. The Vercel site is a static visualizer of captured execution results, not an active AI scorer or a production integration.

We also trained and measured experimental ModernBERT LoRA evaluator checkpoints. Real contextual-reversal tests exposed poor model behavior, and retraining did not improve transfer on the inspected projects. Both checkpoints remain quarantined rather than misrepresented as production-ready or registered on Telegraph.

What is demonstrated: network-eligible evaluation material and independently reproducible public-safe behavior tests. What is **not** claimed: an active scoring adapter, independently certified expert labels, partner mission app integrations, paid customers, a confirmed bounty approval, or winning the competition. FALSUM is designed for developers who want to measure security-review intelligence with concrete, falsifiable evidence.

## Technical proof and run instructions

1. **Open the hosted Evidence Lab** at https://falsum-evidence-lab.vercel.app and select all three fictional PR workflows. Inspect the before/after results and source SHA256 fingerprints.
2. **Rerun the exact Python fixture**: `git clone https://github.com/Iniwura/falsum.git && cd falsum` then `PYTHONPATH=src python3 -m falsum.phase3q_mission_lab --out-dir local-demo`. Open `local-demo/index.html` and compare its JSON with the hosted output. Requires Python 3.11+, no credentials, wallet, secret or network at test execution.
3. **Test failure cases**: `PYTHONPATH=src:tests python3 -m unittest discover -s tests -p 'test_phase3q_mission_lab.py' -v`. It checks bad vs patched operations, valid controls, invalid HMAC/replay conditions and report integrity.
4. **Read network contribution proof** in https://github.com/Iniwura/falsum/blob/main/evidence/phase3o-2026-11-02-20-eligible.json and the actual public bounty comment above. Actual privately held per-row data may be verified through the organizers' authorized Anjoman reviewer access; it must not be exposed in the public form.
5. **Review historical source reproductions**: https://github.com/Iniwura/falsum/blob/main/docs/PHASE3H.md and https://github.com/Iniwura/falsum/blob/main/docs/PHASE3I.md .
6. **Read real negative model diagnostics**: https://github.com/Iniwura/falsum/blob/main/docs/PHASE3J.md and https://github.com/Iniwura/falsum/blob/main/docs/PHASE3K.md .

**Costs and network:** The public Evidence Lab is a statically hosted website with no runtime network purchases, wallet connect, API keys or paid processing; its cases are executed during the build. The private network contribution was made to Anjoman's Telegraph evaluation pool through its signed contributor account, not through the demo website. No future API or token spending is needed to reproduce the demo.

**Known limitations:** No external mission app has adopted FALSUM; the public three-case demo is synthetic; no registered score adapter or independently expert-certified security model exists; the current bounty review has not finished. There is no hidden benchmark disclosed in the demo.

## Public-facing short summary

**FALSUM — Evaluate the evidence, not the confidence.** We contributed 20 `SECURITY_REVIEW_GENERAL` preference pairs that Anjoman marks eligible and shipped a public, independently runnable security-review Evidence Lab. The live demo makes three simple but important review distinctions visible across fictional PRs: actor identity, callback integrity and replay protection. We also publish real negative model-scoring results instead of pretending an unready evaluator works.

Live demo: https://falsum-evidence-lab.vercel.app  
Code and tests: https://github.com/Iniwura/falsum  
Try it and report findings: https://github.com/Iniwura/falsum/issues/16

This is an Evaluators entry for the prize-bearing Telegraph Season II. We welcome independent reproduction and meaningful criticism. No hidden evaluation questions are published.

## H2 growth and outside developer evidence

- Public working demo: **VERIFIED** (HTTP 200 on HTML + JSON).
- Public technical walkthrough: **VERIFIED** (source and reproduction guide).
- Independent developer reproduction/integration: **NOT YET VERIFIED**. Open invitation: https://github.com/Iniwura/falsum/issues/16
- Three meaningful social updates on different dates: **UNPOSTED DRAFTS** at https://github.com/Iniwura/falsum/blob/main/docs/H2_ADOPTION_AND_SUBMISSION_PLAN.md
- Real screen-recorded 2–5-minute demo: **NOT RECORDED/VERIFIED**. Use https://github.com/Iniwura/falsum/blob/main/docs/H2_EVALUATORS_DEMO_STORYBOARD.md

Do not mark an item verified without a genuine external receipt or published link.

## Final submission gate

**DO NOT claim H2 final entry filed until:**
- The user's official H2 registration and track are confirmed.
- A genuine video/accessibility-equivalent link is available.
- The intended public/share and contact permissions are chosen.
- The official H2 form is submitted by the owner and returns a success/confirmation page.
- Its actual entry URL, timestamp and submitted evidence are retained.

The separate deadline is **1 December 2026, 23:59 UTC**. Winning needs at least 70/100 and the Evaluators-track technical minimum plus independent judging; eligible network rows do not guarantee any award.
