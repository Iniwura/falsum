# FALSUM — strict technical and Evaluators-track audit

**Review checkpoint: November 17, 2026**  
**Scope: public source and build evidence only. No demo production, video, signer access, private evaluation material, network registration or official final submission.**  
**Internal completion goal: November 22, contingent on quality. Official H2 deadline: December 1, 23:59 UTC.**

## Decision

**NOT READY FOR OFFICIAL SUBMISSION.** FALSUM has a real, reproducible security-evaluation research base and publicly recorded negative Foundation model results. Its current **qualification evidence and independent technical value are not yet sufficient to justify a first-place claim**. Passing GitHub CI certifies the tested interfaces, source integrity and no-overclaim policies; it does not certify independent AppSec label truth, current contributor acceptance or trained evaluation improvement.

The official [Season II rules](https://anjoman.ai/dashboard/hackathon/season-2/rules) explicitly allow **evaluation material OR a scoring adapter OR both** in the Evaluators track. A released model/registered adapter is **not obligatory** to pursue the evaluation-material path. The valid path must still be meaningfully useful, verifiable and compliant with the live Intent/family and evaluation-pool semantics.

## Evidence actually audited

| Surface | Grounded check | Limits |
| --- | --- | --- |
| Public source and current `main` | GitHub branch and CI; `phase4a`, `phase4b`, `phase4f`, `phase4h`, `phase4i`, `phase4k`, `phase4l`, final entry, judge pack and README | Focused audit of critical evidence paths, **not** a professional line-by-line review of every historical source module |
| Model scoring | Frozen four-project lock and authentic ledger's **16 float32 score bits** revalidated by Phase 4I; adversarial tampering tests in Phase 4M | The same original failed LoRA, not a new model or current live scoring |
| Four before/after projects | PyJWT, Werkzeug, MCP Python SDK and Pillow, frozen before scoring; real pinned upstream source/revision checks | Researcher-interpreted expected answers, **not independent gold**; **two of four selected test files did not change in the selected fix** |
| Model outcome | **5/8** match author-interpreted source expectations; **1/4** complete correct change-of-verdict pairs; constant A **4/8**, constant B **4/8** | This small nonrandom, known-source set does not establish statistical superiority or generalization |
| Old version evaluation | Different 3-project package-version test: **3/6** matches and **0/3** complete reversals | Do not compare with 5/8 as an improvement; unchanged model and different tasks |
| Deterministic reference checker | 36/36 source-constructed checks: **6 SUPPORTED, 6 CONTRADICTED, 24 ABSTAIN** | By construction on known source labels, **not trained semantic model accuracy** or proof of independent AppSec review |
| Review intake | Public seven-source review invitation and GitHub-source-claim audit | **No accepted independently verified security expert gold labels** at this checkpoint |
| External PR Guard | Phase 4L byte-pins three public paid response captures and verifies identical supplied input; excludes third-party-owned Sentinel #731001 | #5530 direct family and #302 different Intent; receipt identities not independently authenticated; not a same-Intent scored model comparison, not customer adoption |
| UI and deployment | Actual static Python-generated root, /proof/, /compare/; existing desktop/mobile Chromium regression jobs; Vercel project production status **READY** on Phase 4L main commit `a7cd285` | Deployment READY is not an independent live end-user trial. Website has no live scorer or customer purchase. No manual browser QA beyond available automated evidence in this checkpoint |
| Reproduction and release assertions | New [Phase 4M CI](../.github/workflows/phase4m-release-audit.yml) reruns original scored model evidence, tests 21 adversarial integrity scenarios, scans final-packet relative file links, checks solo ownership and refuses fabricated submission/eligibility status | A green audit job deliberately outputs `released_ready: false` while real qualification gates remain unverified |

## Real Anjoman evidence: must reconcile

- **November 2:** Anjoman signed-in contributor account UI reported 20 AI-assisted, source-referenced preference pairs marked **Eligible**. This remains a historical account observation, with a linked [public original /submit](https://github.com/telegraphprotocol/bounties/issues/96#issuecomment-6588168396).
- **November 14:** [Phase 4K GET](https://github.com/Iniwura/falsum/actions/runs/43619793133) returned **0 rows for the published GitHub contributor address**, including normalized lowercase query; Intent-wide pool reported 199 Eligible across 9 eligible contributors. The identity match with the contributor's signed-in account was **not** established.
- **November 17:** [Phase 4M repeated GET](https://github.com/Iniwura/falsum/actions/runs/44181080455) returned **HTTPError / UNKNOWN** for the public-comment address; the **separate Intent-wide pool** answered **332 Eligible rows from 10 eligible contributors**. The Intent-wide counts **cannot be credited to FALSUM**. Today's readback failure must not be misreported as zero or rejected rows.
- **Later November 17:** A separate [successful repeated GET](https://github.com/Iniwura/falsum/actions/runs/44181734533) responded **0 rows for the publicly submitted address** with lowercase fallback, while the **Intent-wide pool remained 332 Eligible from 10 eligible contributors**. The prior HTTP error and subsequent valid zero are both part of the recorded evidence. Neither validates the identity match to the signed-in Anjoman account; no deletion/rejection of that other account's rows is established.
- **Bounty #96** closed November 15 because work migrated to the mission Issues; the maintainer explicitly retained earlier claim/submission comments. This closure is **neither verified acceptance nor documented rejection**. [Mission 10 Model Economy #198](https://github.com/telegraphprotocol/bounties/issues/198) remains open for relevant security-evaluator work.

The sole operator must compare the **complete public contributor address** shown by their signed-in Anjoman account to the address in the old GitHub `/submit`. No private keys, seed phrases, signatures, hidden questions or answers are necessary. If the addresses match, request a maintainer explanation of the inconsistent API response while keeping the full row content private.

## Remaining risks by severity

**P0 — qualification and evidence integrity**
- Signed-in contributor ownership, current row eligibility and maintainer acceptance are **unverified**. Without verified evaluation material or an actual registered working adapter, formal Evaluators qualification is uncertain.
- Official H2 registration/track/account star and the successful final form submission receipt have **not** been verified. These are separate from a GitHub `/submit`.
- A genuine final 2–5 minute demo (or accepted accessible equivalent) has **not been published or verified**. **No demo work is part of this audit**, by operator decision.

**P1 — independent technical quality**
- No independently adjudicated source-backed AppSec gold labels; a GitHub self-attested review claim alone would not suffice.
- No new sealed project-disjoint holdout, and no measured improved trained scorer. FALSUM should compete on **new independently useful evaluation coverage** unless valid evaluator improvement is genuinely demonstrated.
- The current four-project set is tiny and purposively selected. The 5/8 versus 4/8 difference is not a defensible superiority claim; only one of four expected source-sensitive reversals was obtained.
- Phase 4L paid fixtures support an external application problem, not controlled same-Intent ranking performance. Some captured receipt miner/Intent fields differ from the response metadata. Preserve unresolved semantics rather than guessing.

**P2 — final-entry and maintainer clarity**
- Previously contradictory 20 Eligible statements, obsolete November 17 completion date and collective “we/our” phrasing in solo materials have been corrected in this audit branch, with fail-closed tests for regressions.
- Need one concise reviewer request and a real independent review verdict if a qualified reviewer is available. Do not invent or silently treat no response as approval.
- Public growth/update URLs and verified third-party activation have not been independently established. The PR Guard contributor's technical response is genuine reported engagement, not proof of using the FALSUM evaluator.

## Relative position and quality judgment

A competing [SECURITY_REVIEW_GENERAL bounty discussion](https://github.com/telegraphprotocol/bounties/issues/96) reports other contestants with more reported Eligible evaluation rows and one entrant with an exported adapter and self-authored validation numbers. **Those are competitors' public claims, not independently confirmed superiority or acceptance**, but they demonstrate that basic source-citing materials and a polished website alone are unlikely to distinguish this submission.

**No numerical judge score is certified**. The strongest verified work today is source integrity, honest failure reporting, reproducibility and the evidence-grounded critique of irrelevant routed security responses. The greatest weakness is missing independent evidence of evaluation coverage solving a mission-critical AppSec measurement problem.

## Quality-based exit gates before any demo

1. **Resolve the contributor identity/API evidence mismatch or clearly document an unresolved protocol limitation without presenting unverified 20-row eligibility as current.**
2. **Seek independent reviewer assessment of selected source-backed cases** and log exact citations, disagreements and abstention. Training claims remain blocked until genuine new data and model evidence exist.
3. **Demonstrate a reviewer-reproducible meaningful evaluation gap**, with precommitted criteria, shortcut baselines, and an actual source-sensitive fail case, not a self-scored accuracy improvement.
4. **Re-run full regression, public source locks, browser checks, network status and the Phase 4M integrity guard on the eventual main commit.**
5. Only after the technical audit is clean: decide whether to proceed with an authentic demo, verify official H2 fields/star, and submit through the official hackathon flow.

**Stop condition:** Do not promote a failing LoRA, manufacture expert labels or row status, use an external participant's own miner as an independent control, invent accepted network receipts, or lower technical standards solely to meet the November 22 internal target.
