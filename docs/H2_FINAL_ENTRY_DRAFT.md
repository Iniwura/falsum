# FALSUM — Telegraph Season II final entry (form-ready draft)

**STATUS: NOT SUBMITTED.** Current concise form answers are below; the older dated evidence is preserved further down for provenance only.

## Current form answers — verified November 26, 2026

**Project:** FALSUM  
**Track:** Evaluators  
**Intent:** SECURITY_REVIEW_GENERAL  
**Deadline:** December 1, 2026, 23:59 UTC  
**Repository:** https://github.com/Iniwura/falsum  
**Live application evidence:** https://falsum-evidence-lab.vercel.app/applications/  
**Judge guide:** https://github.com/Iniwura/falsum/blob/main/docs/H2_NOV24_JUDGE_START.md

### Short project description

FALSUM builds reproducible evaluation material for AI security-review intelligence. It checks whether security conclusions follow authenticated source evidence, exact dependency versions and recorded request/receipt context. It includes historical application replays, original upstream security regression execution, explicit uncertainty controls and portable integrity checks for applications consuming Telegraph responses.

### What was built and measured

- **ACP provider integration (read-only verified on 26 November):** the installed official ACP CLI `1.0.40` and Node SDK `0.1.15` authenticated a direct `GET /agents/wallet/{walletAddress}` lookup for FALSUM and returned the live `verifySecurityReport` offering at `$0.01` with a 30-minute SLA. A prepare-only event handler now binds ordered ACP `job.created → requirement → budget.set → job.funded` evidence to the existing source-bound engine and reproducibly emits `ACCEPT`, `REJECT` or `HOLD`; it executes no budget, submit, settlement or purchase mutation. The ACP dashboard sandbox remains unverified and is not conflated with the CLI's separate testnet environment. [Read-only probe evidence](../evidence/phase5be-2026-11-26-acp-readonly-probe.json) · [Provider event contract](PHASE5BE_ACP_PROVIDER_EVENTS.md). **This is not a live ACP job, completed commercial execution or independent adoption.**
- **ACP live-execution preparation:** [Phase 5BF](PHASE5BF_ACP_LIVE_EXECUTION_PREP.md) records the current direct provider lookup with active EVM chains `4663`, `5042` and `8453`, authenticated SSE readiness, the distinct-agent sandbox route, the current Telegraph Base Sepolia quote and the two honest cost floors. No ACP job, Telegraph payment, signer change or wallet approval was executed.
- **Fresh Anchor approval packet:** [Phase 5BG](PHASE5BG_ACP_FRESH_ANCHOR_APPROVAL_PACKET.md) pins the Virtuals Sandbox/Sandbox Butler route, Base mainnet ACP recipients, Base Sepolia Telegraph quote, separate buyer setup, zero-native-gas ceiling and the unresolved cross-digest binding gate. A self-controlled buyer run would be labelled self-evaluation, not independent customer adoption; no transaction is authorized.
- **Real Telegraph contribution:** 20/20 material rows are Eligible for the entrant-reported Privy address in the [November 24 live read-only recheck](https://github.com/Iniwura/falsum/actions/runs/45490538616). This is material status, not organizer acceptance, cryptographic account ownership or an approved scoring adapter.
- **Application failure coverage:** [129 historical contract cases](https://github.com/Iniwura/falsum/actions/runs/45356819921), 158 recorded decision events and 202 purchase records. Eight count-only vulnerable-label PASS predictions are avoided by FALSUM, which ties verdict-only on this population. Labels are externally published, not independently adjudicated expert gold.
- **Developer-confirmed response integrity:** [Original nine-fixture replay](https://github.com/Iniwura/falsum/actions/runs/45476259143) finds three documented missing-code cases: verdict-only admits 3/3 unsupported clean candidates, Secure plus zero count admits 2/3, FALSUM admits 0/3. Two fixtures were confirmed by the original maintainer. These are bounded retrospective outcomes, not nine unique paid requests.
- **Solana / Anchor coverage:** [Source-verified advisory replay](https://github.com/Iniwura/falsum/actions/runs/45489641572) matches 12/12 constructed dependency queries versus 3/12 for citation-only. A correct range-aware baseline is equivalent. [Actual original Rust regression](https://github.com/Iniwura/falsum/actions/runs/45490186795): affected revision 3/4 tests passed with the expected security assertion failure; fixed revision 4/4 passed. No live Solana deployment or provider-ranking improvement is claimed.
- **Caller context:** [17/17 constructed controls](https://github.com/Iniwura/falsum/actions/runs/45477939270) matched the precommitted policy expectations, with 9/9 to 0/9 unsupported clean candidates and 4/4 clean controls preserved. The new gate uses extra caller information, so this is coverage, not a learned accuracy gain.

### Reproduction and developer evidence

The [five-minute judge route](H2_NOV24_JUDGE_START.md) links live evidence, the no-key reviewer workflow and original test results. [Public maintainer feedback and four dated progress-update days](H2_VERIFIED_GROWTH_EVIDENCE.md) document real Gig Guard and Truvian Shield feedback. [Solana reproduction invitation](https://github.com/Iniwura/falsum/issues/113) is open; no response or independent integration confirmed.

### Current verified production release

[PR #112](https://github.com/Iniwura/falsum/pull/112) passed 16 PR workflows and Vercel preview. Production deployment [dpl_DCUspCvDULXLiJXeb3kEZm8cGBbW](https://vercel.com/iniwura-akurus-projects/falsum-evidence-lab/DCUspCvDULXLiJXeb3kEZm8cGBbW) was READY on exact main commit `dd89602940cd2a900af33c85edd19e549999feda`. [Chromium verification](https://github.com/Iniwura/falsum/actions/runs/45490538700) passed 1440/768/390/320px with no page errors. This is a dated release checkpoint, not a permanent current SHA or an independent live HTTP attestation.

### Remaining form fields and permissions (do not invent)

- Entrant contact and account details: complete through signed-in official portal.
- Required bounties repository star: previously entrant-reported, not authenticated in this audit.
- Demo link or approved accessible equivalent: not supplied or published.
- Showcase permissions: entrant must decide.
- Official submission receipt: absent. Do not mark submitted until actual portal confirmation.

**Limitations:** No independently verified generalization, qualified expert gold, accepted outside integration, registered improved model, or paid customer adoption. Negative model findings are retained; no claim of a 90+ organizer score.

---

## Historical supporting draft (not current form answers)

**STATUS: NOT SUBMITTED.** This document is public-safe text, not an H2 confirmation receipt, network adapter registration, bounty acceptance or proof that a 2–5 minute video exists. Only fill the remaining fields with genuine evidence.

**Official competition:** [Telegraph Season II](https://hackathon.telegraphprotocol.com/)  
**Track:** Evaluators  
**Intent:** SECURITY_REVIEW_GENERAL (shared scoring family SECURITY_REVIEW)  
**Project:** FALSUM  
**Current release checkpoint:** November 24, 2026; [5-minute evidence-first judge start](H2_NOV24_JUDGE_START.md).
**Internal completion target:** Sunday, November 22, 2026. Historical build target, now elapsed; this is not the official deadline, authorization to submit, or evidence of readiness.  
**Actual official deadline:** December 1, 2026 at 23:59 UTC

## Latest measured application evidence — 24 November 2026

[Phase 5AJ](PHASE5AJ_CROSS_APP_EVIDENCE_AVAILABILITY.md) and [Phase 5AK](PHASE5AK_EXTERNAL_LABEL_BASELINES.md) are merged and verified. Two separately authored Mission 14 apps supply original published source records. The full scale comparison includes 129 latest contract labels, 158 decision events, 202 purchases and 70 errors. The original archive reports 201 SETTLED and one NOT_FOUND. The FALSUM consumer policy flags 89/107 vulnerable-labeled cases and gives zero vulnerable-label PASS predictions versus eight count-only; it ties verdict-only and flags five rather than one audited controls. This is retrospective evaluation material, not security clearance, independent expert gold, paid inference by FALSUM, outside adoption, or network ranking improvement. The two original reports and all limitations are linked from the [judge guide](H2_NOV24_JUDGE_START.md). The release checkpoint `8df1942791dc2fcd1b9de4ae5bdf46624839d62a` matched Vercel READY and six successful post-merge workflows. [Reviewer request #97](https://github.com/Iniwura/falsum/issues/97) was subsequently answered by the Gig Guard maintainer. See the newer checkpoint below.

## Latest developer-confirmed evaluation improvement — 24 November 2026

[Truvian Shield maintainer's public memo verification](https://github.com/Iniwura/falsum/issues/97#issuecomment-7132041935) confirms the two parsed live-answer fixtures. [Phase 5AR](PHASE5AR_TRUVIAN_RESPONSE_INTEGRITY_GATE.md) adds a portable response-integrity gate and [successful original-source CI replay](https://github.com/Iniwura/falsum/actions/runs/45476259143) across all nine direct fixture declarations. Three explicitly missing-code cases: verdict-only admits 3/3 clean candidates, Secure + zero count admits 2/3, and FALSUM admits 0/3. Two are maintainer-confirmed; the third is a developer-reported node-shaped fixture. This is a bounded retrospective comparison, not a semantic model-accuracy, network-ranking, or accepted-integration result.

[Verified dated public updates and technical discussion](H2_VERIFIED_GROWTH_EVIDENCE.md) are ready for the form. No outside fork execution or accepted integration has been verified. No final entry or video has been submitted.

## Earlier integrated release checkpoint — 24 November 2026

[Public Gig Guard source-maintainer review](https://github.com/Iniwura/falsum/issues/97#issuecomment-7126424685) independently checks the source records, confirms the historical counts and explains the preflight holds. [Phase 5AN](PHASE5AN_MAINTAINER_COVERAGE_TAXONOMY.md) encodes that clarification in an authenticated replay, confirmed by [Successful Phase 5AN post-merge replay](https://github.com/Iniwura/falsum/actions/runs/45369264734). Latest case population: 103 answers, four failures, 22 explicit input-limit holds; all 22 had earlier recorded security failures. No independent fork execution, app integration, expert gold or network ranking improvement is claimed.

[Live application evidence](https://falsum-evidence-lab.vercel.app/applications/) is deployed. PRs [#99](https://github.com/Iniwura/falsum/pull/99), [#101](https://github.com/Iniwura/falsum/pull/101), and [#102](https://github.com/Iniwura/falsum/pull/102) passed 54/54, 48/48 and 21/21 checks respectively; six post-merge workflows passed on `b120bfbacf4f88bc2b9570b2afb43762c4406d95`, matching Vercel READY. This checkpoint is historical, not a guarantee that later changes have passed CI.

## Earlier judge and production checkpoint — 24 November 2026

- **Verified production:** Vercel reports existing owned project `falsum-evidence-lab` READY on deployment `dpl_DN4yMnNdqqi8un4fdB3heAtuqEVg`, Git commit `4ef69c601cc3bd65c171fa329208b102e6ac0182` (Phase 5AI), matching `main` at this checkpoint.
- **Merged engineering:** [Phase 5AH #93](https://github.com/Iniwura/falsum/pull/93) passed 35/35 PR checks, [Phase 5AI #94](https://github.com/Iniwura/falsum/pull/94) passed 50/50 PR checks. Latest `main` post-merge runs succeeded **8/8**, including production witness HTTPS check.
- **New reviewer path:** the [judge-start page](H2_NOV24_JUDGE_START.md) links the live witness, one-click independent fork workflow, pinned advisory source decision CLI and real negative model results.
- **Remaining hard gates:** external reviewer action, qualified expert labels, required entrant GitHub bounties star, separate-date public updates, final 2–5 minute demo/equivalent, owner-controlled permissions and official entry. They are **not** implied by PR checks or deployment status.
- **Do not infer:** a browser-based general CVE scorer, new qualified model accuracy, an accepted Telegraph ranking, or a registered scoring adapter from Phase 5AG/5AH/5AI source-only code.

## Production verified after the November 22 release

The owned Vercel project `falsum-evidence-lab` (project `prj_8yFMECbS8rbZocliI1yL9eBtYsv6`) reports production deployment `dpl_8wz8KU6yWQSKxhWfLzBjHtmS9UmZ` as READY from Git SHA `cae27afd7ebd6284facae2983b675f4d48d76957` (Phase 5AG). That was the then-latest merged `main` and resolves the former stale-deployment SHA mismatch. This Vercel metadata is **not** proof that a browser-time Phase 5AG evaluator route exists: the new multiecosystem evaluator is presently an installed CLI/CI function. The earlier five-source public witness remains distinct.

After the Phase 5AH parser change, recheck the exact deployed SHA before claiming that *new* parser code is production. A new source-only PR or merge never automatically proves a production release.

The formal H2 submission, 2–5 minute video, verified independent fork/reproduction and qualified outside expert labels remain unconfirmed. No new network ranking or registered improved evaluator is claimed.

## Latest development sign-off evidence (21 November 2026)

The [Phase 5P original authenticated-code evaluator](PHASE5P_AUTHENTICATED_RAW_CODE_EVALUATOR.md) implements a new working public CLI flow: full-source Git SHA integrity verification for eight pinned raw-code revisions across four previously investigated upstream projects, a class-balanced twelve-condition external model response protocol, strict failure handling, and a real published-model CPU measurement. The actual small published Qwen model **ABSTAINED on all twelve**, achieving **4/12** public research-reference matches, **0/4** complete code revisions, and **4/4** missing-code abstentions. It did not beat constant ABSTAIN or the disclosed 8/12 source-blind shortcut. Original [real Actions run 44852933182](https://github.com/Iniwura/falsum/actions/runs/44852933182) and [per-file original ZIP SHA256 index](../evidence/phase5p-2026-11-21-authenticated-raw-code-negative.json). These are real raw-code inputs, unlike Phase 5O's author-written summaries, but **still public known historical fixes and researcher-derived labels, not independent human gold**.

For judging use the [five-minute reproduction guide](H2_FIVE_MINUTE_JUDGE_REPRODUCTION.md). The main official submission remains **NOT SUBMITTED**, and no organizer-accepted 2–5 minute video/equivalent, owner-required GitHub star evidence, official form receipt, showcase permission or independent developer use has been verified. Do not promote any of these to completed.

## Current entry-safe evidence, superseding older dated paragraphs (20 November 2026)

**Use the current [judge guide](H2_EVALUATORS_JUDGE_PACK.md) and [strict readiness audit](H2_NOV20_FIRST_PLACE_READINESS_AUDIT.md), not the old Nov 18 source counts below, when preparing the eventual official entry.** The live source-review page has **5 real historical source-test repair stages in 4 public upstream projects**, with **80 constructed Python-source evidence verdicts** (10 supported / 10 contradicted / 60 abstained). [The latest automatic real production HTTPS check](https://github.com/Iniwura/falsum/actions/workflows/phase5e-live-production-source-freshness.yml) validates actual Vercel output after every main commit.

**Important measurement correction:** A [Phase 5K adversarial audit](PHASE5K_SOURCE_BLIND_LEAK_AND_BALANCED_CHALLENGE.md) showed a trivial **80/80 source-blind metadata-only shortcut** on the original Phase 5F scorecard. The entry must **not** advertise any constructed 80-item match rate as learned evaluator accuracy. The newer 30-item balanced public challenge avoids the obvious explicit revision-role cue but is **still open book**; its disclosed source-blind A-is-parent control achieves 22/30. It is genuine evaluation-material engineering, not independent expert gold or proven model improvement.

The original trained Foundation LoRA still failed its narrower comparison; no registered improved scorer exists. Public Anjoman historical 20/20 address Eligible receipts and the main H2 submission are separate. Independent human gold, verified external adoption, final video/equivalent, required bounties star, account permissions and official final entry remain unresolved. **This document remains a draft; do not submit, publish a demo, or pretend owner-only consent has been granted.**

**Further original-source evidence (20 November):** A [sixth real maintainer-authored regression on pymdown-extensions](PHASE5L_SIXTH_ACTUAL_UPSTREAM_SOURCE_CASE.md) was executed against its vulnerable direct parent and original fixed commit. [Seven actual GitHub Actions jobs passed](https://github.com/Iniwura/falsum/actions/runs/44711309872) across Python 3.11 and 3.13, including the expected parent-fail/fixed-pass security regression and source/test Git hashes. This extends original upstream regression coverage to six historical repair stages across five distinct projects. The extra stage is separate from the five-case public UI and its 80 constructed source verdicts, and is not an independently chosen blind case, new model evaluation, expert gold or registered Telegraph scorer. This final-entry text remains **DRAFT, NOT SUBMITTED**.

**Phase 5M candidate scoring update (20 November):** [A small publicly reproducible code-revision candidate-evaluator exercise](PHASE5M_REAL_ORIGINAL_MODEL_SOURCE_SENSITIVITY.md) now accepts outside developer model predictions with A/B/ABSTAIN, source-revision reversal checks and a no-source abstention control. The task contains three constructed questions from the authenticated sixth original source repair, not a statistically meaningful independent model-accuracy benchmark. Constant-choice baselines match 1/3 by construction. **No actual outside candidate model response has been verified.** The separately frozen experiment to rescore the original unchanged LoRA on this project was **blocked because its original GitHub checkpoint archive is unavailable**; no new original-model score or trained improvement exists. The model availability gate returns a truthful missing-artifact receipt and skips real inference. The historical model failed its earlier recorded 5/8, 1/4 comparison; no independent human gold, newly eligible Anjoman submission or final H2 entry is asserted. The document remains **DRAFT, NOT SUBMITTED**.

**Additional independently reproducible negative measurement (Phase 5N, November 20):** [Genuine, researcher-operated Qwen2.5-0.5B-Instruct model run](https://github.com/Iniwura/falsum/actions/runs/44739535866) against the unchanged previously frozen public source/no-source experiment returned **ABSTAIN on all three conditions**. The published external model scored **1/3 author-constructed source references**, **0/2 source-present original test facts**, **0/1 correct before/fix code reversal**, and did abstain without source. It did **not outperform constant ABSTAIN**, so no learned evaluation improvement is claimed. [Provenance-pinned real output and exact model-weight archive evidence](../evidence/phase5n-2026-11-20-real-open-weight-model-negative.json). This model was run by the FALSUM researcher, not independently submitted by another developer. The original Telegraph LoRA was not recovered, model registration remains false, and this draft remains **UNSUBMITTED**.

## Verified project links

- **Real upstream security-review verifier (strongest current public technical result):** https://falsum-evidence-lab.vercel.app/witness/ (four actual source-fix stages across Koa, Hono and LangChain; 64 precomputed typed evidence checks, original upstream Git/test and CI receipts)
- **Live interactive evidence challenge:** https://falsum-evidence-lab.vercel.app/
- **Genuine recorded model-score judge experience:** https://falsum-evidence-lab.vercel.app/proof/
- **Recorded code-revision model comparison:** https://falsum-evidence-lab.vercel.app/compare/ (four different public upstream source projects; 5/8 researcher-source matches, 1/4 complete reversals, 4/8 constant-choice controls, old checkpoint unchanged)
- **Public repository and reproducible README:** https://github.com/Iniwura/falsum
- **Original model inference verification:** https://github.com/Iniwura/falsum/actions/runs/43291803205
- **Pinned upstream source verification:** https://github.com/Iniwura/falsum/actions/runs/43287674960
- **Source-grounded reference checks:** https://github.com/Iniwura/falsum/actions/runs/43297345188
- **Historical public contributor submission (bounty #96 closed during mission migration, not accepted):** https://github.com/telegraphprotocol/bounties/issues/96#issuecomment-6588168396
- **Independent review invitation:** https://github.com/Iniwura/falsum/issues/25
- **Judge reproduction:** https://github.com/Iniwura/falsum/blob/main/docs/H2_EVALUATORS_JUDGE_PACK.md

**Browser-verifiable current public build (November 18):** The [live-source test reviewer](https://falsum-evidence-lab.vercel.app/witness/) is a self-contained, no-key public interface to the real Phase 4R/4S/4T/4U upstream proof chain. A judge can switch among four historical patch stages, compare vulnerable parent and fixed revisions, assert a regression result, corrupt a receipt digest or overclaim production exploitability. The displayed SUPPORTED / CONTRADICTED / ABSTAIN results come from 64 **Python-precomputed source-bound checks**, not live model inference or human expert labels. [Complete evidence provenance and browser acceptance](PHASE4V_REAL_SOURCE_WITNESS_WEB_LAB.md). The three-case fictional review challenge remains separate and explicitly labeled; it is not offered as real upstream integration.

**Runnable evaluation process:** I provide a [typed source-witness claim gate](PHASE4U_SOURCE_REVIEW_CLAIM_GATE.md) that accepts code/test provenance and chooses SUPPORTED, CONTRADICTED or ABSTAIN for narrowly defined historical test claims. Seven public examples cover true and false regression assertions and unsupported production claims. The 32 additional source-derived regression fixtures are deliberately *correct by construction*, **not a neural evaluator benchmark, independent expert gold, network scoring adapter or registered model improvement**. The four original true regression witnesses were obtained through live upstream executions and pinned by original GitHub artifact hashes.

**November 18 verified executable source coverage (latest technical evidence):** Real upstream code/test replay across [Koa and Hono](https://github.com/Iniwura/falsum/actions/runs/44352329150) and [both LangChain security fix stages](https://github.com/Iniwura/falsum/actions/runs/44353999011) now proves **four specific historical source-regression reversals across three public upstream projects**: the genuine original tests passed, the fixed-version upstream security test failed for the expected assertion on the vulnerable direct parent, then passed on the fixed implementation. All involved source and test Git file blobs and original execution logs are bound to machine-checkable GitHub Actions receipts. The [Phase 4T single-source proof](PHASE4T_ONE_COMMAND_REAL_SOURCE_TEST_PROOF.md) links all checks and a consolidated run verifier. **This is a stronger public evaluation-material evidence artifact; it is not a trained model accuracy gain or an independently reviewed gold label.**

**14 November evidence update (historical state, superseded on November 18):** A real [Phase 4K live readback](https://github.com/Iniwura/falsum/actions/runs/43619793133) found **0 rows for the public bounty-comment contributor address** (checksum-case and lowercase), while the then-active Intent-wide pool contained **199 eligible rows across 9 eligible submitters**. At that date the contributor address and signed-in account had **not yet been reconciled**. The later November 18 **correct-Privy-wallet 20/20 Eligible node verification**, below, resolved why the earlier wrong-address query returned zero; this is **not** a maintainer acceptance verdict. [Historical reproduction](PHASE4K_LIVE_SUBMISSION_READBACK.md).


**17 November program audit:** The `SECURITY_REVIEW_GENERAL` evaluation-material path, real source scores, and [Phase 4L external PR Guard failure evidence](PHASE4L_PR_GUARD_REAL_MINER_EVIDENCE.md) are distinct. FALSUM has not integrated a live scorer with PR Guard, authenticated the third-party payment receipts, achieved expert-reviewed gold labels, or proven an improvement over the original model. [Mission 10 Model Economy](https://github.com/telegraphprotocol/bounties/issues/198) is an open mission discussion, not FALSUM's confirmed mission delivery. The original [bounty #96](https://github.com/telegraphprotocol/bounties/issues/96) was closed November 15 due to mission migration; its earlier comments remain visible and are not an acceptance decision.

**November 17 live evidence update:** A new [read-only GitHub Actions probe](https://github.com/Iniwura/falsum/actions/runs/44181080455) returned **HTTPError / contributor status unavailable** for the address in the public /submit; this is **UNKNOWN**, not evidence of zero currently. Separately, the healthy **Intent-wide** node showed **332 Eligible rows across 10 eligible contributors**. Those are NOT FALSUM-owned records. The November 14 zero-row result remains a genuine dated observation, not a claim about the present. At that **November 17** snapshot, the contributor identity and whether my actual Anjoman account's rows remained Eligible were **unresolved**; the November 18 correct-wallet readback below supersedes this historical uncertainty.

**November 17 successful retry:** A later [source-checking CI run](https://github.com/Iniwura/falsum/actions/runs/44181734533) returned **0 rows for the public bounty-comment wallet**, while the overall Intent pool still showed **332 Eligible rows across 10 contributors**. The earlier HTTP error remains part of the audit record. On that date the user-account-to-public-address identity was **unverified**, so the wrong-address zero did not establish that the 20 rows in my signed-in account had vanished or been rejected. The correct-wallet November 18 live verification below establishes 20/20 Eligible for the operator-reported Privy address; it does not prove maintainer acceptance.

**November 18 verified account-address correction:** The operator's signed-in Anjoman dashboard displayed a **Privy Wallet different from the original GitHub /submit wallet**. A new [read-only Phase 4N CI run](https://github.com/Iniwura/falsum/actions/runs/44311491808) verified **20 Eligible out of 20 total rows** for the operator-provided Privy address, and **0 rows** for the incorrect historic bounty-comment address. The 20-row *network status for the Privy address* is independently corroborated; the association of the address with the operator is user-supplied screenshot evidence, not cryptographic ownership proof. The earlier zero-row observations are correct for the wrong address and are not contrary to this result. **Bounty maintainer acceptance remains unresolved**. [Methods and boundaries](PHASE4N_PRIVY_WALLET_RECONCILIATION.md).

**Still needed from owner:**
- Official H2 registration and team/contact details: **UNVERIFIED**
- GitHub username that actually starred telegraphprotocol/bounties: **UNVERIFIED**
- Publicly playable final 2–5 minute demo URL: **NOT UPLOADED OR VERIFIED**. No video work is authorized during the technical audit; this gate remains pending.
- Owner's public showcase and buyer-introduction permissions: **NOT SELECTED**
- At least three published original technical progress URLs on different dates: **NOT VERIFIED**
- Actual successful H2 form submission receipt and entry URL: **NONE YET**

## Project description — ready to paste

**FALSUM evaluates security evidence rather than the confidence of an AI answer.** It contributes source-backed evaluation material for Telegraph's SECURITY_REVIEW_GENERAL Intent, where a security review must distinguish published vulnerabilities from reachable application impact and change its verdict when the relevant facts change.

I uploaded 20 explicitly AI-assisted, source-referenced preference pairs through Anjoman. My signed-in account displayed 20 **Eligible** after the November 2 rollover. On November 18, an independent read-only node query confirmed **20 Eligible records for the public Privy Wallet address shown in my Anjoman account**. An earlier GitHub bounty /submit mistakenly named a different wallet, which explains why its prior API checks found zero. The public address-to-my-account association comes from my account screenshot, not independent cryptographic ownership proof, and **formal maintainer acceptance remains unresolved**. I do not publish hidden prompts, answers or row identifiers.

FALSUM's public research makes the evaluation problem falsifiable. I pinned real GitHub-reviewed advisory and PyPI version records for docling-core, hydra-core and python-multipart. I used the official Telegraph Foundation ONNX/WASI runtime to score the **same unchanged original LoRA** on six affected-versus-fixed version conditions, with 12 authentic scores and 24 repeat-verified inferences.

The observed result was negative: **3/6** matches with narrowly verified source facts and **0/3** complete version-sensitive answer reversals. The model preferred A on all six conditions, matching a trivial constant-A baseline of 3/6. The full bit-exact evidence and source records are public. I have not registered or promoted the failing model.

FALSUM's separate **offline reference checker** verifies source-supported and contradicted advisory/version claims and abstains when evidence is missing or a security assertion goes beyond the source. Across 36 deliberately constructed scenarios it produced 6 supported, 6 contradicted and 24 abstained outcomes, agreeing with its own source-derived expectations **by construction**. This is **new reproducible evaluation coverage**, not a claim that a trained evaluator has reached 100% accuracy.

I also reproduced **four actual upstream security-regression reversals** against exact vulnerable parent and fixed Git commits from three different open-source software projects: Koa's protocol-relative redirect guard, Hono's `text/ping` CSRF guard, and both initial and follow-up LangChain Core prompt-file loading fixes. Each reuses the real upstream regression test. In every case, original functionality passed, the new security regression failed on original vulnerable code for the expected source behavior, and it passed on the fixed implementation. All Git file blobs and actual test-process receipts are linked in my [single-source execution evidence index](PHASE4T_ONE_COMMAND_REAL_SOURCE_TEST_PROOF.md). This is verified **source-level evaluation coverage**; it does not certify expert-reviewed gold labels or a superior trained scorer.

A public website now offers three clear experiences: a three-case interactive security-review challenge backed by real Python execution on **fictional** PR fixtures; an interactive display of the original model's **recorded actual** GHSA-version scores; and a source-revision comparison using four more historical security fixes. The same unchanged original LoRA matched **5/8** source-based researcher expectations and completed **1/4** correct before-to-after reversals against **4/8** for constant-choice baselines on the same eight questions. This is not independent expert-reviewed accuracy or an improved trained model. Reviewers can reproduce the work offline without wallets, model credentials or paid inference.

FALSUM is an **evaluation-material contribution**, not a registered network scoring adapter. It has no claimed independently adjudicated expert labels, verified partner app integrations, production exploits, paying customers, accepted bounty or guaranteed prize. I invite independent reproduction and corrections so the measurement standard can improve.

## Short public summary

**FALSUM — security-review evaluation grounded in facts.**

A model that gives the same answer to an affected and patched version cannot be trusted for context-sensitive security review. FALSUM documents that failure through authentic Telegraph Foundation scoring, a reproducible reference checker, and **four executed security regressions from three real upstream projects**. Each upstream regression was replayed at the exact vulnerable parent and fixed Git commit, with pinned source/test files and GitHub Actions receipts.

I submitted 20 AI-assisted evaluation preference pairs. The November 18 node readback confirmed **20 Eligible** for the operator-shown Privy Wallet; the original GitHub submission listed a different wallet and therefore returned zero. Formal bounty acceptance and independent expert review remain unverified.

[Try the challenge](https://falsum-evidence-lab.vercel.app/) · [See actual model scores](https://falsum-evidence-lab.vercel.app/proof/) · [Run and review the evidence](https://github.com/Iniwura/falsum)

This work is an entry for the prize-bearing Telegraph Season II Evaluators track. I welcome genuine independent tests and criticism; no confidential evaluation questions are published.

## What a judge can test

1. Open the /proof/ page and toggle docling-core 2.48.3 versus 2.48.4. See original model A/A while pinned source-supported answer changes A/B.
2. Repeat with hydra-core and python-multipart. Inspect real exact score bits and published advisories.
3. Open the root challenge, select a weak written review and reveal the executed local fictional before/after test evidence, including legitimate controls.
4. Clone the public repo with Python 3.11–3.13 and build both static pages:
   
   ~~~bash
   PYTHONPATH=src python3 -m falsum.phase4c_release --out-dir reviewer-demo
   ~~~
5. Verify the official upstream scoring and reference-checker CI records linked above, then test five source-grounded sample claims as described in the README. **Do not confuse 36/36 constructed rule checks with model accuracy.**

**Network and costs:** the actual Anjoman submission is a separate signed contributor activity. This public website has no live Telegraph purchase, customer transaction, wallet request or real-time model call. Reproducing the local static demo and deterministic checker uses no credentials and no paid API.

**Security and limitations:** public GHSA version facts cannot establish deployed exploitability or universal software safety. Synthetic before/after examples are not live partner integrations; source facts are publicly known and not a sealed holdout. The failed research LoRAs remain quarantined. Exact private Anjoman prompts and answer pairs are not published.

## What the video must show

Aim for 3 minutes: actual /proof/ affected/fixed switches and genuine scores; actual synthetic challenge and before/after fixture; official GitHub Actions and public source links; truthful Anjoman contributor status without private details. Finish with how another developer can reproduce it. See [the complete shot-by-shot script](H2_EVALUATORS_DEMO_STORYBOARD.md).

**Actual video link:** PENDING. Do not put a fictitious URL in the submission.

## Growth and independent verification

Current evidence: a public interactive challenge, reproducible source checker, authentic CI, an open independent-review issue and educational technical docs.

**Established since the earlier checkpoint:** substantive external developer activation through the linked Gig Guard source-maintainer review and follow-up implementation. **Not yet established:** three verified meaningful public updates on separate dates, further independent developer activity or repeat use, expert AppSec adjudication, or independent mission integration. A GitHub review issue being open is not itself independent adoption. [The growth and outreach plan](H2_ADOPTION_AND_SUBMISSION_PLAN.md) holds suggested original content; only published URLs and genuine third-party actions should be submitted as evidence.

## Submit only when these checks pass

- Official H2 registration, contact and intended Intent selected accurately.
- Required bounties repository star verified with the submitting account, not just assumed.
- Actual 2–5 minute video or accessible equivalent uploaded and playable.
- Public repo, both real and synthetic pages, and instructions verified reachable by unauthenticated reviewers.
- Full GitHub CI and build run green; source evidence and model score references correct; no private material exposed.
- Include the verified [Phase 4N correct-wallet readback](https://github.com/Iniwura/falsum/actions/runs/44311491808): **20 Eligible for the user-shown Privy Wallet, zero for the mistaken GitHub address**. Do not confuse node eligibility with maintainer acceptance, cryptographic address ownership or AppSec expert gold labels.
- Actual public update URLs and outside reproductions included only if they exist.
- Owner grants or declines public showcase and buyer-introduction permissions.
- Submit on the **official H2 site** (not just GitHub bounty) and preserve its real success receipt, timestamp and final entry URL.

A model that fails the source-fact sensitivity tests stays blocked even if the presentation looks good. Winning requires technical validity, independent verification and the judges' decision; an Eligible flag and passing CI are not substitutes.
