# FALSUM

**Evidence-grounded security-review evaluation for Telegraph's `SECURITY_REVIEW_GENERAL` Intent.**

A reliable security review changes when the evidence changes. FALSUM tests that requirement against real vulnerable and fixed open-source code, distinguishes source-supported facts from unsupported security claims, and publishes failures as well as successful checks.

**Public deployment status (Nov 19):** The merged source and CI now support five authenticated historical fixes, including Flask. The Vercel production alias still serves an older four-case commit because the account reached its free daily deployment cap. The [strict source-freshness release gate](docs/PHASE5E_PRODUCTION_FRESHNESS_GATE.md) and [tracked release blocker](https://github.com/Iniwura/falsum/issues/61) remain open. **Do not claim the fifth case is live until the actual alias passes that gate.**

[**Explore real code and tests**](https://falsum-evidence-lab.vercel.app/witness/) · [**Run locally**](#run-the-check) · [**See genuine model results**](https://falsum-evidence-lab.vercel.app/compare/) · [**Verify the four executions**](docs/PHASE4T_ONE_COMMAND_REAL_SOURCE_TEST_PROOF.md)

## Try the real upstream verification lab

**[Open the interactive source-evidence workbench](https://falsum-evidence-lab.vercel.app/witness/)**

Choose a real Koa, Hono, LangChain or Flask security fix. Switch between the exact vulnerable parent and fixed Git commits. Assert that its security test passes or fails, then inspect the source-backed **SUPPORTED / CONTRADICTED / ABSTAIN** verdict. Try a deliberately **wrong execution receipt SHA**: FALSUM abstains rather than endorsing bad evidence. A production exploit or universal-safety claim also abstains because upstream unit tests cannot prove either.

The current five-source workbench presents **80 exact outcomes precomputed by FALSUM's independently rerunnable Python source-witness checker** from four original authenticated regression receipts and the separately archived real Flask Actions proof. It is not a second trained model, 80 independent reviews, a network evaluator, a live production scan, or expert-reviewed gold. [How the five-case UI is verified](docs/PHASE5D_FIVE_CASE_PREMIUM_JUDGE_WORKBENCH.md).

## What works

| Verifiable result | Evidence | Boundary |
| --- | --- | --- |
| **Interactive public source review** at [the real-code lab](https://falsum-evidence-lab.vercel.app/witness/) | Five historical source-fix stages across four upstream projects, two exact Git revisions each, claim and receipt-integrity controls, 80 precomputed source-grounded outcomes. [Chromium QA and source evidence](docs/PHASE5D_FIVE_CASE_PREMIUM_JUDGE_WORKBENCH.md) | Historical source-test behavior, **not** real-time model inference or arbitrary-prose scoring |
| **4 real parent/fix regression reversals across 3 upstream projects** | [One authenticated GitHub Actions proof](https://github.com/Iniwura/falsum/actions/runs/44356563508) · [Permanent digest index](evidence/phase4u-2026-11-18-permanent-four-executed-source-witness-index.json) | Reproducible *source behavior*, not a measured model quality increase |
| **Typed source-witness checker** with SUPPORT / CONTRADICTION / ABSTENTION | [Run seven example claims](examples/source-review-witness-claims.json) · [Source checker](src/falsum/source_review_witness_gate.py) | Evaluates structured claims, not arbitrary natural-language reviews |
| **20 out of 20 Anjoman evaluation pairs marked Eligible** for the operator-shown Privy Wallet | [Read-only corrected-wallet verification](https://github.com/Iniwura/falsum/actions/runs/44311491808) · [GitHub bounty submission](https://github.com/telegraphprotocol/bounties/issues/96#issuecomment-6588168396) | Eligibility status is verified for the public address; **maintainer acceptance remains unresolved** |
| **Authentic negative trained-model evaluation** on four earlier source-project cases | [Original Foundation score run](https://github.com/Iniwura/falsum/actions/runs/43530363990) · [Reproducible comparison](docs/PHASE4I_JUDGE_COMPARISON.md) | The unchanged LoRA matched 5/8 researcher source expectations and 1/4 complete reversals versus 4/8 for either constant-choice baseline. **No demonstrated trained-model improvement** |

FALSUM targets the **Evaluators** track through **evaluation material and a source-bound evaluation process**, not a claimed registered scorer. The existing 20 Eligible submissions are separate from the four publicly executed upstream regression cases.

## Run the check

The main developer workflow requires **Python 3.11+** and no model endpoint, private Anjoman data, wallet or paid API.

```bash
git clone https://github.com/Iniwura/falsum.git
cd falsum
python -m pip install --no-deps -e .

falsum verify-source-review \
  --index evidence/phase4u-2026-11-18-permanent-four-executed-source-witness-index.json \
  --source-lock data/phase4p-three-project-open-review-lock.json \
  --requests examples/source-review-witness-claims.json \
  --out source-review-results.json
```

**Expected:** 2 `SUPPORTED`, 2 `CONTRADICTED`, 3 `ABSTAIN`. The wrong source-receipt hash is refused. The result is tied to actual Git source/test byte identities and previously executed upstream test outcomes.

Omit `--requests` and use a different output filename to run **32 automatically constructed guards**: 8 supported, 8 contradicted, 16 abstained. These all match their *source-derived expectations by construction*, **not because a trained evaluator reached 100% accuracy**.

[Checker specification and limitations](docs/PHASE4U_SOURCE_REVIEW_CLAIM_GATE.md) · [Source-backed regression tests](.github/workflows/phase4u-typed-security-witness-gate.yml)

## Additional authenticated source-case replay (Phase 5C)

**[Reproduce a fifth historical source witness, Flask](docs/PHASE5C_AUTHENTIC_FLASK_FIFTH_WITNESS.md).** The five-case offline checker preserves the original four immutable Koa/Hono/LangChain receipts and admits Flask's real upstream parent-fail/fix-pass session `Vary: Cookie` regression only from its **original, GitHub-SHA-256-pinned Actions ZIP artifact**. Its 40 constructed controls cover 10 supported, 10 contradicted and 20 abstained typed source claims across 4 distinct upstream repositories. These are **source-test consistency checks, not learned-model accuracy, independent expert labels or blind new-case generalization**. The existing four-witness command above remains unchanged.

## Score an evaluator's own predictions (Phase 5F)

**[Open-book source-review prediction scorecard](docs/PHASE5F_OPEN_EVALUATOR_SCORECARD.md).** FALSUM exports 80 no-answer historical source-test questions and an unfilled prediction template. A developer can submit their **own** SUPPORTED / CONTRADICTED / ABSTAIN judgments through the installed CLI, then inspect exact agreement, macro class recall, unsupported confident claims and correct vulnerable-parent-to-fixed reversals. No secrets, wallet or network access needed.

The trivial always-ABSTAIN baseline gets **75% raw agreement** because 60 of 80 constructed conditions are evidence-limited, but only **33.3333% macro recall and 0/5 complete source reversals**. This illustrates why one raw percentage is insufficient. The public questions are deliberately source-derived and **not independent expert gold, a blind model holdout, actual trained-model performance or a registered Telegraph scoring adapter**. [Follow the independent developer tutorial](docs/PHASE5F_OPEN_EVALUATOR_SCORECARD.md#try-it-with-python-311).

## Four real upstream regression witnesses

Each stage is a counterfactual using the third-party project's **own original regression test**:

1. Original upstream functionality runs on the vulnerable direct-parent Git commit and **passes**.
2. The actual fixed-commit security regression is run against that original vulnerable source and **fails for the expected behavioral assertion**, not because a dependency is missing.
3. The identical security regression is run against the pinned fixed upstream source and **passes**.

| Public repository | Actual security condition tested | Real execution |
| --- | --- | --- |
| Koa · `koajs/koa` | Protocol-relative `Referer` redirect bypass | [Source-and-test CI](https://github.com/Iniwura/falsum/actions/runs/44352329150) |
| Hono · `honojs/hono` | Cross-origin `text/ping` CSRF filtering | [Source-and-test CI](https://github.com/Iniwura/falsum/actions/runs/44352329150) |
| LangChain Core, initial fix | Default absolute/`..` prompt-path restriction | [Two-stage source CI](https://github.com/Iniwura/falsum/actions/runs/44353999011) |
| LangChain Core, follow-up | Resolved symlink target file-suffix validation | [Two-stage source CI](https://github.com/Iniwura/falsum/actions/runs/44353999011) |

The [Phase 4T verification workflow](.github/workflows/phase4t-github-execution-proof.yml) independently retrieved all four immutable GitHub Actions evidence artifacts and verified the source/test Git SHA pins, original run SHAs, outcome statuses and process log digests. The [permanent hash snapshot](evidence/phase4u-2026-11-18-permanent-four-executed-source-witness-index.json) preserves core receipt identities even after GitHub's downloadable artifacts expire; authentic replays remain available through the pinned source workflows.

A [source-level adversarial AI review](docs/PHASE4Q_AI_ADVERSARIAL_SOURCE_REVIEW.md) identifies limits in Koa's host-only comparison, LangChain's template-suffix check and Hono's simulated `app.request()` coverage. **This internal AI assessment is not independently verified human gold or an external AppSec label.**

## Security-review decisions

An agent or developer submits a **typed review claim** with its upstream commit, source file Git blob, exact security-regression test blob, and original execution receipt hash.

The checker returns **SUPPORTED** when an asserted parent/fix regression result matches the source-executed fact; **CONTRADICTED** when the same tested fact directly disproves the assertion; or **ABSTAIN** for unknown revisions, bad evidence and untested production exploitability or universal safety claims. An ungrounded review never becomes a verified result merely because it sounds convincing.

This process does **not** parse natural-language security reviews, establish application exploitability, produce independent qualified reviewer labels, register a network scoring adapter or create new eligible evaluation pairs. The original research LoRA remains quarantined.

## Contribution and status

- **20 Eligible pairs, verified on November 18:** The public node returned 20 total, 20 Eligible for the Privy address provided from the signed-in Anjoman account. The address association is based on the operator's account panel, not independent cryptographic signer proof. The historical GitHub bounty submission was corrected to the matching wallet; **maintainer acceptance is not confirmed**.
- **November 14 historical wrong-address query:** The public bounty-comment address returned **0 rows**. This was a different wallet, not evidence the actual Anjoman pairs had disappeared.
- **Latest read-only network check (November 17):** The then-published, wrong-wallet contributor lookup had an **HTTP error**; its current status was **UNKNOWN**. A separate **Intent-wide** query returned **332 Eligible rows across 10 contributors**, not 332 FALSUM-owned rows.
- **Corrected network verification (November 18):** The live [dual-wallet readback](https://github.com/Iniwura/falsum/actions/runs/44311491808) confirmed **20 Eligible** for the correct operator-provided **Privy Wallet**, and **0 rows** for the historical wrong /submit address. The earlier UNKNOWN and zero were dated *wrong-address* observations. Final **maintainer acceptance remains unresolved**.
- **Phase 4L external evidence:** A separately pinned [PR Guard three-miner receipt study](docs/PHASE4L_PR_GUARD_REAL_MINER_EVIDENCE.md) documents public third-party routing/relevance failures, not FALSUM adoption, certified model performance or a verified fair leaderboard.

**The real measured old-model result remains negative:** 5/8 provisional source matches, 1/4 complete source-sensitive reversals, versus 4/8 constant-choice controls. The failing research checkpoints remain quarantined. [Original score ledger](evidence/phase4h-2026-11-14-actual-original-model-source-8-conditions.json) · [Full technical interpretation](docs/PHASE4H_NEW_PROJECT_DIAGNOSTIC.md).

No expert-validated gold labels, sealed model holdout, documented external application adoption, improved registered model, or official H2 submission receipt is claimed.

## Phase 4Y: two additional real historical replay families

[**Reproduce the cross-family historical replay**](docs/PHASE4Y_CROSS_FAMILY_RELIABILITY.md): the new CI runs installed affected/fixed Starlette and Requests versions on synthetic inputs, alongside authentication of the original four-source proof. These two additional projects were **already researched earlier**; this is new combined execution coverage, **not an unseen holdout, model improvement, or independent expert gold**. See the linked CI status before claiming a successful new replay.

## Phase 4Z: verified new Flask source project

[**New original upstream security regression**](docs/PHASE4Z_FLASK_NEW_SOURCE_CASE.md) · [Passing real source-test workflow](https://github.com/Iniwura/falsum/actions/runs/44524997174)

At exact Flask historical source/test Git revisions, its upstream-authored permanent-session `Vary: Cookie` regression **fails on the vulnerable parent for the expected missing-header behavior and passes on the fixed commit**, while the old control passes. This adds **one new public upstream project** beyond the four authenticated source-witness stages and two older historical library-method replays. It was **researcher-selected**, not a blind model holdout or independent expert-reviewed gold. Phase 5C separately admitted the exact archived Flask CI proof into a five-source structured checker; Phase 5D also exposes it in the same public workbench. Neither extension proves semantic model generalization.

## Phase 5A: independently checkable external review intake

[**Read the four-source review census protocol**](docs/PHASE5A_PUBLIC_EXECUTED_REVIEW_INTAKE.md). The live read-only GitHub issue scanner validates external review-form structure against immutable Koa, Hono and LangChain parent/fixed/test source pins. It distinguishes format-valid claims and disagreements from independently authenticated AppSec judgments. **Zero expert gold is inferred from GitHub identity, checkboxes, or agreement.** The former four-case research intake remains separate.

## Independent review welcome

**[Review one real upstream security fix](docs/REVIEW_FOUR_EXECUTED_CASES.md)** · [Open the source-cited review form](https://github.com/Iniwura/falsum/issues/new?template=independent-executed-source-review.yml)

A developer can independently inspect **one** of the four executed Koa, Hono and LangChain historical fixes using immutable parent/fixed source, the actual upstream test, and an open-ended question. The reviewer can disagree or **ABSTAIN**; no account, wallet, model access or hidden evaluation answers are needed. **No independently validated external AppSec gold labels are claimed**. A submitted GitHub review remains an unadjudicated source claim until its substance, author independence and expertise are separately checked.

## Official Season II submission status

**[Check the verified evidence against the current official competition requirements](docs/H2_NOV19_RULES_AND_SUBMISSION_GATE.md)**. This separates the real four-stage source execution, the 20/20 Eligible public-Privy-address readback and the negative old-model scores from **unverified owner-only requirements**: confirmed Season II registration, GitHub bounties star, genuine independent review, published progress-update URLs, the authorized 2–5 minute demo or accessible equivalent, showcase permissions and the actual official H2 submission receipt. **No completed entry, acceptance or prize is claimed.**

## Reproduce and review

- [Real-source evidence, one-page judge guide](docs/PHASE4T_ONE_COMMAND_REAL_SOURCE_TEST_PROOF.md)
- [Official source score record and strict release audit](docs/H2_EVALUATORS_JUDGE_PACK.md)
- [Public adversarial shortcut audit](docs/PHASE4O_SHORTCUT_ROSTER_AND_REVIEW_GATE.md): original answer-length shortcut agreed with 13/14 researcher-preferred answers; after an explicitly non-blind revision another question-overlap shortcut still triggered a quality veto
- [Public-source reviewer form](https://github.com/Iniwura/falsum/issues/new?template=independent-phase4p-open-review.yml)
- [Archived full development history and negative findings](docs/RESEARCH_HISTORY_AND_NEGATIVE_RESULTS_ARCHIVE.md)

```bash
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_source_review_witness_gate.py' -v
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_phase4t_four_stage_evidence.py' -v
```

**Hackathon:** Telegraph Season II, Evaluators, `SECURITY_REVIEW_GENERAL`. **Internal engineering target:** Sunday, November 22, 2026. **Official submission deadline:** December 1, 2026 at 23:59 UTC. No completed video, submitted final entry or independently verified source expert certification is claimed. Demo work remains paused until the operator authorizes it.
