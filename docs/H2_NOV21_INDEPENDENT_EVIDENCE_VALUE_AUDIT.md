# FALSUM — independent evidence-oriented competitive audit (21 November 2026)

**Telegraph Season II Evaluators · SECURITY_REVIEW_GENERAL · no demo or H2 submission yet**

## What materially improved after the strict 60/100 audit

This is a factual evidence reconciliation, not a new official judging score. The release addresses **two technical criticisms**, while the third remains unresolved.

### 1. Real application-quality need, not a constructed source quiz

The independent third-party PR Guard builder published real paid-flagged responses to two different **canonical SECURITY_REVIEW_GENERAL** tasks, both reporting Miner **77003**:

| Canonical real original task | Paid-status HTTP result | Actual output | Authenticated FALSUM task-gate |
| --- | --- | --- | --- |
| Review a JavaScript diff | HTTP 200; paid flag true | 100 unrelated GHSA IDs | OFF_TARGET_ADVISORY_FEED |
| Assess npm lodash 4.17.15 security | HTTP 200; paid flag true | The *same* ordered 100 GHSA IDs; zero lodash-specific advisory mentions | OFF_TARGET_ADVISORY_FEED |

Original independently published capture source: [PR Guard issue](https://github.com/telegraphprotocol/bounties/issues/187) and the exact pinned original Git blobs in [Phase 5R's original evidence](../evidence/phase5r-2026-11-21-original-telegraph-two-task-invariance.json). No request or response text from a third party is duplicated in FALSUM's public aggregate artifacts.

**What this proves:** A task-insensitive miner output can look successfully delivered and paid. FALSUM's source/package relevance check correctly identifies two original real instances, without mistaking bare HTTP success for quality.

**What it does not prove:** That FALSUM improves live network ranking, that another miner was better under an identical canonical request, that captured payment flags have been cryptographically settled, or that PR Guard installed FALSUM. Two failures from one miner are still only two examples.

### 2. Source-blind scoring no longer looks like success

The historic source scorecard had an authenticated **80/80 metadata-only shortcut**, then an improved 30-question exercise still allowed **22/30 without reading code**. The benchmark validity problem was real, and we documented it.

The [Phase 5S preregistered source/answer-position challenge](PHASE5S_FOUR_WAY_SOURCE_SENSITIVITY.md) now has **24 balanced prompts**: eight A, eight B, eight ABSTAIN; eight full-file Git-verified original source excerpts across four public projects; two answer orders; original vulnerable/fixed revision and code-omitted controls.

**Primary endpoint: a complete correct four-way reversal** when code changes and answer order swaps. Under the defined prompt-only source-masked attacker, **0/4 is the maximum**. The attacker can still collect up to 16/24 raw agreement by choosing the same code answer and abstaining when source is absent. A model must change its output according to authentic source content to cross the four-way bound.

This is a legitimate **metric-strength improvement and anti-shortcut proof**. It is not an independent expert gold set, secret evaluation pool or generalizable model-accuracy result. Original source URLs are public, and attackers capable of outside lookup can retrieve the references. The previously studied cases are only four projects.

### 3. Two genuine published model checkpoints tested, with negative results retained

In original successful GitHub Actions [Phase 5S real model run](https://github.com/Iniwura/falsum/actions/runs/44857757905), actual immutable publisher checkpoints Qwen2.5-0.5B-Instruct and Qwen2.5-1.5B-Instruct each processed **24 original authenticated source prompts**. Both returned ABSTAIN on every prompt:

| Genuine original model | Total | Source-present | Missing-source | Four-way reversals |
| --- | ---: | ---: | ---: | ---: |
| Qwen2.5-0.5B-Instruct | 8/24 | 0/16 | 8/8 | 0/4 |
| Qwen2.5-1.5B-Instruct | 8/24 | 0/16 | 8/8 | 0/4 |
| Declared *synthetic* source-blind baseline | 16/24 | 8/16 | 8/8 | 0/4 |

Full original model weight hashes, challenge SHA-256, original model raw completions, authentic GitHub Actions artifact IDs and original ZIP/content hashes are in the [Phase 5S permanent provenance index](../evidence/phase5s-2026-11-21-authenticated-dual-model-counterfactual-negative.json).

**Main result:** The test reveals complete source non-responsiveness by these two particular models on four public security puzzles. It does not demonstrate FALSUM's evaluator itself is more accurate, that source interpretation has a validated expert gold standard, or that model scale inherently affects score.

## Highest-impact work still needed for first place

1. **Independent expert-source validity** remains unresolved. The historical Git source bytes and upstream tests are real, but the question interpretation and expected classifications are author-derived. External disagreement must be recorded, not coerced into a target score.
2. **Demonstrated same-Intent ranking value** remains unresolved. The PR Guard captures are invaluable task-failure evidence, but there is no fair same-request two-miner comparison with independent semantic quality labels. Do not rank a direct SECURITY_REVIEW request against a canonical SECURITY_REVIEW_GENERAL route.
3. **Live Telegraph evaluator artifact registration** is still unverified. The Evaluators track permits useful evaluation material, so this is not automatically disqualifying, but actual integration/eligibility evidence should be explicit.
4. **Outside developer adoption and demo** will be handled later. Current owner-submitted public PR/issue comments and researcher-operated model runs do not count as independent use.
5. **Final official H2 submission and its owner-controlled steps** remain pending. The user has confirmed starring the Telegraph bounties GitHub repository, but full account-level star ownership proof has not been independently retrieved.

## Operational status / qualified sign-off

- Public FALSUM repo, original-source verifier, browser witness lab, multi-Python test matrix, reproducible CLI and retained original model output are real.
- Phase 5Q and Phase 5R both merged after authentic live external-source verification and all PR checks. Phase 5S remains a separate release until its own PR checks clear.
- Production deployment on Vercel must be verified after any merge; do not equate prior preview/production readiness with the latest commit without a fresh check.
- **Do not report a 90+/100 judge score on these facts alone.** This audit reflects real progress against the previous technical deductions but independent validity and Telegraph ranking impact remain open.

## Immediate route for a reviewer

Run `falsum audit-telegraph-consistency --out original-pair.json` to see a real paid-success/task-relevance contradiction; run `falsum score-counterbalanced-source export --questions-out public-24.json --template-out decisions.json` and score an outside method; inspect both original Qwen raw outputs and their negative result. Then challenge the reference answers and the source-blind threat model. Use only genuine actual network records for any paid or ranking assertions.

**Short thesis:** Real quality ranking must distinguish successful delivery from relevant intelligence, and source-review answers must change when authenticated code changes, not when public metadata changes.
