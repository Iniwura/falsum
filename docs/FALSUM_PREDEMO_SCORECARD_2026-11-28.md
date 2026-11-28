# FALSUM pre-demo scorecard — 28 November 2026

**Status: below the required pre-demo threshold. No demo or official submission is authorized.**

## Fixed internal sprint score

The internal sprint rubric remains unchanged. This is a project-readiness score, not Telegraph's official score.

| Internal criterion | Score |
| --- | ---: |
| Technical quality | 19/20 |
| Evaluation coverage and originality | 17/20 |
| Measured improvement | 13/20 |
| Evidence and reproducibility | 18/20 |
| Ecosystem impact and adoption | 11/20 |
| **Total** | **78/100** |

**Required pre-demo threshold: 90/100. Gap: 12 points.**

No score increase is recorded in this handoff. The RealVuln maintainer's adoption of the order-invariance fix is real external benchmark impact, but it does not establish Telegraph evaluator-material acceptance, a Solana app workflow, or Telegraph network usage. It therefore does not change this fixed internal score.

## Official Season II rules — separate from the internal score

The [official rules page](https://hackathon.telegraphprotocol.com/rules) was checked on 28 November 2026. It defines the Evaluators track as an evaluation adapter, evaluation material, or both. Every track must show a working contribution, real Telegraph integration, repeatable results, safe handling, accurate claims, and the required bounties-repository star.

The current repo's [Evaluators rubric extraction note](H2_EVALUATORS_RUBRIC_2026-11-27.md) records a client-bundle extraction with these track-specific weights: measurement validity/baselines 40 (technical minimum 28), integrity 15, reproducibility/protocol compatibility 10, useful coverage/improvement 10, documentation/integration 5, and organic growth 20. That note records the official bundle URL and SHA-256. The visible rules page's server-rendered default summary currently shows the Apps & Agents weights (35/25/10/5/5/20), while the page's track selector is client-rendered. The Evaluators bundle was not independently re-fetched and re-hashed during this run; treat the track-specific extraction as source-recorded but provisional until revalidated. Do not use either official rubric to alter the fixed internal sprint weights.

**No official organizer score is available or assigned here.** The historical 96/100 internal readiness mapping and 84/100 judge-style audit mentioned in the November 27 documents are separate historical assessments. Neither is an organizer score, and neither replaces the fixed 78/100 internal sprint score above.

For Evaluators delivery awards, the official rules prioritize distinct commercial missions, distinct H2 app workflows, independently verified missing mission-critical Intent needs, and combined technical quality. Evaluator excellence ties prefer proven measurement improvement or valuable new coverage, then validity. The main competition deadline is **1 December 2026, 23:59 UTC**.

## Current verified evidence and limits

### Phase 5BP public-provider answer audit

[PR #122](https://github.com/Iniwura/falsum/pull/122) remains open. Its previous head `18552161af0727889ff8d58b3f27d3a7d47f0429` had 36 successful pull-request workflow runs. The focused [Phase 5BP workflow](https://github.com/Iniwura/falsum/actions/runs/46036978276) passed. After the finding-binding fix below was merged into the feature branch, PR #122 advanced to head `9ef7b0e8dddf05dc04b1891678ca73233294d586`; its new 36-run matrix was still queued/in progress at the latest check. Do not merge PR #122 until that exact head completes CI and its 40-file diff receives a final review.

The audit uses six immutable public PR Guard response blobs from one pinned commit: three structured and three free-text responses. The recorded result is 18/24 source-bound integrity checks, two fully supported structured actions, and four review holds. The reference oracle is a narrow source-derived pattern check (SQL concatenation, shell construction, and dynamic execution), not human AppSec gold, a blind source-disjoint holdout, or a general vulnerability detector. It does not establish provider accuracy or a Telegraph ranking change.

A code review found that duplicate findings could reuse one evidence source and malformed findings without a rule ID were skipped. [PR #123](https://github.com/Iniwura/falsum/pull/123) is now merged into the feature branch as commit [`9ef7b0e8dddf05dc04b1891678ca73233294d586`](https://github.com/Iniwura/falsum/commit/9ef7b0e8dddf05dc04b1891678ca73233294d586), not into main. Its eight hosted workflows passed. The Phase 5BP contract job ran 11 tests, including duplicate-source reuse rejection, malformed-finding rejection, and a valid two-source positive case; the public replay remained 18/24, 2/6 supported actions, and 4/6 holds. Evidence: [Phase 5BP run](https://github.com/Iniwura/falsum/actions/runs/46114762639) and [Foundation run](https://github.com/Iniwura/falsum/actions/runs/46114762622).

### Anjoman material

[Phase 5BQ](PHASE5BQ_ANJOMAN_PAIR_PREPARATION.md) prepares 14 source-backed candidate preference pairs for `SECURITY_REVIEW_GENERAL`, mapped to the `SECURITY_REVIEW` judgment family by [bounty #96](https://github.com/telegraphprotocol/bounties/issues/96) and the official [INTENTS.md](https://github.com/telegraphprotocol/bounties/blob/main/docs/INTENTS.md).

The packet is generated from pinned advisory and registry snapshots. It is **not uploaded**, not human-adjudicated, not eligible, and not used for network ranking. Its `source_kind: generated` provenance must not be relabelled. Bounty #96 asks for realistic questions, a believable wrong answer of comparable length, varied answers, and multiple contributors before the pool is used. The owner-only upload path requires an EIP-191 signature. No signature, wallet action, upload, or official submission was performed; these remain outside the authorized scope.

### RealVuln upstream result

FALSUM's [reproducibility issue #68](https://github.com/kolega-ai/Real-Vuln-Benchmark/issues/68) received a maintainer-confirmed resolution. Upstream [PR #70](https://github.com/kolega-ai/Real-Vuln-Benchmark/pull/70) merged as `d376b96b64337de19e01e17a51ddb2f54814f432`; the maintainer reports deployment in [RealVuln v4.0.0](https://realvuln.com/v/4.0.0/dashboard.html). The maintainer reports 5,609 saved reports replayed, 90 additional true positives, zero per-report true positives lost, and identical assignments when both input lists are reversed. These are upstream-reported results, not an independent FALSUM rerun.

FALSUM's earlier 51-report comparison tied the original published F3 on all 51 reports and improved on the sorted-greedy control in only one case. This is a reproducibility finding, not improved scanner detection, and not Telegraph adoption.

## Next actionable handoff

1. Verify [PR #125](https://github.com/Iniwura/falsum/pull/125), the new pinned ResQ Solana Cargo.lock compatibility harness, against its exact head. It freezes a real application lockfile and two RustSec advisories before candidate implementation; do not count the expected replay until hosted CI completes.
2. Wait for the 36-run matrix on PR #122's exact head `9ef7b0e8dddf05dc04b1891678ca73233294d586`, then review the complete 40-file diff before considering a merge.
3. Seek a genuinely independent, same-Intent review or source-disjoint adjudicated response set. If authentic paired reference answers are unavailable, keep the reproducible ingestion harness honest; do not manufacture gold or label the six PR Guard captures as blind held-out cases.
4. Keep the Anjoman packet in generated/unsubmitted state until the owner separately authorizes the signature and upload. No wallet/signature action is part of this sprint.

Re-score only when evidence materially changes one of the five fixed internal categories. Do not record a demo below 90/100. If the threshold is eventually met, recording capability must be confirmed before promising a video; otherwise provide a runnable 2–5 minute demo plan.
