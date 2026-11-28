# FALSUM pre-demo scorecard — 28 November 2026

**Status: below the required pre-demo threshold. No demo or official submission is authorized.**

## Fixed internal sprint score

The five-category internal sprint rubric remains unchanged. This is a project-readiness assessment, not Telegraph's official score.

| Internal criterion | Score |
| --- | ---: |
| Technical quality | 19/20 |
| Evaluation coverage and originality | 17/20 |
| Measured improvement | 13/20 |
| Evidence and reproducibility | 18/20 |
| Ecosystem impact and adoption | 11/20 |
| **Total** | **78/100** |

**Required pre-demo threshold: 90/100. Gap: 12 points.**

No score increase is recorded. The RealVuln maintainer's adoption of the order-invariance correction is genuine external benchmark impact, but it does not establish FALSUM's Telegraph material acceptance, a Solana application integration adopted by its maintainer, or Telegraph network usage. It does not change the fixed internal score.

## Official Season II rules — separate from the internal score

The [official rules page](https://hackathon.telegraphprotocol.com/rules) defines the Evaluators track separately from Apps & Agents. The repository's [Evaluators rubric extraction note](H2_EVALUATORS_RUBRIC_2026-11-27.md) records a track-specific client-bundle extraction and hash, but explicitly says that extraction was not independently re-fetched and re-hashed during this sprint. The visible rules page's server-rendered summary shows Apps & Agents weights while the Evaluators selector is client-rendered. Therefore the track-specific weights remain **provisional** here.

**No official organizer score is available or assigned.** Do not use the provisional extraction, the historical 96/100 readiness mapping, or the 84/100 judge-style audit to alter the five fixed internal categories. The official deadline is **1 December 2026, 23:59 UTC**.

## Latest verified repository state

Main is at [`78beff3789e629b9e1556dfce59f92f4b630564f`](https://github.com/Iniwura/falsum/commit/78beff3789e629b9e1556dfce59f92f4b630564f). This includes the scorecard handoff from [PR #124](https://github.com/Iniwura/falsum/pull/124) and the Phase5BN reproducibility fix from [PR #127](https://github.com/Iniwura/falsum/pull/127).

### Phase 5BN corrected independent holdout replay

[PR #127](https://github.com/Iniwura/falsum/pull/127) merged after its seven hosted workflow runs passed. The [Phase5BN workflow](https://github.com/Iniwura/falsum/actions/runs/46116935498) passed the Python 3.11–3.13 matrix; the 3.13 job ran 10 focused tests, replayed the live registry inputs and reproduced the frozen 24-case result:

- External resolver: **24/24**.
- FALSUM: **22/24**.
- Leakage audit: **no label leakage detected**.
- The two candidate misses remain negative results; no improvement is claimed.

The fix preserves freeze-time registry metadata SHA-256 values as provenance while replaying against mutable PyPI/npm indexes by checking the exact already-frozen version keys and package identity. It never selects new versions or changes labels. The committed cases, balance, policies, leakage audit and answer-surface audit remain identical to the frozen result.

This is a reproducibility correction, not a new accuracy gain. The external resolver is a version-semantics baseline, not human AppSec gold or an independent evaluator adapter.

### Phase 5BP public-provider answer/action audit

[PR #122](https://github.com/Iniwura/falsum/pull/122) remains open at head [`0c2899bccfa4c2565971c557bc72d48bb670460b`](https://github.com/Iniwura/falsum/commit/0c2899bccfa4c2565971c557bc72d48bb670460b), after [PR #123](https://github.com/Iniwura/falsum/pull/123) and the Phase5BN branch sync [PR #126](https://github.com/Iniwura/falsum/pull/126) were merged into its feature branch. The new hosted matrix for this exact head has started but is not yet complete. Do not merge PR #122 until every required check finishes and the full 43-file diff is reviewed.

The Phase5BP study uses six immutable public PR Guard response blobs from one pinned commit: three structured and three free-text responses. The recorded result remains 18/24 source-bound integrity checks, two fully supported structured actions, and four review holds. Its reference oracle is a narrow source-derived pattern check (SQL concatenation, shell construction and dynamic execution), not human AppSec gold, a blind source-disjoint holdout, or a general vulnerability detector. It does not establish provider accuracy or a Telegraph ranking change.

### Phase 5BU real Solana application compatibility

[PR #125](https://github.com/Iniwura/falsum/pull/125) is still open on its child branch at head [`84334e2c4f240e5ec61fd7a83237b48fcba562c5`](https://github.com/Iniwura/falsum/commit/84334e2c4f240e5ec61fd7a83237b48fcba562c5). Its eight hosted workflows passed. The [Phase5BU CI run](https://github.com/Iniwura/falsum/actions/runs/46115849700) verified a pinned ResQ Programs Anchor workspace and 235 KB Cargo.lock, then checked locked `anchor-lang 1.0.0-rc.4` against two pinned RustSec advisories.

The [machine-readable artifact](https://github.com/Iniwura/falsum/actions/runs/46115849700/artifacts/15250699975) reports:

| Measure | Result |
| --- | ---: |
| Applications | 1 |
| Locked package versions | 1 |
| Package/advisory pairs | 2 |
| FALSUM coverage / abstentions | 2 / 0 |
| Agreement with independent `semver@7.8.6` reference | 2/2 |
| False acceptances / rejections vs that reference | 0 / 0 |
| Citation-only false applicables | 2 |

This is a read-only lockfile compatibility result. It is **not** a full Cargo.lock audit, Solana program-source analysis, human AppSec gold, ResQ maintainer review, independent app adoption, security clearance, or Telegraph network improvement. The artifact is owner-run CI, not independent reproduction.

## Telegraph material and ecosystem boundary

The historical [SECURITY_REVIEW bounty #96](https://github.com/telegraphprotocol/bounties/issues/96) is closed and points contributors to the current mission issues, including [Model Economy #198](https://github.com/telegraphprotocol/bounties/issues/198) and [Web3 Native & DeFi #202](https://github.com/telegraphprotocol/bounties/issues/202).

The official [Contribute Evaluation Data guide](https://anjoman.ai/docs/scoring/contribute-evaluation-data) states that:
- judgment questions enter the pool only after at least **five different contributors** have material;
- the pool is split into a hidden testing half and a ranking half;
- only rows in an active eligible snapshot are used;
- `source_kind: llm`, `synthetic`, `generated` or `model` is always classified as unverified, even when a URL is present.

FALSUM's evidence file records 20 rows as UI-visible eligible, but it also explicitly records that independent API verification of those user-owned rows and maintainer approval are null/false. Do not claim those rows were used for ranking. The 14 Phase5BQ rows remain generated, unsubmitted candidates and are not eligible material.

A public MIT-licensed external Evaluators project, [Ritapossible/AdversarialEval](https://github.com/Ritapossible/AdversarialEval), publishes a 40-pair test set from two independent authors and a reported 31/40 (77.5%) adapter result. It is a useful candidate external corpus, not a FALSUM result. An initial source-ID comparison found two overlapping identifiers (CVE-2025-27152 and GHSA-JR5F-V2JV-69X6, the same advisory family) in FALSUM's publicly visible corpus, plus eight candidate rows across six other GHSA sources that are disjoint from those public sources. The private content of FALSUM's historical 20 eligible rows is not available in the repository, so complete source-disjointness cannot be proven. Do not call this a blind held-out set or claim FALSUM accuracy from it. Next: pin the external repo commit and file blob, build a reproducible ingestion/overlap harness, and keep the private-overlap limitation explicit before any candidate evaluation.

A single attempt to post the ResQ compatibility result and request reproduction on mission #202 was blocked by GitHub's integration permission: **403, Resource not accessible by integration**. No comment was published. Do not retry through the same permission boundary. The PR, CI artifact and this handoff remain public evidence; an authorized human maintainer or reviewer is still needed for independent reproduction.

## Next actionable handoff

1. **Finish PR #122 at its exact current head.** Monitor the queued 36-workflow matrix for `0c2899bccfa4c2565971c557bc72d48bb670460b`, review any failures, and inspect the complete diff before merge.
2. **Review PR #125** and decide whether the two-pair ResQ lockfile compatibility result is sufficient as a bounded integration or whether a real full-lockfile tool comparison is warranted. Do not claim app adoption.
3. **Build the external AdversarialEval ingestion/overlap harness** against its pinned MIT-licensed 40-pair corpus. Verify the published 31/40 baseline from its raw score file, report the 8 public-source-disjoint candidates separately, and explicitly mark overlap with private FALSUM material as unknown. Do not invent a FALSUM score or human gold.
4. **Seek independent reproduction only through an authorized channel.** The GitHub integration cannot post to Telegraph's mission repository; do not impersonate a maintainer or repeatedly retry the 403.
5. Keep Phase5BQ in generated/unsubmitted state. No wallet/signature action, material upload, official submission, payment, demo publication or external account change is authorized.

Re-score only when evidence materially changes one of the five fixed internal categories. Do not record a demo below 90/100. At the threshold, confirm recording capability; if unavailable, provide a runnable 2–5 minute walkthrough plan instead of claiming a video.
