# FALSUM pre-demo scorecard — 28 November 2026

**Status: below the required pre-demo threshold. No demo or official submission is authorized.**

## Fixed internal sprint score

The five-category internal rubric remains unchanged. This is a project-readiness assessment, not Telegraph's official score.

| Internal criterion | Score |
| --- | ---: |
| Technical quality | 19/20 |
| Evaluation coverage and originality | 17/20 |
| Measured improvement | 13/20 |
| Evidence and reproducibility | 18/20 |
| Ecosystem impact and adoption | 11/20 |
| **Total** | **78/100** |

**Required pre-demo threshold: 90/100. Gap: 12 points.**

No score increase is recorded in this iteration. The RealVuln maintainer's adoption of the order-invariance correction is genuine external benchmark impact, but it does not establish Telegraph evaluator-material acceptance, Solana application adoption, or Telegraph network usage. The ResQ integration adds real Solana application compatibility, but its four measured cases are all positive, its negative controls are previously used calibration cases, and no ResQ maintainer adoption or independent reproduction is verified. The Phase 5CA corpus is authenticated but fails its frozen data-integrity gate and produced no candidate comparison. These results do not justify changing the fixed score.

Older 84/100 and 96/100 figures in historical judge-pack documents are separate historical internal assessments. They are not organizer scores and do not replace this current fixed 78/100 sprint score.

## Official Season II Evaluators criteria — separate from the internal score

The [official rules page](https://hackathon.telegraphprotocol.com/rules) defines Evaluators as an evaluation adapter, evaluation material, or both. The repository's [Evaluators rubric extraction note](H2_EVALUATORS_RUBRIC_2026-11-27.md) records the track-specific criteria from the official client bundle:

| Official Evaluators criterion | Weight |
| --- | ---: |
| Measurement validity, quality discrimination, and baseline evidence | 40 |
| Integrity and robustness | 15 |
| Reproducibility and protocol compatibility | 10 |
| Useful evaluation coverage and demonstrated improvement | 10 |
| Documentation and integration clarity | 5 |
| Organic growth, education, and developer activation | 20 |
| **Total** | **100** |

The recorded technical minimum is **28/40** for measurement validity. The extraction note includes the bundle URL and SHA-256; the bundle was not independently re-fetched and re-hashed during this run. The visible rules page defaults to an Apps & Agents rendering, so do not substitute its 35/25/10/5/5/20 weights for the Evaluators-specific table.

**No official organizer score is available or assigned here.** The official rules' common Section 5 bar still applies: a working Evaluator contribution, real Telegraph integration, repeatable results, safe handling, accurate claims, and the required bounties-repository star. Evaluator delivery selection prioritizes distinct commercial missions, distinct H2 app workflows, independently verified missing mission-critical Intent needs, and combined technical quality. Evaluator excellence ties prefer proven measurement improvement or valuable new coverage, then validity.

The official [bounty #96](https://github.com/telegraphprotocol/bounties/issues/96) and [INTENTS.md](https://github.com/telegraphprotocol/bounties/blob/main/docs/INTENTS.md) map SECURITY_REVIEW_GENERAL to the SECURITY_REVIEW judgment family. The recorded Anjoman status of 20/20 eligible rows is for the operator-reported address only. The five-contributor pool gate, active snapshot use, maintainer acceptance, wallet ownership, and live adapter registration remain unverified.

## New evidence since the 78/100 baseline

### ResQ Solana application compatibility

[PR #135](https://github.com/Iniwura/falsum/pull/135) merged as [commit d7c072ce155b33fcb906df55d2025f9efc167906](https://github.com/Iniwura/falsum/commit/d7c072ce155b33fcb906df55d2025f9efc167906). Its [exact-head hosted replay](https://github.com/Iniwura/falsum/actions/runs/46129715492) passed. It replays four published RustSec package/advisory pairs from a pinned ResQ Programs lockfile: FALSUM agrees with cargo-audit and semver 7.8.6 on 4/4 positive cases. There are no new negative cases in this slice. The repository is read-only to the connected integration; no ResQ maintainer adoption or independent reproduction is claimed.

### RealVuln upstream correction

FALSUM's [issue #68](https://github.com/kolega-ai/Real-Vuln-Benchmark/issues/68) is referenced by merged [upstream PR #70](https://github.com/kolega-ai/Real-Vuln-Benchmark/pull/70). The maintainer reports that v4.0.0 replayed 5,609 saved reports, recovered 90 true positives with none lost in per-report comparison, and produced identical assignments when both input lists were reversed. These are upstream-reported results, not an independent FALSUM rerun. This is external benchmark impact, not Telegraph network improvement or FALSUM adoption.

### Phase 5CA VADER corpus freeze

[Phase 5CA workflow](https://github.com/Iniwura/falsum/actions/runs/46136480080) authenticated the pinned AfterQuery/VADER source and published [the aggregate manifest and reserved roster](https://github.com/Iniwura/falsum/actions/runs/46136480080/artifacts/15260111211). It found 177 VADER rows, 173 valid graded rows, 60 malformed graded records, 159 metadata-valid matched cases, 12 source-identity mismatches, two invalid source-metadata records, four source-only IDs, and 43 reserved holdout cases across 39 repositories. The frozen readiness gate failed. No model inference, candidate training, or baseline comparison was performed. Full details and exact blockers are in [Phase 5CA corpus results](PHASE5CA_VADER_CORPUS.md).

### Phase 5CB VADER workbook cross-format audit

[PR #137](https://github.com/Iniwura/falsum/pull/137) authenticates the second immutable file, `graded.xlsx`, and compares it with the pinned CSVs. The exact workbook SHA-256 and both CSV Git blob identities were checked in [hosted run 46138606549](https://github.com/Iniwura/falsum/actions/runs/46138606549); the aggregate-only [manifest and roster artifact](https://github.com/Iniwura/falsum/actions/runs/46138606549/artifacts/15260840970) are public.

- Workbook: 174 physical data rows, 172 valid, 2 malformed (both lack a parseable CWE).
- 0 duplicate IDs, 0 incomplete six-answer records, 0 invalid score rows.
- 160 workbook/source metadata matches; 12 metadata mismatches; 5 source-only IDs.
- Public-inventory holdout: 43 cases across 39 repositories.
- XLSX/CSV common IDs: 171; all 171 common rows are byte-normalized identical. There is still 1 workbook-only and 2 CSV-only IDs.
- Candidate readiness remains **false** because of malformed workbook rows, source metadata mismatches, and cross-format unmatched IDs requiring source-owner resolution.

The workbook has fewer malformed rows than the CSV, but it is not a clean corrected source. No row was repaired or promoted to gold. No candidate inference or baseline comparison ran. The Phase 5CB result does not raise the 78/100 score. The parser/test failures found on the first PR head were fixed with a standard-library parser helper and dependency-free OOXML fixtures; the full PR workflow rerun is being checked before merge.

## Next actionable handoff

1. Keep the VADER candidate benchmark blocked until the dataset owner resolves the Phase 5CA/5CB CSV and workbook integrity differences, or a separately frozen authentic paired corpus is found. Do not repair observed records or change frozen criteria after seeing results.
2. Build the next benchmark only on source-disjoint cases with defensible reference answers. Compare verdict-only, context-aware evidence checking, and FALSUM on identical inputs; report false acceptance, false rejection, coverage, abstention, and exact sample sizes.
3. Pursue actual Telegraph material-pool activation only through the authorized Anjoman flow. Do not claim the 20 eligible rows are used by an active five-contributor pool.
4. Seek independent ResQ or other Solana-app reproduction only through an authorized genuine developer channel. Do not retry blocked write permissions or describe owner-run CI as adoption.
5. Re-score only when evidence materially changes one of the five fixed internal categories. Keep the 78/100 internal score unchanged; no official organizer score is assigned.

The Season II deadline is **1 December 2026, 23:59 UTC**. No demo below 90/100. At the threshold, record an honest 2–5 minute walkthrough only if recording capability is available; otherwise provide a runnable demo plan.
