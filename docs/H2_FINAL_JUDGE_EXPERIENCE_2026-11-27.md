# FALSUM — final judge experience

Start here: [final storyboard](H2_FINAL_DEMO_STORYBOARD_2026-11-27.md), then
run the two zero-credential commands in the [submission package](H2_FINAL_SUBMISSION_PACKAGE_2026-11-27.md).

## Current measurement result

The earlier Phase 5BM result remains preserved as historical evidence, but it
is not the current certification basis. The corrected [Phase 5BN independent
holdout](PHASE5BN_CORRECTED_INDEPENDENT_HOLDOUT.md) removes FALSUM-dependent
layout selection, freezes labels from `packaging==26.4` and `semver@7.8.6`
before candidate execution, checks actual registry version existence, tests
index/position/token leakage with computed permutation tests, and evaluates
target-specific competing security answers. It records 22/24 FALSUM decisions
against 24/24 for the external version-resolution reference. The two FALSUM
unknowns are preserved; this is not human AppSec gold or a perfect-score claim.

## Ecosystem-native semantic regression

Phase 5BO is a separate improvement, not a rewrite of Phase5BN. It resolves
both observed abstentions using PEP 440 and strict SemVer semantics, supports
disjoint affected intervals, fails closed on unsupported ranges, and uses
committed raw PyPI/npm registry snapshots with SHA-256 sidecars. Its 14-case
offline audit includes 12 additional unseen cases and evaluates structured
candidate claims/actions rather than label-derived answer tokens. It records
14/14 candidate decisions and 14/14 structured claim/action selections. The
option prose is display-only, not natural-language answer scoring. No score
points are added automatically for this regression suite.

## What the judge should learn in three minutes

1. FALSUM is **Evaluator material** for `SECURITY_REVIEW_GENERAL`, which
   official bounty #96 and `INTENTS.md` map to the `SECURITY_REVIEW` judgment
   family; it is not a claimed registered scoring adapter or security-clearance
   service.
2. A genuinely fresh public provider capture is bound to its exact target and
   immutable advisory-source bytes. Unsupported identity or version evidence
   becomes an explicit abstention.
3. The fresh holdout produced 66 Django references and no lodash references;
   27 Django rows were source-applicable and 39 were fail-closed
   unknown/insufficient. A separately implemented competent baseline agreed on
   every row.
4. The earlier frozen roster has a bounded, repeatable measurement: an
   accept-all policy displayed 12 references including 2 known inapplicable
   instances; the reviewed gate displayed 10 and suppressed both.
5. The cross-source audit adds fair discriminative comparisons: 3/3 explicit
   missing-evidence clean candidates rejected, 2/2 version-inapplicable
   references suppressed, 8 count-only vulnerable-label PASS outcomes removed,
   and 66/66 agreement with the competent baseline; it preserves the tie with
   verdict-only.
6. The historical Phase 5BM balanced holdout remains available for audit, but
   the corrected Phase 5BN holdout is the current result: 24 registry-backed
   cases, 22/24 FALSUM, 24/24 external resolver, 48 distinct target-specific
   answers, and computed index/position/token leakage checks with no detected
   signal at the predeclared threshold.
7. The ecosystem-native semantic regression resolves the two legacy-version
   abstentions and adds 12 unseen snapshot-backed cases: 14/14 candidate
   decisions and 14/14 structured claim/action selections, without
   reference-label-to-token mappings. Its option prose is display-only; this
   is not natural-language answer scoring.
8. Two distinct official mission workflows have repeatable supporting tests:
   Model Economy supply-chain verification and Web3 Native and DeFi
   security/bug-bounty proof. They are not claimed as completed missions or
   independent app consumption.
9. The project is honest about what remains: no independent customer adoption,
   no human AppSec gold, no current paid transaction in this sprint, no
   ranking uplift, and no submitted entry.

The correct Evaluators rubric is [40/15/10/10/5/20 with a 28/40 measurement
minimum](H2_EVALUATORS_RUBRIC_2026-11-27.md), not the Apps & Agents-shaped
35/25/10/5/5/20 table.

## Evidence order

| Order | Open | Why |
| ---: | --- | --- |
| 1 | [Strict score](H2_FINAL_STRICT_SCORE_2026-11-27.md) | Immediate scope and gaps |
| 2 | [Fresh holdout protocol](../data/phase5bj-fresh-provider-holdout-protocol.json) | Proves selection was frozen before observation |
| 3 | [Fresh holdout implementation](../src/falsum/phase5bj_fresh_provider_holdout.py) | Shows binding, interval policy and independent baseline |
| 4 | [Fresh holdout tests](../tests/test_phase5bj_fresh_provider_holdout.py) | Adversarial boundary, target and leakage checks |
| 5 | [Hosted Phase 5BI CI](https://github.com/Iniwura/falsum/actions/runs/45918441661) | Prior bounded measurement replay |
| 6 | [Final storyboard](H2_FINAL_DEMO_STORYBOARD_2026-11-27.md) | Safe presentation sequence |
| 7 | [Official rules](https://hackathon.telegraphprotocol.com/rules) | Eligibility and submission bar |
| 8 | [Mission/workflow matrix](../data/phase5bk-evaluator-mission-workflow-matrix.json) | Two repeatable supporting workflows, no inflated delivery claim |
| 9 | [Current Anjoman status](../evidence/phase5bk-2026-11-27-anjoman-status.json) | 20/20 current Eligible rows for the operator-reported Privy address |
| 10 | [Cross-source measurement audit](../data/phase5bl-cross-source-measurement-discrimination.json) | Fair contrasts, baseline tie, and preserved negative findings |
| 11 | [Independent balanced holdout](../data/phase5bm-independent-balanced-holdout-result.json) | 24 paired cases, balanced order, shortcut audit, and citation-only contrast |
| 12 | [Corrected independent holdout](PHASE5BN_CORRECTED_INDEPENDENT_HOLDOUT.md) | Independent labels, external resolver, version existence, meaningful answers, and computed leakage audit |
| 13 | [Ecosystem-native semantic audit](PHASE5BO_ECOSYSTEM_SEMANTICS.md) | PEP 440/SemVer semantics, offline registry snapshots, disjoint/unsupported ranges, and structured claim/action selection |
| 14 | [Final release-gate record](../evidence/final-release-gate-check-2026-11-27.json) | Reviewer command smoke checks, public-route accessibility checks, resolved local links, and owner-controlled blockers |
| 15 | [Hosted Playwright and axe inspection](https://github.com/Iniwura/falsum/actions/runs/45978583401) | Four desktop/mobile screenshots, zero automated WCAG axe violations, and public-route structural checks |

## Claims a judge can safely repeat

- “FALSUM provides source-authenticated, version-aware evaluation material.”
- “The fresh public holdout was selected before response inspection and was
  replayed against an independent version-aware baseline.”
- “FALSUM and the baseline agreed; unknown cases were not forced positive.”
- “The corrected 24-case study records 22/24 FALSUM versus 24/24 for an external version-resolution reference, with two explicit unknown disagreements.”
- “The prior measured effect is bounded to a frozen reviewed-reference roster.”
- “The cross-source audit shows two safety-relevant contrasts against weaker
  policies, ties a competent baseline, and preserves the verdict-only tie.”
- “FALSUM supplies repeatable supporting tests for two official mission
  workflows; it does not claim completed mission delivery or independent app
  consumption.”
- “No customer adoption, expert gold, current paid Telegraph execution, or
  security clearance is claimed.”

## Claims not to repeat

- “FALSUM is an official registered evaluator.”
- “The fresh holdout proves security accuracy, recall, or production safety.”
- “The historical Phase5BM 24/24 result is the current corrected score.”
- “Paid/charged fields prove settlement or independent customer demand.”
- “The old model experiment proves FALSUM improved ranking.”
- “The ACP Sandbox route is complete.”
- “The family mapping proves maintainer acceptance or live adapter registration.”
