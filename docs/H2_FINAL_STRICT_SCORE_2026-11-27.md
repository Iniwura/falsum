# FALSUM — strict Evaluators assessment (27 November 2026)

**Status: internal, conservative, not an organizer score and not submitted.**
This assessment uses the current Evaluators-specific rubric, not the Apps &
Agents rubric. The official source and extracted criteria are recorded in
[H2_EVALUATORS_RUBRIC_2026-11-27.md](H2_EVALUATORS_RUBRIC_2026-11-27.md).

## Correct rubric

| Evaluators criterion | Points | Technical minimum |
| --- | ---: | ---: |
| Measurement validity, quality discrimination, and baseline evidence | 40 | **28/40** |
| Integrity and robustness | 15 | — |
| Reproducibility and protocol compatibility | 10 | — |
| Useful evaluation coverage and demonstrated improvement | 10 | — |
| Documentation and integration clarity | 5 | — |
| Organic growth, education, and developer activation | 20 | — |
| **Total** | **100** | **70/100 overall published threshold** |

## Strict result: **90 / 100**

The 34/40 measurement result clears the 28/40 technical minimum. That is a qualification
threshold, not evidence that the entry is first. Every awarded point below is
tied to a verified artifact or public record; no future action is counted.

| Criterion | Awarded | Evidence-backed point allocation | Withheld |
| --- | ---: | --- | ---: |
| Measurement validity, quality discrimination, and baseline evidence | **34/40** | 10: exact target binding, immutable source identity, interval semantics and fail-closed decisions; 8: prior bounded accept-all comparison removed 2 known inapplicable displays from 12; 6: separately implemented version-aware baseline agreed on all 66 fresh rows; 4: fresh public holdout supplied 38 canonical source records and appropriate unknown/insufficient outcomes; 3: the new Phase 5BL cross-source audit demonstrates 3/3 missing-evidence rejection against verdict-only and 0/2 version-inapplicable display against accept-all; 3: fair 129-case external policy comparison removes 8 count-only vulnerable-label PASS outcomes while preserving the verdict-only tie and audited-control trade-off. | 6: no independent AppSec gold, no blind model benchmark, no full recall/completeness, no advantage over verdict-only, and no demonstrated ranking change. |
| Integrity and robustness | **15/15** | 6: response-content/provenance binding and wrong-target rejection; 5: adversarial regression coverage for tampering, unsupported intervals, duplicates and caller-supplied adoption; 3: safe signer/credential/receipt boundaries and accurate non-clearance claims; 1: authoritative `SECURITY_REVIEW_GENERAL` → `SECURITY_REVIEW` family mapping is source-pinned without conflating acceptance or registration. | 0 |
| Reproducibility and protocol compatibility | **10/10** | 4: public CLI, frozen protocols and write-once evidence; 3: hosted Python 3.11–3.13 contracts plus live public replay; 2: public-safe artifacts and exact run instructions with network/cost/limit disclosure; 1: official bounty and `INTENTS.md` mapping confirms the child Intent, response schema and family-level adapter route. | 0; a live registered adapter is not required for this evaluation-material contribution and is not claimed. |
| Useful evaluation coverage and demonstrated improvement | **8/10** | 4: multi-ecosystem reference gating, Anchor/Rust source/runtime coverage, and fresh Django coverage; 2: bounded 2/12 known false-positive reduction; 2: two official mission workflows now have repeatable supporting tests in the [Phase 5BK matrix](../data/phase5bk-evaluator-mission-workflow-matrix.json). | 2: no finalized ranking change or independent application consumption. |
| Documentation and integration clarity | **5/5** | 2: clear judge route and storyboard; 2: beginner commands, evidence links, network/cost/limits and troubleshooting; 1: explicit separation of evaluation material, historical Telegraph evidence, test/internal activity and adoption. | 0 |
| Organic growth, education, and developer activation | **18/20** | 5: public explanation, technical walkthroughs and honest limitations; 5: reproducible no-key route with examples and next steps; 5: four separate competition-period update dates plus public technical sharing and follow-up; 3: a concrete no-key invitation and two genuine external maintainer reviews/actions. | 2: no independently verified repeat integration/contribution beyond those two maintainer reviews. |
| **Total** | **90/100** | 34/40 measurement result and 28/40 technical minimum passed; total exceeds the published 70 threshold, subject to entry eligibility and official review. | **10** |

## Current evidence facts

### Fresh unseen-provider holdout

The [Phase 5BJ protocol](../data/phase5bj-fresh-provider-holdout-protocol.json)
was frozen before response inspection. Hosted replay [45918441740](https://github.com/Iniwura/falsum/actions/runs/45918441740)
verified:

- Django 3.2.0: 66 reported references, 38 canonical advisory records, 27
  applicable, 39 unknown/insufficient and fail-closed.
- lodash 4.18.1: zero reported advisories.
- FALSUM and the independent version-aware baseline: 66/66 agreement.

This is new coverage and validity evidence, not a superiority, recall,
security-clearance, or customer-adoption claim.

### Cross-source discriminative measurement

The new [Phase 5BL audit](../data/phase5bl-cross-source-measurement-discrimination.json)
is a repeatable cross-source analysis with its own adversarial contract tests;
the [hosted Python 3.11–3.13 replay](https://github.com/Iniwura/falsum/actions/runs/45942955107)
passed on measurement commit `b8db95d`.
It does not relabel the underlying studies. It records:

- 3/3 explicit missing-evidence clean candidates rejected by FALSUM versus
  3/3 accepted by verdict-only and 2/3 accepted by count-plus-verdict;
- 0/2 independently reviewed version-inapplicable references displayed by
  FALSUM versus 2/2 displayed by accept-all;
- on the complete 129-case published application population, 0 vulnerable-label
  PASS outcomes for FALSUM versus 8 for count-only, while tying verdict-only;
- 66/66 agreement with the separately implemented competent baseline on the
  fresh holdout.

This raises measurement validity through discriminative, fair comparisons,
not through a superiority claim. The report keeps independent human AppSec
gold at zero and preserves the verdict-only tie.

### Current Anjoman status

The fresh [read-only status evidence](../evidence/phase5bk-2026-11-27-anjoman-status.json)
records 20 total / 20 Eligible rows for the operator-reported Privy address
and 0/0 for the distinct historical bounty-comment address. Under the
authoritative [bounty #96](https://github.com/telegraphprotocol/bounties/issues/96)
and [INTENTS.md mapping](https://github.com/telegraphprotocol/bounties/blob/main/docs/INTENTS.md),
that satisfies the individual contribution gate: an individual's part counts
once their rows are `eligible`. It does not prove the five-contributor pool
gate, active-snapshot use, cryptographic wallet ownership, maintainer
acceptance, evaluator registration, or independent label quality.

### Growth reassessment

[H2_VERIFIED_GROWTH_EVIDENCE.md](H2_VERIFIED_GROWTH_EVIDENCE.md) records six
public evidence links across four separate update dates (Nov 2, Nov 17, Nov
21, Nov 24) and two genuine external maintainer reviews. The assessment counts
those facts under the official four growth criteria and does not count likes,
followers, self-controlled status, or unverified adoption.

## Award outlook

### Evaluators excellence award

FALSUM is now a credible 90-point internal contender if the entry passes the
common eligibility bar. Its strongest excellence differentiators are
source-integrity discipline, two source-bound safety contrasts, a fresh public
holdout, explicit abstention, and valuable multi-ecosystem coverage. It is not
guaranteed first place: the competent baseline ties, verdict-only remains a
tie, independent AppSec gold and finalized ranking change are absent, and no
registered adapter is claimed.

### Evaluators verified delivery award

The delivery case is stronger than the previous audit suggested: FALSUM now
documents two distinct official mission workflows with repeatable supporting
tests—Model Economy supply-chain verification and Web3 Native and DeFi
security/bug-bounty proof. The [matrix](../src/falsum/phase5bk_evaluator_mission_workflow_matrix.py)
is explicit that these are supporting tests, not completed missions or
independent app consumption. Delivery remains plausible but not secure: the
rules prioritize distinct mission/workflow impact and independent verification,
and FALSUM still lacks an external application rerun or accepted integration
test.

## Highest-value remaining technical gaps

1. **Obtain independent adjudication.** Add independently adjudicated
   reference answers or an accepted external review set, then run a sealed
   Provider-discrimination comparison under the same Intent. More self-authored
   fixtures would not solve this gap.
2. **Prove one real workflow impact.** An independent reviewer or app should
   rerun the Model Economy or Web3 workflow and inspect the evaluation result
   and Telegraph evidence. This cannot honestly be simulated as customer use.
3. **Keep the material version operationally consumable.** Preserve the
   versioned source manifest, input/output schema, deterministic commands and
   CI artifact as the reviewer-accessible replacement if a network adapter is
   not registered.

Items 1–2 require an external reviewer or independent action; ACP is
intentionally suspended and is not a dependency for this Evaluators entry.
