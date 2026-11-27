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

## Strict result: **82 / 100**

The 28/40 measurement minimum is met exactly. That is a qualification
threshold, not evidence that the entry is first. Every awarded point below is
tied to a verified artifact or public record; no future action is counted.

| Criterion | Awarded | Evidence-backed point allocation | Withheld |
| --- | ---: | --- | ---: |
| Measurement validity, quality discrimination, and baseline evidence | **28/40** | 10: exact target binding, immutable source identity, interval semantics and fail-closed decisions; 8: prior bounded accept-all comparison removed 2 known inapplicable displays from 12; 6: separately implemented version-aware baseline agreed on all 66 fresh rows; 4: fresh public holdout supplied 38 canonical source records and appropriate unknown/insufficient outcomes. | 12: no independent AppSec gold, no blind model benchmark, no full recall/completeness, and no demonstrated ranking change. |
| Integrity and robustness | **14/15** | 6: response-content/provenance binding and wrong-target rejection; 5: adversarial regression coverage for tampering, unsupported intervals, duplicates and caller-supplied adoption; 3: safe signer/credential/receipt boundaries and accurate non-clearance claims. | 1: current official Intent/pipeline compatibility is not yet externally confirmed. |
| Reproducibility and protocol compatibility | **9/10** | 4: public CLI, frozen protocols and write-once evidence; 3: hosted Python 3.11–3.13 contracts plus live public replay; 2: public-safe artifacts and exact run instructions with network/cost/limit disclosure. | 1: no registered/current evaluator adapter or independently confirmed `SECURITY_REVIEW_GENERAL` → `SECURITY_REVIEW` compatibility. |
| Useful evaluation coverage and demonstrated improvement | **8/10** | 4: multi-ecosystem reference gating, Anchor/Rust source/runtime coverage, and fresh Django coverage; 2: bounded 2/12 known false-positive reduction; 2: two official mission workflows now have repeatable supporting tests in the [Phase 5BK matrix](../data/phase5bk-evaluator-mission-workflow-matrix.json). | 2: no finalized ranking change or independent application consumption. |
| Documentation and integration clarity | **5/5** | 2: clear judge route and storyboard; 2: beginner commands, evidence links, network/cost/limits and troubleshooting; 1: explicit separation of evaluation material, historical Telegraph evidence, test/internal activity and adoption. | 0 |
| Organic growth, education, and developer activation | **18/20** | 5: public explanation, technical walkthroughs and honest limitations; 5: reproducible no-key route with examples and next steps; 5: four separate competition-period update dates plus public technical sharing and follow-up; 3: a concrete no-key invitation and two genuine external maintainer reviews/actions. | 2: no independently verified repeat integration/contribution beyond those two maintainer reviews. |
| **Total** | **82/100** | 28/40 measurement minimum passed; total exceeds the published 70 threshold, subject to entry eligibility and official review. | **18** |

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

### Current Anjoman status

The fresh [read-only status evidence](../evidence/phase5bk-2026-11-27-anjoman-status.json)
records 20 total / 20 Eligible rows for the operator-reported Privy address
and 0/0 for the distinct historical bounty-comment address. It does not prove
cryptographic wallet ownership, maintainer acceptance, evaluator registration,
or independent label quality. The 20 rows remain eligible material evidence,
not an award or adapter registration.

### Growth reassessment

[H2_VERIFIED_GROWTH_EVIDENCE.md](H2_VERIFIED_GROWTH_EVIDENCE.md) records six
public evidence links across four separate update dates (Nov 2, Nov 17, Nov
21, Nov 24) and two genuine external maintainer reviews. The assessment counts
those facts under the official four growth criteria and does not count likes,
followers, self-controlled status, or unverified adoption.

## Award outlook

### Evaluators excellence award

FALSUM is a legitimate contender if the entry passes the common eligibility
bar and the historical/current Intent mapping is accepted. Its strongest
excellence differentiators are source-integrity discipline, a fresh public
holdout, explicit abstention, and valuable multi-ecosystem coverage. It is not
currently favored for first place because measurement validity only clears the
minimum, the baseline agrees rather than being beaten, no independent AppSec
gold or finalized ranking change exists, and no registered adapter is shown.

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

1. **Resolve Intent compatibility.** Obtain authoritative confirmation that
   the historical `SECURITY_REVIEW_GENERAL` material is valid for the current
   official `SECURITY_REVIEW` Intent and document the exact adapter/material
   schema expected by the H2 pipeline. This is the highest internal technical
   risk.
2. **Raise measurement validity above the minimum.** Add independently
   adjudicated reference answers or an accepted external review set, then run
   a sealed Provider-discrimination comparison under the same Intent. More
   self-authored fixtures would not solve this gap.
3. **Prove one real workflow impact.** An independent reviewer or app should
   rerun the Model Economy or Web3 workflow and inspect the evaluation result
   and Telegraph evidence. This cannot honestly be simulated as customer use.
4. **Keep the material version operationally consumable.** Preserve the
   versioned source manifest, input/output schema, deterministic commands and
   CI artifact as the reviewer-accessible replacement if a network adapter is
   not registered.

Items 1–3 require an external platform decision or independent action; ACP is
intentionally suspended and is not a dependency for this Evaluators entry.
