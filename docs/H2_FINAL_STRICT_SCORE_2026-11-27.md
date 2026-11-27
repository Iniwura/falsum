# FALSUM — strict final Evaluators score (27 November 2026)

**Status: internal, conservative, not an organizer score and not submitted.**
This score awards only evidence that is already public, reproducible, and
within the official Season II scope. It does not treat a self-authored label,
an owner-controlled action, a constructed fixture, a paid flag, or a planned
demo as independent adoption or expert validation.

Official reference: [Season II rules](https://hackathon.telegraphprotocol.com/rules),
especially the Evaluators definition, Section 5 entry bar, Section 6 rubric,
Section 7 delivery priorities, and Section 8 submission requirements.

## Score: **56 / 100**

| Rubric area | Awarded | Evidence that earns the points | Points withheld |
| --- | ---: | --- | --- |
| Technical quality and mainnet readiness | **30/35** | 8: authenticated public Git source/provider identities and response-integrity gates; 8: fail-closed handling, signer restrictions, and adversarial Phase 5B/5BG contracts; 6: repeatable CLI plus hosted multi-version CI; 5: valuable version-aware coverage across original upstream security regressions and the fresh Phase 5BJ holdout; 3: safe Telegraph-related material and explicit network/cost boundaries. Current proof includes [Phase 5BI hosted CI](https://github.com/Iniwura/falsum/actions/runs/45918441661), the [fresh holdout implementation](../src/falsum/phase5bj_fresh_provider_holdout.py), and the [Phase 5BJ protocol](../data/phase5bj-fresh-provider-holdout-protocol.json). | 5: no currently registered/independently operated network evaluator and no current production purchase in this sprint. |
| Commercial viability | **12/25** | 4: clear security-review buyer problem—avoid displaying version-inapplicable advisory evidence; 3: measured bounded result (prior 2/12 known false-positive reduction) plus fresh 27 applicable references; 3: sensible zero-cost reproduction path and explicit spending/safety limits; 2: usable public CLI/judge route for a future integration. | 13: no independently funded customer, retained usage, production SLA, or verified mission workflow. |
| Genuine independent adoption and retention | **0/10** | No point claimed. | No independent customer, external integration, repeat user, or funded demand is verified. |
| Telegraph integration and usage quality | **2/5** | 2: real Telegraph-related evaluation material, historical public contribution evidence, and explicit separation of production, test, internal, and unsupported claims in the [audit](H2_FINAL_COMPETITIVE_AUDIT_2026-11-27.md). | 3: no fresh paid Telegraph execution or current independently verified ranking/accounting result is being claimed; ACP is suspended. |
| Reproducibility, demo/tutorial, and verifiable proof | **4/5** | 2: public repository, deterministic commands, frozen protocols and adversarial tests; 1: hosted CI artifacts; 1: this judge route and [final storyboard](H2_FINAL_DEMO_STORYBOARD_2026-11-27.md). | 1: a final owner-approved 2–5 minute recording or equivalent reviewer-accessible presentation is not yet verified. |
| Organic growth, education, and developer activation | **8/20** | 3: public technical explanations and honest limitations; 3: beginner-run instructions, zero-credential source replay, costs and troubleshooting; 2: useful public technical milestones and review material. | 12: the required three dated external updates, external developer action, community activation, and attributable repeat contribution are not all independently verified. |
| **Total** | **56/100** | Every awarded point maps to the evidence above; no score is reserved for future work. | **44** |

## New holdout result

The Phase 5BJ protocol was frozen at Git blob
`0b51a6b645f38aaeb31ace53e6bbde146a2d3bf6` before either selected response
body was inspected. The selected public provider commit is
`99d2e3c93890a8fc083947bde4f21217516b7a5f`.

| Capture | Reported refs | Canonical source records | FALSUM applicable | Fail-closed unknown/insufficient | Baseline disagreement |
| --- | ---: | ---: | ---: | ---: | ---: |
| PyPI Django 3.2.0 | 66 | 38 | 27 | 39 | 0 |
| npm lodash 4.18.1 | 0 | 0 | 0 | 0 | 0 |
| **Total** | **66** | **38** | **27** | **39** | **0** |

The separate baseline uses exact target binding, numeric version comparison,
exclusive `fixed`, inclusive `last_affected`, and explicit abstention on
unsupported intervals. It agrees with FALSUM on all 66 rows. That is a
reproducibility and new-coverage result, not a new superiority claim. The
clean lodash response is a valid zero-reference observation, not proof of
security. The raw response, payment object, receipt, and token are excluded
from the evidence artifact.

## Official eligibility and material disposition

The rules allow an Evaluator entry to be an **evaluation adapter, evaluation
material, or both**. FALSUM should enter as evaluation material for
`SECURITY_REVIEW_GENERAL`, with the source-authenticated reference gate,
version-boundary checks, response-integrity controls, fresh holdout, and
reproducible tests as the contribution. It should not present the quarantined
model experiments as a released superior evaluator.

Eligible/public-safe material:

- Phase 5BI bounded measurement artifact and hosted CI.
- Phase 5BJ frozen fresh-provider holdout, source hashes, fail-closed decisions,
  and separate competent baseline.
- Original upstream source/test witnesses and public-safe Telegraph evidence.
- Adversarial tests for forged provenance, wrong target, unsupported interval,
  sensitive-field leakage, and boundary handling.
- The judge guide, final storyboard, and beginner run instructions.

Do not count as independent adoption or expert gold:

- constructed fixtures, self-authored classifications, or caller-supplied
  adoption labels;
- historical paid/HTTP-200 flags as settlement proof;
- the old model's negative results as a trained evaluator improvement;
- the historical Anjoman eligibility readback as maintainer acceptance;
- ACP preparation, Sandbox access, or a self-controlled buyer test.

## Gaps not realistically solvable internally

1. An independent developer or customer must perform a real reproduction,
   integration, or repeat use. The repository cannot create genuine external
   adoption without becoming self-dealing.
2. An independent AppSec adjudication set or accepted evaluator registration
   requires an external reviewer/platform decision; more self-authored cases
   would not cure that gap.
3. The required bounties-repository star, H2 registration, showcase permission,
   contact identity, and final form receipt are owner-controlled actions.
4. A current paid Telegraph purchase/ranking/accounting result requires the
   operator's explicit financial and platform authorization. ACP remains
   intentionally suspended and is not a submission dependency.
5. A final screen recording or accessible equivalent needs owner approval of
   the final public-facing presentation and cannot be honestly claimed before
   it exists.

The strict score is therefore below the 90+/100 internal target. The strongest
remaining improvement is external verification, not another internal metric
or another preparation document.
