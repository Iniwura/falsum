# FALSUM — final Evaluators submission package

**Prepared for review; not published or submitted.**

## Project details

- Project: **FALSUM**
- Track: **Evaluators**
- Intent: **`SECURITY_REVIEW_GENERAL`**
- Official mapping: **`SECURITY_REVIEW_GENERAL`** is the child Intent of the
  **`SECURITY_REVIEW`** judgment family, as documented by [bounty #96](https://github.com/telegraphprotocol/bounties/issues/96)
  and [INTENTS.md](https://github.com/telegraphprotocol/bounties/blob/main/docs/INTENTS.md).
  This does not claim maintainer acceptance or live adapter registration.
- Contribution shape: **evaluation material**; no released model adapter is
  claimed.
- Repository: <https://github.com/Iniwura/falsum>
- Judge guide: [H2 final judge experience](H2_FINAL_JUDGE_EXPERIENCE_2026-11-27.md)
- Historical internal assessment: [96/100 under the correct rubric](H2_FINAL_STRICT_SCORE_2026-11-27.md); the latest independent judge-style audit remains 84/100, and this package does not recertify a replacement score.
- Optional ACP integration: suspended, excluded from the final claim.

## Short public summary draft

FALSUM makes security-review evaluation evidence auditable. For a new public
provider response it binds the exact ecosystem, package and version to
immutable advisory-source bytes, applies fixed/last-affected version
boundaries, and abstains when identity or interval evidence is unsupported.
The fresh public holdout evaluates 66 Django references and a zero-reference
lodash response; 38 canonical sources resolve, 27 are applicable, 39 remain
fail-closed unknown/insufficient, and a separate version-aware baseline agrees
on every row. Two official mission workflows have repeatable supporting tests:
Model Economy supply-chain verification and Web3 Native and DeFi
security/bug-bounty proof. The cross-source measurement audit rejects 3/3
explicit missing-evidence clean candidates, suppresses 2/2 independently
reviewed version-inapplicable references, removes 8 count-only vulnerable-label
PASS outcomes, and agrees 66/66 with a competent baseline while tying
verdict-only. A prior frozen roster measured a bounded 2/12 reduction in known
version-inapplicable displays. The historical Phase5BM 24-case holdout remains
preserved, but its perfect result is not the current certification basis. The
corrected Phase5BN holdout records 22/24 FALSUM against 24/24 for an external
`packaging`/`semver` resolver, with two explicit unknown disagreements, real
registry versions, meaningful competing answers and computed index/position/
token leakage checks. These results are reproducible evaluation
material—not security clearance, human AppSec gold, recall, customer adoption,
ranking uplift, or a new paid Telegraph transaction.

The ecosystem-native semantic regression is a separate improvement: it
resolves both legacy-version abstentions, adds 12 unseen snapshot-backed cases,
covers disjoint intervals and unsupported ranges, and evaluates structured
claim/action selection. It records 14/14 candidate decisions and 14/14
structured claim/action selections. The option prose is display-only, not
natural-language answer scoring. This is not automatic score credit or
external validation.

## Reviewer run path

Prerequisite: Python 3.11–3.13 and public internet access for immutable
GitHub raw sources. No wallet, API token, signer, deposit, native gas, or paid
purchase is required.

```bash
git clone https://github.com/Iniwura/falsum.git
cd falsum
PYTHONPATH=src python -m unittest discover -s tests \
  -p 'test_phase5bj_fresh_provider_holdout.py' -v
PYTHONPATH=src python -m falsum.cli audit-fresh-provider-holdout \
  --out fresh-holdout.json
PYTHONPATH=src python -m falsum.cli audit-evaluator-measurement \
  --out prior-measurement.json
PYTHONPATH=src python -m falsum.cli audit-independent-balanced-holdout \
  --out independent-balanced-holdout.json
python -m pip install --no-deps packaging==26.4
npm install --prefix .phase5bn-node --ignore-scripts --no-audit --no-fund semver@7.8.6
npm install --prefix .phase5bo-node --ignore-scripts --no-audit --no-fund semver@7.8.6
PYTHONPATH=src FALSUM_PHASE5BN_NODE_PATH=.phase5bn-node/node_modules \
  python -m falsum.cli audit-corrected-independent-holdout \
  --out corrected-independent-holdout.json
PYTHONPATH=src FALSUM_PHASE5BO_NODE_PATH=.phase5bo-node/node_modules \
  python -m falsum.cli audit-ecosystem-semantics \
  --out ecosystem-semantics.json
```

Expected fresh result: 66 reported references, 38 canonical source records,
27 applicable, 39 fail-closed unknown/insufficient, zero baseline
disagreements, and zero lodash references. Expected prior result: 12
accept-all references, 2 known inapplicable, 10 reviewed display references,
and 0 known inapplicable displays. The Phase5BM command is retained as
historical evidence. Expected corrected Phase5BN result: 24 cases, 22/24
FALSUM, 24/24 external resolver, 48 distinct target-specific answers,
computed leakage checks with no detected signal, and verified package versions
from pinned live registry metadata.
Expected Phase5BO result: 14/14 from committed registry snapshots with zero
live registry reads during audit.

The network used by the fresh replay is public GitHub source retrieval pinned
to immutable commits. The replay costs **$0** and performs **no Telegraph
transaction**. Historical Telegraph evidence remains separately labelled and
does not become current production usage.

## Evidence links to include

| Claim | Evidence | Honest scope |
| --- | --- | --- |
| Frozen fresh public-provider holdout | [Phase 5BJ protocol](../data/phase5bj-fresh-provider-holdout-protocol.json) and [implementation](../src/falsum/phase5bj_fresh_provider_holdout.py) | New public coverage; not blind gold or recall |
| Fresh outcome | `data/phase5bj-fresh-provider-holdout-result.json` when the owner elects to retain the replay artifact | 66 references, 38 resolved, 27 applicable, 39 abstentions/unknowns |
| Mission/workflow support | [Phase 5BK matrix](../data/phase5bk-evaluator-mission-workflow-matrix.json) | Two repeatable supporting workflows; no completed mission or app consumption claim |
| Current Anjoman status | [Phase 5BK read-only status](../evidence/phase5bk-2026-11-27-anjoman-status.json) | 20/20 current Eligible rows for the operator-reported Privy address; acceptance/registration unverified |
| Prior bounded measurement | [Phase 5BI scorecard](../src/falsum/phase5bi_measurement_scorecard.py) and [hosted CI](https://github.com/Iniwura/falsum/actions/runs/45918441661) | 2/12 known false-positive reduction; narrow reviewed roster |
| Cross-source discriminative measurement | [Phase 5BL report](../data/phase5bl-cross-source-measurement-discrimination.json) and [contracts](../tests/test_phase5bl_measurement_discrimination.py) | Two weaker-policy contrasts, competent-baseline tie, verdict-only tie preserved |
| New independent balanced holdout | [Phase 5BM protocol](../data/phase5bm-independent-balanced-holdout-protocol.json), [implementation](../src/falsum/phase5bm_independent_balanced_holdout.py), [result](../data/phase5bm-independent-balanced-holdout-result.json), and [contracts](../tests/test_phase5bm_independent_balanced_holdout.py) | 24 paired cases; FALSUM and competent baseline 24/24; citation-only 12/24; balanced/no leakage |
| Corrected independent holdout | [Phase 5BN protocol](../data/phase5bn-corrected-independent-holdout-protocol.json), [implementation](../src/falsum/phase5bn_corrected_independent_holdout.py), [result](../data/phase5bn-corrected-independent-holdout-result.json), [contracts](../tests/test_phase5bn_corrected_independent_holdout.py), [hosted workflow](../.github/workflows/phase5bn-corrected-independent-holdout.yml) and [passed run](https://github.com/Iniwura/falsum/actions/runs/45949446218) | 22/24 FALSUM vs 24/24 external resolver; real registry versions; meaningful answers; computed leakage audit |
| Ecosystem-native semantic improvement | [semantic protocol](../data/phase5bo-ecosystem-semantics-protocol.json), [implementation](../src/falsum/phase5bo_ecosystem_semantics.py), [snapshots](../data/phase5bo-registry-snapshots/), [result](../data/phase5bo-ecosystem-semantics-result.json), [contracts](../tests/test_phase5bo_ecosystem_semantics.py), and [passed final hosted CI](https://github.com/Iniwura/falsum/actions/runs/45976774179) | PEP 440/SemVer, 12 additional unseen cases, disjoint/unsupported ranges, snapshot-only replay, and structured claim/action selection; option prose is not natural-language scoring; no automatic score credit |
| Official Intent mapping | [Bounty #96](https://github.com/telegraphprotocol/bounties/issues/96) and [INTENTS.md](https://github.com/telegraphprotocol/bounties/blob/main/docs/INTENTS.md) | Child Intent maps to `SECURITY_REVIEW` family; no acceptance or adapter registration claim |
| Safety and provenance | [Phase 5B/5BG tests](../tests/) and current GitHub Actions workflows | Fail-closed evidence handling; no security clearance |
| Telegraph relevance | [final competitive audit](H2_FINAL_COMPETITIVE_AUDIT_2026-11-27.md) | Historical/public evidence only; ACP suspended |
| Demo/equivalent | [final storyboard](H2_FINAL_DEMO_STORYBOARD_2026-11-27.md) | Prepared, not recorded or submitted |
| Internal release gate | [release-gate evidence](../evidence/final-release-gate-check-2026-11-27.json) | Read-only command, public-route, accessibility and owner-blocker verification |
| Hosted production inspection | [Playwright + axe run](https://github.com/Iniwura/falsum/actions/runs/45978583401) and [release-gate evidence](../evidence/final-release-gate-check-2026-11-27.json) | Four desktop/mobile screenshots, zero automated axe violations; no human screen-reader claim |

## Official submission checklist

The official rules require project/contact details, track and Intent, working
or reviewer-access link, the GitHub username that starred the bounties repo, a
2–5 minute demo or accessible equivalent, beginner-friendly run instructions
with network/costs/limits, evidence, a short public summary with H2 links, and
showcase permissions. The entry must also show something working, real
Telegraph integration, repeatable results, safe handling, accurate claims, and
the required star on `github.com/telegraphprotocol/bounties`.

Owner-controlled items intentionally remain unchecked until performed:

- H2 registration and final form receipt;
- correct bounties-repository star and username;
- contact identity and showcase/buyer-introduction permissions;
- final public recording or approved accessible equivalent;
- any current paid Telegraph run or independent customer evidence.

The final internal release gate is otherwise green: code and evidence are
committed, hosted CI is passing, the public reviewer routes returned HTTP 200
with structural accessibility/responsive checks, the local evidence links
resolve, and the zero-credential reviewer commands were smoke-tested. These
checks do not authorize publication or submission.

No submission, publication, payment, deposit, tokenization, signer change, or
ACP browser action is authorized by this package.
