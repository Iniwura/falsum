# FALSUM — final Evaluators submission package

**Prepared for review; not published or submitted.**

## Project details

- Project: **FALSUM**
- Track: **Evaluators**
- Intent: **`SECURITY_REVIEW_GENERAL`**
- Contribution shape: **evaluation material**; no released model adapter is
  claimed.
- Repository: <https://github.com/Iniwura/falsum>
- Judge guide: [H2 final judge experience](H2_FINAL_JUDGE_EXPERIENCE_2026-11-27.md)
- Strict score: [56/100 evidence score](H2_FINAL_STRICT_SCORE_2026-11-27.md)
- Optional ACP integration: suspended, excluded from the final claim.

## Short public summary draft

FALSUM makes security-review evaluation evidence auditable. For a new public
provider response it binds the exact ecosystem, package and version to
immutable advisory-source bytes, applies fixed/last-affected version
boundaries, and abstains when identity or interval evidence is unsupported.
The fresh public holdout evaluates 66 Django references and a zero-reference
lodash response; 38 canonical sources resolve, 27 are applicable, 39 remain
fail-closed unknown/insufficient, and a separate version-aware baseline agrees
on every row. A prior frozen roster measured a bounded 2/12 reduction in known
version-inapplicable displays. These results are reproducible evaluation
material—not security clearance, human AppSec gold, recall, customer adoption,
ranking uplift, or a new paid Telegraph transaction.

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
```

Expected fresh result: 66 reported references, 38 canonical source records,
27 applicable, 39 fail-closed unknown/insufficient, zero baseline
disagreements, and zero lodash references. Expected prior result: 12
accept-all references, 2 known inapplicable, 10 reviewed display references,
and 0 known inapplicable displays.

The network used by the fresh replay is public GitHub source retrieval pinned
to immutable commits. The replay costs **$0** and performs **no Telegraph
transaction**. Historical Telegraph evidence remains separately labelled and
does not become current production usage.

## Evidence links to include

| Claim | Evidence | Honest scope |
| --- | --- | --- |
| Frozen fresh public-provider holdout | [Phase 5BJ protocol](../data/phase5bj-fresh-provider-holdout-protocol.json) and [implementation](../src/falsum/phase5bj_fresh_provider_holdout.py) | New public coverage; not blind gold or recall |
| Fresh outcome | `data/phase5bj-fresh-provider-holdout-result.json` when the owner elects to retain the replay artifact | 66 references, 38 resolved, 27 applicable, 39 abstentions/unknowns |
| Prior bounded measurement | [Phase 5BI scorecard](../src/falsum/phase5bi_measurement_scorecard.py) and [hosted CI](https://github.com/Iniwura/falsum/actions/runs/45915924410) | 2/12 known false-positive reduction; narrow reviewed roster |
| Safety and provenance | [Phase 5B/5BG tests](../tests/) and current GitHub Actions workflows | Fail-closed evidence handling; no security clearance |
| Telegraph relevance | [final competitive audit](H2_FINAL_COMPETITIVE_AUDIT_2026-11-27.md) | Historical/public evidence only; ACP suspended |
| Demo/equivalent | [final storyboard](H2_FINAL_DEMO_STORYBOARD_2026-11-27.md) | Prepared, not recorded or submitted |

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

No submission, publication, payment, deposit, tokenization, signer change, or
ACP browser action is authorized by this package.
