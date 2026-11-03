# Phase 3W — one-click independent security review intake

**Status:** The form and public source cases are a **reviewer invitation**, not independent validation or training progress. The earlier Phase 3V genuine model test showed **0/2 complete context reversals**, so both candidate LoRA models remain blocked from release. Getting independently assessable source cases is the next quality gate, not a new design milestone.

## One clear reviewer experience

1. [Read seven real upstream source-fix comparisons](REVIEW_ONE_CASE.md). Choose one case; all answer choices are **FALSUM-authored public proposals**.
2. Open [the GitHub review form](https://github.com/Iniwura/falsum/issues/new?template=independent-seven-review.yml). Select one case and **A, B or ABSTAIN**. Cite exact lines from the immutable source/test fix commit and the primary security advisory.
3. Explain the boundary, uncertainty and what the available evidence *does not* prove about real deployed code. Submit from your own GitHub account. There is no JSON digest editing, Actions download, wallet, secret, SDK or service to install.

No public source patch by itself demonstrates a live customer vulnerability. Neither FALSUM's authored answer order nor old model preferences determine correctness. Cases are previously studied, not a sealed prospective blind holdout. **Author expectations and model scores are deliberately absent from the reviewer-facing page, but source repo history remains public; this is not a blinded trial.**

## Exact supported cases

Seven different source- and regression-test-pinned families from [Phase 3F](PHASE3F.md): Requests proxy authentication, Jinja sandbox attr, Axios absolute URL/baseURL, Starlette static path containment, urllib3 authorization casing, Django recursive numeric formatting, and Express malformed redirects.

The published source identities are bound to [the original research queue](../data/real-fix-queue.json), [the separate candidate queue](../data/real-fix-train-candidates.json) and code-level [Phase 3F `PINS`](../src/falsum/phase3f_multifamily_material.py). The prior network-enabled upstream verification is in the original [Phase 3F CI](https://github.com/Iniwura/falsum/actions/runs/41353459211). This phase **does not re-test external software or independently validate reviewer conclusions**.

## Honest machine-readable claims

[Phase 3W intake](../src/falsum/phase3w_review_intake.py) reads GitHub's **actual public issue list** from `api.github.com/repos/Iniwura/falsum/issues`, not an owner-supplied local list masquerading as live data.

For each candidate issue, it verifies a normal GitHub user account (not the project owner or a bot), exact canonical issue identity and timestamps, selected pinned case, supported preference including ABSTAIN, minimum original analysis, independent safety attestation and exact source/test line citations under the known full Git commit SHA. Same-account duplicate claims do not count twice. Wrong parent/fix URLs, missing advisory, fake checkboxes and injected/missing form headings are rejected. A source link's **format**, not its security meaning, is checked.

```bash
PYTHONPATH=src python -m falsum.phase3w_review_intake --out /tmp/falsum-external-claim-report.json
PYTHONPATH=src:tests python -m unittest discover -s tests -p test_phase3w_review_intake.py -v
```

A complete audit always records:

- Which actual public GitHub issues supplied claims, and whether the GitHub API was actually consulted.
- Rejected submissions, per-case positions, unresolved disagreements, potential duplicates.
- **0 independently expert-certified labels, 0 accepted training pairs, 0 new eligible network rows and 0 registered models**, regardless of apparent agreement.

A GitHub login, checkbox and two matching authors **do not** establish independence, technical expertise or ground truth. Qualified review still needs real human adjudication, conflict checks and repeatable source testing before it can affect model training. The report exports no trainable preference pairs.

[Phase 3W CI](../.github/workflows/phase3w-one-click-review.yml) tests these boundaries on Python 3.11–3.13, re-runs previous independent-intake unit suites and separately audits the **live GitHub issue list**. Its report remains an unapproved public-claim record. A passing test does **not** mean an independent reviewer responded.

## Preserve existing work

- Existing [Phase 3G JSON-comment path](PHASE3G.md) and [issue #3](https://github.com/Iniwura/falsum/issues/3) are retained for backward compatibility. The new form removes a real adoption friction, not its existing verification gates.
- Existing [Phase 3V model diagnostic](PHASE3V.md) remains research-only and failed both recorded context-switch families. It demonstrates a problem, **not a solved evaluator or model accuracy**.
- The user's **20 previously Anjoman-eligible `SECURITY_REVIEW_GENERAL` evaluation pairs** are separate; no private row, hidden question, source key, wallet or answer was exposed.
- The production FALSUM demo is **unchanged**. No fabricated usage, expert comments, mission adoption or prize claim was added.

## What unblocks future model work?

A real external reviewer must actually submit a source-backed assessment. Its expertise, evidence and uncertainty must be independently assessed before the project considers it an approved research label. We should then collect new case families with strict project separation, freeze the holdout **before** model tuning, run the scorer on both changed facts and untouched cases, and report gains and failures in full. We should not retrain another LoRA using the owner's provisional answers as if they were independently verified labels.

A public social update inviting review and the actual issue URL may count as useful education, but not as independent community adoption. Telegraph H2 requires a separate final entry by **1 December 2026, 23:59 UTC**; see the [official rules](https://hackathon.telegraphprotocol.com/rules).
