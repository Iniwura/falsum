# Phase 5AK — complete external-label policy comparison

**Verified November 24, 2026:** [actual original-source run](https://github.com/Iniwura/falsum/actions/runs/45356819921) succeeded, artifact 14901884473, SHA-256 `61be36e839f1a80d2196d59cd6b2b1cf956a7c9c599957f9f08427e00a5982de`. PR #98 passed 22/22 checks and merged; all six [post-merge workflows](https://github.com/Iniwura/falsum/actions?query=branch%3Amain) passed at `8df19427`. This extends Phase 5AJ with the complete independently published [Gig Guard scale run](https://github.com/swiftbotlabs/gig-guard/blob/aa495fe5cd713c41e89698dc20463c5d6dade8fd/eval/scale/RESULTS.md). All 158 decision events, 29 reruns, 202 purchases, 70 errors, and 129 latest case labels are frozen in the [protocol](../data/phase5ak-external-label-baseline-protocol.json). Git lock commit `d334423e7d564cf3c8b6c0c40d515ad758282f39`. Original records were inspected before freezing; this is not a blind test.

## Why this matters

A consumer treating zero vulnerability count as a clean result can ignore an explicitly negative verdict. We compare that policy with verdict-only, strict field agreement, and a portable conservative FALSUM policy. These are downstream decision-policy predictions, not new Miner outputs, learned ranking improvements, or security clearance.

Actual latest-case comparison confirmed by original-source CI:

| Policy | Vulnerable flagged /107 | Vulnerable PASS /107 | Vulnerable unknown /107 | Audited PASS /22 | Audited flagged /22 | Audited unknown /22 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Count only | 80 | 8 | 19 | 13 | 1 | 8 |
| Verdict only | 89 | 0 | 18 | 9 | 5 | 8 |
| Strict agreement | 80 | 0 | 27 | 9 | 1 | 12 |
| FALSUM consumer | 89 | 0 | 18 | 9 | 5 | 8 |

The measured consumer policy avoids eight count-only vulnerable-label PASS predictions at the expense of more flags on audited controls. **It does not improve upon verdict-only on this sample.** Audited controls are not proven bug-free; an audited-control flag is not established as a false vulnerability claim. The 98-case no-name-hint stratum is shown separately in the report. Excluding known hints does not make a public historical benchmark a blind test.

The full ledger retains earlier attempts but the latest-by-case comparison uses each case once. Abbreviated addresses are matched only by a collision-rejecting transformation against the authenticated manifest. Explicit failure differs from no recorded answer. The archived check lists 201 settled and one NOT_FOUND, not 202 independently verified live settlements. We compare archived status metadata, not current payment proof.

The first original-source run rejected the missing `hint` field in the audited controls. All 22 audited rows omit it; the source publisher's [scorer](https://github.com/swiftbotlabs/gig-guard/blob/aa495fe5cd713c41e89698dc20463c5d6dade8fd/eval/scale/score.mjs) uses `!it.hint`. The parser now reproduces that documented convention only for audited rows and rejects missing or malformed vulnerable-row hints. The frozen protocol, source identities, population and expected metrics are unchanged. [First fail-closed run](https://github.com/Iniwura/falsum/actions/runs/45356686227/job/138316220251).

## Reproduce

Python 3.11+, network access to pinned GitHub raw files. No wallet, key or new purchases.

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_phase5ak_external_label_baselines.py' -v
PYTHONPATH=src python -m falsum.phase5ak_external_label_baselines --out phase5ak-report.json
```

[Dedicated public CI workflow](../.github/workflows/phase5ak-external-label-baselines.yml). Source bytes are checked against exact original Git identities; no external code is executed. Full source bodies are not republished.

The two application teams' own tests, labels, app behavior and published results remain theirs. This does not establish outside adoption, qualified expert gold, a new registered evaluator, new paid inference, improved network ranking or mission completion.
