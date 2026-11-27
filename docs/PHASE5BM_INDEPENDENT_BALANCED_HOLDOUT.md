# Phase 5BM — independent balanced holdout

Phase 5BM is a new source-roster experiment, not a repackaging of Phase 5BI,
5BJ or 5BL. It freezes six package families and two previously unused
GitHub-reviewed advisory records per family from the public OSV API. Each
record contributes one source-covered predecessor of its first fixed boundary
and the exact fixed boundary, producing 24 cases with a 12/12 applicable versus
inapplicable balance.

The protocol is [frozen in JSON](../data/phase5bm-independent-balanced-holdout-protocol.json)
and the executable audit is [phase5bm_independent_balanced_holdout.py](../src/falsum/phase5bm_independent_balanced_holdout.py).

## Result contract

The run compares three policies under the same source facts:

- FALSUM's fail-closed interval policy.
- A separately implemented competent interval baseline.
- A deliberately weak citation-only policy that ignores version boundaries.

The protocol also audits balanced left/right answer order, equal-length answer
surfaces, identifier-only and package-only shortcuts, package-family leakage,
and outcome-based reselection. It records no exploitability, security
clearance, customer adoption, ranking, or paid Telegraph execution claim.

The selected records are public OSV entries with `github_reviewed=true`. This is
stronger provenance than a constructed label, but it remains a source-bound
version-applicability reference set rather than independent human AppSec gold.
For context, NIST's [Juliet suite](https://www.nist.gov/publications/juliet-11-cc-and-java-test-suite)
and public vulnerability-detection benchmarks such as [PrimeVul](https://arxiv.org/abs/2403.18624)
were considered but not substituted: they evaluate source-code vulnerability
classification, while this Intent needs target-bound advisory applicability.

Reproduce without payments, wallets or model calls:

```text
PYTHONPATH=src python -m falsum.cli audit-independent-balanced-holdout --out phase5bm.json
PYTHONPATH=src python -m unittest tests.test_phase5bm_independent_balanced_holdout -v
```

Expected result: 24/24 FALSUM, 24/24 competent interval baseline, and 12/24
citation-only accuracy. FALSUM wins 12 fixed-boundary cases over citation-only
and ties the competent baseline on all 24. The tie is intentionally preserved.
