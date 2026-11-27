# Phase 5BN corrected independent-label holdout

Phase 5BM remains preserved as historical evidence. Phase 5BN is a separate corrected experiment and is the only result that may be used for current measurement claims.

## Contract

The protocol freezes 24 registry-backed cases from 12 GitHub-reviewed advisories: 12 PyPI and 12 npm cases, balanced between applicable and inapplicable versions. The vulnerable/fixed version pair for each advisory is selected from the published package registry metadata, and the exact metadata and advisory bytes are SHA-256 pinned in the protocol.

Reference labels are computed before the candidate runs with two independent, established implementations:

- PyPI: [`packaging==26.4`](https://pypi.org/project/packaging/), using `SpecifierSet` and `Version`.
- npm: [`semver@7.8.6`](https://www.npmjs.com/package/semver), invoked in a separate Node process.

The case order and answer-token assignment use one fixed seed. The seed is not searched against labels or FALSUM output. The reference stage re-resolves every frozen case and fails closed if a pinned source or package version changes. Only after that stage does the existing FALSUM policy execute.

Each case presents two target-specific security triage answers. They state the package, version, advisory, action and scope; they are not generic “A/B” placeholders. The answer-selection score is still limited to source-bound version applicability and is not human AppSec gold, exploitability, security clearance or customer adoption.

## Corrected result

The committed result is reproducible with the workflow and records:

| Policy | Correct | Incorrect | Denominator |
| --- | ---: | ---: | ---: |
| FALSUM | 22 | 2 | 24 |
| external version-resolution reference | 24 | 0 | 24 |

The two FALSUM disagreements are preserved, not hidden:

- `setuptools@0.6c11` — external resolver: `APPLICABLE`; FALSUM: `UNKNOWN_OR_INSUFFICIENT`.
- `pymongo@0.1pre` — external resolver: `INAPPLICABLE`; FALSUM: `UNKNOWN_OR_INSUFFICIENT`.

This is meaningful discrimination against a competent baseline, not evidence that FALSUM is perfect. The experiment does not establish a winner over human security reasoning because the external resolver only adjudicates version applicability.

## Leakage and shortcut audit

The result computes, rather than asserts, permutation-test evidence for:

- case-index parity;
- case-index modulo three;
- correct answer position; and
- correct answer token.

The corrected result reports `label_leakage_detected: false`. The strongest observed index signal is 16/24 majority accuracy for parity, with a deterministic permutation p-value of approximately 0.222; it does not pass the predeclared 0.01 threshold. The clean protocol is tested against adversarial index- and token-correlated mutations, which must be detected.

## Reproduction

From the repository root:

```text
python -m pip install --no-deps packaging==26.4
npm install --prefix .phase5bn-node --ignore-scripts --no-audit --no-fund semver@7.8.6
set PYTHONPATH=src
set FALSUM_PHASE5BN_NODE_PATH=.phase5bn-node/node_modules
python -m falsum.cli audit-corrected-independent-holdout --out phase5bn-result.json
python -m unittest discover -s tests -p "test_phase5bn_corrected_independent_holdout.py" -v
```

The output must match `data/phase5bn-corrected-independent-holdout-result.json`. Hosted CI repeats the registry existence checks on Ubuntu across Python 3.11, 3.12 and 3.13.

## Limits

The experiment uses public advisory and package metadata, not independently adjudicated human labels. It does not prove exploitability, remediation quality, live Telegraph delivery, customer adoption or ranking. ACP remains suspended and no financial transaction is part of this evidence.
