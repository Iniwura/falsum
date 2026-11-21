# Phase 5Y — A real version-level false positive in original paid Telegraph Miner output

**FALSUM / Telegraph Season II Evaluators / November 21, 2026**

## Finding

Two independently recorded *reported* Miner IDs, **190048** and **77010**, returned six security advisories apiece for the exact target **npm lodash 4.17.15**. Their original public request/response captures recorded paid and HTTP success, but both included **CVE-2026-2950 / GHSA-f23m-r3pf-42rh**, an advisory that **does not apply to lodash 4.17.15** according to the independently maintained original GitHub-reviewed Advisory Database.

The reviewed advisory gives the exact package `npm / lodash` this affected interval:

**Affected:** 4.17.23 (inclusive) through 4.18.1 (exclusive).

**Requested:** 4.17.15, which is earlier than the affected interval.

The same advisory separately names packages such as `lodash.unset` and `lodash.omit`, with different version ranges. **These are different package names**. A version judge that merges their intervals into `lodash` gives a false positive. Phase 5Y explicitly selects **exactly** the matching `name=lodash`, `ecosystem=npm` entry before checking the numeric version boundary.

## Results, after original Git provenance verification

| Original outside Miner | Reported advisory references | Version-applicable references | Version-inapplicable references | Use after FALSUM |
| --- | ---: | ---: | ---: | --- |
| **190048** (direct GET /query) | 6 GHSA IDs | 5 | **1** | Show only 5 as unverified references |
| **77010** (direct GET /query) | 6 OSV/CVE identifiers | 5 | **1** | Show only 5 as unverified references |
| **Total** | **12** references | **10** | **2** | Reject two misapplied references |

There are **six distinct advisories**, and **one unique misapplied advisory repeated across both original Miner outputs**. Do not claim twelve independent cases or two independent new discoveries. The fraction 5/6 (83.3%) describes applicability **among these six reported references per Miner**, not full detection accuracy, advisory recall, precision on a representative holdout, or vulnerability exploitability.

**The original recorded paid-success baseline admits all 12 references.** The reference-constrained filter removes the two version-inapplicable claims while retaining ten references whose *reviewed affected ranges include the requested version*. That is a verifiable concrete difference in an application's decision; it does not establish that the ten advisories are complete, independently retested exploits or suitable for automated security approval.

## Where each fact comes from

The frozen source protocol is [here](../data/phase5y-original-reviewed-lodash-six-advisory-protocol.json), committed **before building this evaluator** at Git SHA `c6c8a492c4a9467b29f61899567bce5145e1267a`, frozen full Git blob SHA-1 `ed0e5c40d918dbc46e8a7e58eeb0a225cfaef237`.

### Original provider evidence

Source: the separately developed [PR Guard](https://github.com/anvithagowda098/pr-guard) project, immutable Git revision `99d2e3c93890a8fc083947bde4f21217516b7a5f`.

- Reported Miner **190048**, original file `test/fixtures/miner-responses/SECURITY_REVIEW_GENERAL/190048-npm-lodash-4.17.15-200-paid.json`, immutable Git blob `658510885abb51d35f74357bf3ffc5a8c88e0374`.
- Reported Miner **77010**, original file `test/fixtures/miner-responses/SECURITY_REVIEW_GENERAL/77010-npm-lodash-4.17.15-200-paid.json`, immutable Git blob `c914607b580e99d2f269bc69a01d6104dc25191e`.

Both direct captures reported receipt Intent `SECURITY_REVIEW` and HTTP 200, paid and charged. They are **not byte-identical requests**, and they do **not** provide a fair same-canonical-`SECURITY_REVIEW_GENERAL` Miner ranking test. Recorded paid flags have not been independently verified against a settlement chain.

### Independent reviewed version references

Source: [GitHub Advisory Database](https://github.com/github/advisory-database), immutable original Git revision `76955defc62d048f8f7cc68bc39a2f6dd1899ebe`. All **six complete original reviewed advisory JSON files** were downloaded and their full Git SHA-1 checked against the preregistered manifest.

| Reviewed GitHub advisory | CVE alias | Exact npm lodash affected interval | Applies to 4.17.15? |
| --- | --- | --- | --- |
| [GHSA-29mw-wpgm-hmr9](https://github.com/advisories/GHSA-29mw-wpgm-hmr9) | CVE-2020-28500 | 4.0.0 to before 4.17.21 | Yes |
| [GHSA-35jh-r3h4-6jhm](https://github.com/advisories/GHSA-35jh-r3h4-6jhm) | CVE-2021-23337 | From 0 to before 4.17.21 | Yes |
| [GHSA-f23m-r3pf-42rh](https://github.com/advisories/GHSA-f23m-r3pf-42rh) | CVE-2026-2950 | 4.17.23 to before 4.18.1 | **No** |
| [GHSA-p6mc-m468-83gw](https://github.com/advisories/GHSA-p6mc-m468-83gw) | CVE-2020-8203 | 3.7.0 to before 4.17.19 | Yes |
| [GHSA-r5fr-rjxr-66jc](https://github.com/advisories/GHSA-r5fr-rjxr-66jc) | CVE-2026-4800 | 4.0.0 to before 4.18.0 | Yes |
| [GHSA-xxjr-mmjv-4gpg](https://github.com/advisories/GHSA-xxjr-mmjv-4gpg) | CVE-2025-13465 | 4.0.0 to before 4.17.23 | Yes |

The work is based on **independently maintained source records**, not fabricated gold labels. We have **not** commissioned a qualified human AppSec expert to adjudicate this dataset. We do not assume a reference database is infallible, either.

## What was executed

[**Original successful Phase 5Y GitHub Actions run**](https://github.com/Iniwura/falsum/actions/runs/44905080530): **4/4 jobs passed**, including three Python 3.11/3.12/3.13 adversarial tests and one independent online source-authentication run.

The actual job fetched **six original reviewed Git blobs and two original provider capture Git blobs** (with the previous Phase 5X wrapper also validating the public routed reference as a prerequisite), verified original package identities, exact reviewed version ranges, and generated a bounded **12-row** report. It checks source identity and CVE↔GHSA aliases for all six references and refuses ambiguous ranges.

Adversarial tests cover numeric-version ordering, fixed-exclusive vs last-affected-inclusive bounds, the critical 4.17.23 introduction boundary, exact package name vs similarly named lodash subpackages, missing/duplicate source ranges, altered source bytes, modified provider requests, forged source hashes and missing identifiers.

Original retained artifact:

- GitHub Actions artifact ID **14708020009**.
- ZIP SHA-256: `d30a8e01199f659203b96915cfd12aed80d56d89c1630e1b2bc3cf1a3977a41e`.
- Original aggregate report SHA-256: `0c08e6cbb25cbd1bcd975a4ff4d443afd36045571e1719fb5d205f305ffd9baa`.
- [Permanent safe original-evidence index](../evidence/phase5y-2026-11-21-actual-reviewed-ghsa-version-inapplicable-miner-references.json).

Reproduce without an API key, wallet, paid Telegraph request or third-party private material:

```bash
git clone https://github.com/Iniwura/falsum.git
cd falsum
python -m pip install --no-deps -e .
PYTHONPATH=src python -m falsum.cli audit-reviewed-advisory-version \
  --out original-reviewed-version-evidence.json
PYTHONPATH=src python -m unittest discover \
  -s tests -p 'test_phase5y_original_reviewed_version_applicability.py' -v
```

Raw original third-party response bodies are **not republished** in FALSUM's artifacts. The minimized report contains the source URLs, SHA-1 fingerprints, reported IDs, reviewed numeric version boundaries and decisions.

## Competition claim boundaries

**Demonstrated:** an actual version-inapplicable original reported security advisory, repeated across two original Miner outputs, caught using separately maintained primary records and reproducible application-filter decisions.

**Not demonstrated:** a real same-canonical-Intent ranking improvement, qualified human AppSec labels, full advisory recall, observed network evaluation/rewards, verified payment settlement, independently owned providers, original Miner adoption of FALSUM, registered network scorer, or a trained model outperforming baselines. The original disclosures may share upstream deps.dev/OSV data; do not claim independent model consensus.

This is new, externally grounded semantic validity evidence. It makes the case for FALSUM stronger than a source-format-only judge, but it is not sufficient by itself to warrant a 90+/100 win prediction. No demo or official submission was made by this phase.
