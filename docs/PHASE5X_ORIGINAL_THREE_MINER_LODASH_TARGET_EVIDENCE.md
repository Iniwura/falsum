# Phase 5X — Three original paid-status Miner outputs, one real package target

**FALSUM | Telegraph Season II Evaluators | November 21, 2026**

## The genuine independent-source observation

The independent [PR Guard project](https://github.com/anvithagowda098/pr-guard) published original reported-paid Telegraph captures for **npm lodash 4.17.15**. At a fixed historical public Git commit, the records identify **three different Miner IDs** and three original signal/receipt hashes. They are genuine third-party **published observations**, not responses bought by FALSUM.

| Reported Miner | Original channel and recorded receipt Intent | Original answer type | Narrow FALSUM use |
| --- | --- | --- | --- |
| **77003** | Routed `SECURITY_REVIEW_GENERAL` with canonical `params.target` | 100 generic GHSA advisory rows; no package-specific identity | **Reject unscoped advice** |
| **190048** | Direct `GET /query`; receipt Intent `SECURITY_REVIEW` | Exactly named `lodash`, ecosystem NPM, version `4.17.15`, six GHSA advisory identifiers | **Permit display of unverified package-bound references** |
| **77010** | Direct `GET /query`; receipt Intent `SECURITY_REVIEW` | Exactly named `lodash`, ecosystem NPM, version `4.17.15`, six OSV-source advisory entries with CVE aliases | **Permit display of unverified package-bound references** |

The three original requests share **the same semantic package/version target** but are **not byte-identical and do not use the same protocol Intent**. Miner IDs are distinct, but actual independence of their ownership is not verified. **This is not a same-Intent fair Miner ranking test, and it cannot prove a change in Telegraph's canonical leaderboard or probabilistic routing.**

The direct responses are allowed only as **target-bound advisory references for display**. Exact package identity and the presence of advisory identifiers do **not** establish those advisories' independent correctness, severity, exploitability or complete coverage. No positive result automatically approves a package, payment, security review or transaction.

## Why a gate is useful

Every original third-party capture records HTTP 200, paid and charged flags, and a successful payment object. A transport-only acceptance rule therefore lets **all three** enter a downstream application, despite one response being a list of unrelated security advisories.

The source-aware relevance gate checks original request envelope, exact package/version, original reported Miner ID, response structure and the target binding. It refuses the unrelated advisory list even if generic keyword padding mentions the target. It also rejects a response whose reported Miner identity or request target is changed.

This is a more realistic application-quality failure than awarding raw accuracy to a model that always abstains. It still remains a **bounded deterministic checker for a public, known package target** rather than a universal security semantic judge.

## Preregistered observation and controls

The source selection, original byte SHA references, route distinctions and outcomes were [committed before implementing this phase](../data/phase5x-frozen-original-three-provider-lodash-relevance.json). Git blob SHA-1: `227b91ab42688ac4a02a95633ba3556d3ff8b84f`. Original external Git commit: `99d2e3c93890a8fc083947bde4f21217516b7a5f`.

The workflow downloads and verifies the **exact original Git blob SHA-1 bytes** for each of the three third-party captures. Original request/receipt identity, recorded reported-paid flags and signal/receipt hash *presence* are verified against those exact bytes, without publishing the entire original bodies in our repository.

Additional **12 clearly synthetic adversarial cases** change request package, change version, remove package-identifying response data, or swap claimed Miner identity, across all three original observations. Those mutations are **not** additional real external Miner responses. Their purpose is strict fail-closed behavior, not inflation of a field accuracy sample.

## Reproduce

Python 3.11–3.13, publicly accessible upstream GitHub source, no money, wallet, customer data or original third-party secret.

~~~bash
git clone https://github.com/Iniwura/falsum.git
cd falsum
python -m pip install --no-deps -e .

# Fetch exactly three original public third-party Git blobs, check complete Git SHA-1,
# evaluate bounded package-target display/reject and 12 constructed anti-bypass cases.
PYTHONPATH=src python -m falsum.phase5x_three_real_miner_target_relevance \
  --out three-real-provider-target-evidence.json

# Run adversarial local unit tests with explicitly fake test fixtures.
PYTHONPATH=src python -m unittest discover \
  -s tests -p 'test_phase5x_three_real_miner_target_relevance.py' -v
~~~

[Original GitHub Actions workflow](../.github/workflows/phase5x-three-real-miner-package-relevance.yml) runs three Python test matrices and the actual source-authentication job. Only the **actual successful source-authentication job** is evidence about the three external historical outputs. Unit-test doubles are not.

## Exact claim boundaries

This stage does **not** demonstrate a new model or training gain, independent AppSec judgement, original external payment *settlement* confirmation, comparable different Miners on the *same canonical Intent*, improved network leaderboard, FALSUM installed by PR Guard, a registered canonical evaluator, independently funded adoption or an official Season II submission.

It demonstrates a verifiable external application-quality decision: **two original package-targeted outputs can be presented with a strong warning, while one original paid-status off-target output is denied.** That is a **task-relevance decision**, not a source-to-exploit semantic verdict.
