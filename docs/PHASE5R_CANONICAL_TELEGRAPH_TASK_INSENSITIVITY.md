# Phase 5R — A real Telegraph Miner returned the same 100 advisories for two different tasks

**FALSUM / Telegraph Season II Evaluators / canonical SECURITY_REVIEW_GENERAL / 21 November 2026**

## A real, reproducible network-quality diagnostic

The independent PR Guard builder published two **reported-paid HTTP 200** captures from the **same canonical SECURITY_REVIEW_GENERAL request route**, both reporting Miner **77003**, at exact Git revision `99d2e3c93890a8fc083947bde4f21217516b7a5f`.

- **Task A — source code:** Review a JavaScript source diff that introduces query-string concatenation into SQL and dynamic evaluation of a request body.
- **Task B — package security:** Review the npm package **lodash version 4.17.15**.

Despite the different inputs, the original public response captures include **the same 100 GitHub Security Advisory identifiers, in exactly the same order**. The lodash response's advisory entries include **zero mentions of lodash** in original public source data. The FALSUM task-relevance gate flags both as **OFF_TARGET_ADVISORY_FEED**. A naïve HTTP-success or `payment.success` quality check would accept both.

This finding is stronger than the original Phase 5Q one-task check because the pair exposes **task-insensitive output under two unrelated target types**. It is still **two publicly captured tasks from one reported miner**, not a multi-miner fair ranking study or a population accuracy estimate.

## Source integrity and protections

The original observed pair is [locked](../data/phase5r-observed-independent-two-task-contrast-lock.json) in commit `10bafd6b9076e1b109bf6d580cefb44b3ead02cc` (Git blob SHA1 `94b90f7276b001e1660eb53497a20611f3a6973a`) **before automated Phase 5R implementation**. The original files and their response similarity **were manually inspected before this study was designed**. This is an observational public case study, not a preselection-blind held-out benchmark.

Each original public third-party file is fetched only from the immutable PR Guard commit and checked against the **complete original Git blob SHA1**:

| Original public capture | Source Git blob SHA1 |
| --- | --- |
| `ROUTED/security-review-diff-77003-off-target.json` | `90088128cb12c4b55966e72165c6a8b311fdbfb2` |
| `ROUTED/security-review-lodash-77003-off-target.json` | `0b3268f57d3e21d906e51be9aebf754347e5787d` |

Both contain original `request.intent = SECURITY_REVIEW_GENERAL`, `params.target`, `body.miner_id = 77003` and `result_shape = raw`. We require their target strings to differ, advisory lists to have 100 unique IDs each and the two original GHSA-ID sequences to be identical before emitting a success report. A modified or unavailable upstream file is rejected rather than guessed.

**Privacy:** the resulting public evidence JSON contains only source URLs, Git/source/task SHA hashes, counts, categories and aggregate decisions. It never republishes the third-party source-code diff or full original response. Do not train on these third-party captures without rights. The owner-operated PR Guard Sentinel Miner #731001 is excluded.

## Judge and developer reproduction

With Python 3.11+, no wallet, payment or model key required:

~~~bash
git clone https://github.com/Iniwura/falsum.git
cd falsum
python -m pip install --no-deps -e .
falsum audit-telegraph-consistency --out two-task-consistency.json
~~~

The output confirms the two immutable external sources, two distinct canonical requests, identical ordered GHSA responses and two off-target results. [Actual live GitHub Actions source verification](../.github/workflows/phase5r-telegraph-public-two-task-consistency.yml) performs this process and retains an aggregate-only ZIP. The offline adversarial suite checks package-name changes, fake evidence, protocol role equality and malicious request shape changes on Python 3.11–3.13.

The reusable `classify_package()` method separates **structural relevance** from actual correctness:
- A broad generic advisory listing with no relation to the specified package fails task relevance.
- A response that mentions the correct package or cites an actual package vulnerability is only a candidate *relevance present* observation.
- It must **not** receive a validated security-claim accuracy score or model-quality reward from such a shallow check. Package labels, affected versions and severity require external authoritative evidence.
- Cross-Intent results and different request formats are not eligible as same-task ranking comparisons.

## Exactly what we can and cannot claim

**Supported:** An external real app's historical capture shows two successfully returned/paid-status canonical responses with the same generic irrelevant 100-advisory list despite different tasks. FALSUM detects these observed task mismatches and provides a public reproducible tool that does not treat HTTP 200 as quality.

**Not supported:** FALSUM has not registered a new Telegraph evaluator, changed canonical rankings, improved quality on a validated multi-miner holdout, independently verified settlement, recruited an outside expert or customer, or established independent FALSUM adoption. The two responses come from the same reported Miner and cannot establish a comparative Miner rank.

## Why it matters for the Evaluators track

The official [Telegraph evaluation-material rules](https://docs.telegraphprotocol.com/docs/bounties/evaluation-material) value reproducible, grounded measurement **coverage**. A task-specific relevance gate backed by two actual original paid captures reveals a real failure mode in the evaluator supply loop. A future full scoring adapter would need task-specific semantic verification, representative same-Intent comparative outputs and independent gold labels before claiming leaderboard improvement.

[Original external app builder's public report](https://github.com/telegraphprotocol/bounties/issues/187) · [Phase 5Q original one-task capture](PHASE5Q_PUBLIC_TELEGRAPH_RESPONSE_CONTRACT.md).

## Verified actual GitHub execution and original retained evidence

[**Original fully successful public CPU-independent upstream-source CI**](https://github.com/Iniwura/falsum/actions/runs/44857165885) completed on November 21, 2026 after a workflow shell delimiter was corrected (the prior attempt had source-classifier success but the job failed when running its Python post-check). All three Python 3.11–3.13 adversarial jobs and the genuine dual-source live check passed.

- Original GitHub Actions evidence artifact ID: **14688277065**.
- Original artifact ZIP SHA-256: **f6c94d0506e9b39822f6f60a66e3513265846d82d970b722c297e88fbf38dadc**.
- Original aggregate-only JSON SHA-256: **a9c620276ef2404f0571b147ffeef0b1366572c72270976a24864089d84d9ca6**.
- SHA-256 of the ordered 100 original GHSA IDs (same for both external captured responses): **551afad90c90bb2a3717569d33e8caa05c307f925d9f28a4a3039d53e590b2aa**.
- [Permanent source-and-output digest index](../evidence/phase5r-2026-11-21-original-telegraph-two-task-invariance.json).

The two source task SHA-256 digests differ while the ordered 100-GHSA digest is identical. This proves a narrow task-insensitivity observation; no probability, population accuracy or same-request rank increase is inferred.
