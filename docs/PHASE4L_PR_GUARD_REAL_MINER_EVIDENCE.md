# Phase 4L — PR Guard paid-response evidence, source-locked and unscored

**Telegraph / Anjoman Season II · Evaluators / SECURITY_REVIEW_GENERAL · November 17, 2026**

This phase takes a concrete external integration problem seriously without inventing a fix or a scientific model-accuracy result.

## The external application problem

The independent Season II app builder [PR Guard](https://github.com/anvithagowda098/pr-guard) reported in [Telegraph issue #187](https://github.com/telegraphprotocol/bounties/issues/187) that canonical `SECURITY_REVIEW_GENERAL` requests were routed to miner **77003**, whose answer contained a 100-item GitHub Security Advisory feed unrelated to the supplied code target. PR Guard also recorded paid reference answers for the same diff from a direct **Verity #5530** request and a routed **ChainSight #302** request using a **different Intent**.

These captures help establish **why a better evaluator and target-sensitive ranking would matter**. They do not establish that FALSUM has fixed the network's route selection or that a FALSUM evaluator is running on the network.

The external builder disclosed ownership of **PR Guard Sentinel #731001** and specifically requested its exclusion from scoring. Phase 4L **does not download, load, score, compare or train on any #731001 answers**.

## What was actually pinned

Source snapshot: [PR Guard at `99d2e3c93890a8fc083947bde4f21217516b7a5f`](https://github.com/anvithagowda098/pr-guard/tree/99d2e3c93890a8fc083947bde4f21217516b7a5f).

| Pinned public response capture | Input / route | Structural outcome and limit |
| --- | --- | --- |
| [Miner 77003 routed security diff](https://github.com/anvithagowda098/pr-guard/blob/99d2e3c93890a8fc083947bde4f21217516b7a5f/test/fixtures/miner-responses/ROUTED/security-review-diff-77003-off-target.json) | Canonical `SECURITY_REVIEW_GENERAL`, `params.target` | Paid response capture with `result_shape: raw` and **100 GHSA entries**, not a review of the supplied diff |
| [Verity #5530 direct security review](https://github.com/anvithagowda098/pr-guard/blob/99d2e3c93890a8fc083947bde4f21217516b7a5f/test/fixtures/miner-responses/SECURITY_REVIEW_GENERAL/5530-review-sqli-eval-diff-200-paid.json) | Direct `/v1/intent` call to the `SECURITY_REVIEW` family | Paid capture reports **two target-relevant heuristic rule identifiers** for SQL injection and dynamic execution; **not** the same canonical routed request shape |
| [ChainSight #302 routed code review](https://github.com/anvithagowda098/pr-guard/blob/99d2e3c93890a8fc083947bde4f21217516b7a5f/test/fixtures/miner-responses/ROUTED/code-review-sqli-eval-diff-302-intent.json) | Canonical `CODE_REVIEW_GENERAL`, `params.code` | Paid capture includes source-related findings and `result_shape: intent`; **different Intent** and therefore contextual only |

The three JSON files encode **the identical raw 311-character diff string**, tested by an exact SHA-256 input digest equality. The comparison does **not** treat the original old Foundation model's **5/8** on different source-fix cases as comparable with any of these paid responses.

**Git source authenticity:** `src/falsum/phase4l_external_receipt_evidence.py` reads exactly three immutable GitHub raw file URLs at the pinned commit, recomputes the true Git blob SHA-1 for each byte stream, and rejects changes in request Intent, miner, response shape, payment-capture flags, advisory-list structure, relevant rule identifiers or exact diff identity. The output does **not** include the raw response JSON, question text, public payer address, third-party miner result or any internal hidden evaluation rows.

**Not blockchain authenticity:** The recorded response metadata includes `payment.success: true` and public signal/receipt hashes, but this is **unverified capture evidence**, not an independent onchain/settlement check. The response miner IDs and the receipt's `miner` fields differ in the checked captures. In the Verity file, the recorded receipt `intent` field is `FACT_CHECK_GENERAL` despite the direct request declaring `SECURITY_REVIEW`. The source does not establish whether that is expected payment-proxy semantics or a metadata error. Do not call these fields fraudulent or fully verified without checking Telegraph's authoritative receipt specification and source ledger.

## Reproduce

Python 3.11–3.13. From the FALSUM repository root:

```bash
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_phase4l_external_receipt_evidence.py' -v
PYTHONPATH=src python -m falsum.phase4l_external_receipt_evidence --out phase4l-new-audit.json
```

On Windows PowerShell set `$env:PYTHONPATH = 'src'` before the second command. Use a new output path on every run: existing results are never overwritten.

The dedicated [GitHub Actions workflow](../.github/workflows/phase4l-external-receipts.yml) executes offline adversarial tests, downloads the three *public* pinned external files read-only, validates all source bytes and emits a retained **aggregate-and-links-only** artifact. If the external source cannot be verified, the command exits nonzero and **does not publish a false success report**.

## What can and cannot be claimed

**Supported by public capture evidence, subject to independent reproduction:**

- A real app developer reported a concrete integration blockage for `SECURITY_REVIEW_GENERAL`.
- A captured paid canonical route returned an advisory feed rather than a target-specific review.
- Different request routes for the same diff yielded two target-relevant reference responses.
- FALSUM can independently recompute structural comparisons from pinned public fixture bytes without copying third-party bodies into its public dataset.

**Not supported:**

- That FALSUM's old LoRA can rank these miners, or that FALSUM trained or registered a superior scoring adapter.
- That any captured receipt hash has been cryptographically verified or paid-onchain settlement independently authenticated.
- That #5530 and #302 can be used as equal same-Intent ranking candidates; #302 uses a different Intent and #5530 a different direct request envelope.
- That target-relevant answer structure is independently verified AppSec gold. Vulnerability severity, evidence correctness, finding omissions and real deployed exploitability require qualified external adjudication.
- That the external developer endorsed FALSUM, adopted its evaluator, or granted rights to republish full response material or train on their fixtures.
- That the existing [20 reported Eligible Anjoman rows](PHASE4K_LIVE_SUBMISSION_READBACK.md) have been independently resolved or that bounty #96 has been formally accepted.

## Path from this case study to a genuine Evaluators contribution

1. Receive an explicit approval for expanded reuse or keep **immutable links only**. Preserve original author credit and exact source commit; do not assume copying/training rights from a public repository.
2. Precommit a **realistic, task-specific**, reviewable rubric before scoring additional examples: target adherence, response contract, precise source citations, material omissions, uncertainty and abstention.
3. Independently adjudicate real security claims with at least one qualified reviewer and evidence of expertise. Accept dissent and ABSTAIN; never label a response "gold" solely because it was a paid miner response.
4. Evaluate permitted miner responses **on the same Intent and identical task**, avoiding hidden evaluation content, contributor-owned Sentinel answers, and leakage between training and holdout.
5. Reproduce actual official Foundation scoring and compare against fair baselines. Claim improvement only if the new trained evaluator genuinely outperforms them on independent holdout cases.
6. Verify any network adapter registration separately under official terms. Do not suggest that a link-only research comparison resolves PR Guard's routing problem or satisfies the official final entry requirements by itself.

FALSUM remains a **solo** project, and the external builder is credited as an independent source of example receipts, not described as a teammate, independent expert labeler or formal partner.
