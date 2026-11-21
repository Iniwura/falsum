# Phase 5Q — Measure a real Telegraph routing-quality failure, without inventing rankings

**FALSUM · Evaluators / SECURITY_REVIEW_GENERAL · Original external public capture provenance frozen on 21 November 2026**

## The falsifiable problem

[PR Guard's public Telegraph integration report](https://github.com/telegraphprotocol/bounties/issues/187) recorded a **paid HTTP 200 canonical SECURITY_REVIEW_GENERAL response** to a 311-character JavaScript diff. The routed Miner 77003 returned a **100-item general GitHub Security Advisory feed** rather than a review of the target lines in src/users.js. A naïve scoring or health check based only on successful HTTP/payment metadata would accept this irrelevant result.

**FALSUM Phase 5Q implements an executable relevance gate that rejects that original off-target answer**, even though it is reported paid and HTTP 200. The original public source is immutably Git-blob verified on every execution. This is **one authentic external capture**, not 100 independent negative quality judgments or a network improvement demonstration.

The comparison has an essential fairness rule. Two other public PR Guard capture fixtures use the identical raw diff, but **different request conditions**:
- Direct Verity #5530: SECURITY_REVIEW family and /v1/intent direct envelope, not identical canonical routed task;
- Routed ChainSight #302: CODE_REVIEW_GENERAL, not the same Intent.

FALSUM excludes them from any equivalent same-Intent miner ranking comparison. PR Guard's owner-operated Sentinel Miner #731001 is explicitly excluded. No third-party response bodies are published, scored as expert gold, or used for training.

## Pre-implementation integrity and original public proof

The complete initial study contract was [frozen](../data/phase5q-preimplementation-telegraph-target-contract.json) in commit **5c3d692c2a1b4c46a64e49bdbf9a15e8f9efa6cd**, Git blob SHA-1 **7c88b3508b6e8cfb842c51b68dc6224b130a0d64**. It predates the Phase 5Q gate implementation, tests or execution.

Three approved public source artifacts are retrieved **only** from PR Guard at commit 99d2e3c93890a8fc083947bde4f21217516b7a5f, with the original byte-level SHA-1 checks preserved in [Phase 4L source verifier](../src/falsum/phase4l_external_receipt_evidence.py). Phase 5Q reuses the same authenticated fixture routine rather than duplicating sources or trusting user-provided labels.

## Use it

With Python 3.11+, public internet, no keys, wallet or paid Telegraph request:

~~~bash
git clone https://github.com/Iniwura/falsum.git
cd falsum
python -m pip install --no-deps -e .

# Real external PR Guard source captures: download, Git blob verify,
# verify original same diff and request intent then publish aggregate-only report.
falsum audit-telegraph-target --out original-task-relevance.json

# For another locally available, public-safe response:
falsum audit-telegraph-target \
  --request-json my-request.json \
  --response-json my-miner-body.json \
  --out local-task-relevance.json
~~~

The local envelope is the actual canonical shape: request JSON with `intent: SECURITY_REVIEW_GENERAL`, `params.target` containing a bounded unified diff, and response body JSON with a `result` field. Unrecognized Intent or a different request schema is **not comparable**; missing diff/source data fails closed. No direct Telegraph purchase is made by this command.

There are three meaningful outcomes for canonical tasks:
- **OFF_TARGET_ADVISORY_FEED**: a generic bulk advisory response rather than target-diff review.
- **INSUFFICIENT_EVIDENCE**: no traceable structured finding; that does **not** establish the response is incorrect or worthless.
- **REVIEW_STRUCTURE_PRESENT_NOT_SEMANTIC_GOLD**: a reported finding includes exact added source line, file and new-line number with an explanation. This is **traceability only**, never a security-claim correctness verdict, trusted gold label, model quality score or license to rank miners.

For other Intents or direct request routes, the tool emits **NOT_COMPARABLE** rather than misrepresenting the capture as a fair head-to-head contest. The same-source line test can be gamed by copying it; do not use positive statuses as a valid reward signal without external adjudication.

## Threat model, failure cases and baseline

Tests deliberately attempt to pass an HTTP 200 paid response that is an irrelevant GHSA feed; a keyword-padded advisory list; a response that merely echoes the entire target diff; a polished unsourced security claim; an incorrect file path or impossible line; and cross-Intent/cross-envelope comparisons. The original result must remain off-target even if unrelated advisory entries mention the file name.

The naive **HTTP200/paid** baseline accepted the one original unrelated public canonical result. The Phase 5Q gate detects that mismatch. Neither a single captured response nor synthetic perturbation scores create a general model-accuracy metric. The correct claim is *one original paid canonical route's task-relevance failure was reproducibly detected*.

The original captured receipt metadata includes inconsistencies reported in Phase 4L. We do not independently verify paid settlement, escrow or onchain state from those fixture flags.

## Evidence required before claiming success

Inspect [Phase 5Q GitHub Actions](../.github/workflows/phase5q-telegraph-task-relevance.yml). It must run Python 3.11–3.13 adversarial controls and a genuine read-only fetch of all three exact pinned external files. The CI report publishes only original links, digests, safe role/Intent comparisons and the measured task-relevance outcome. No third-party request, source code or full response text is reproduced.

**Explicit nonclaims:** not a deployed WASM or safetensors scoring module, not a registered canonical network Evaluator, not independent AppSec semantic ground truth, not actual new FALSUM-paid Telegraph network traffic, not proof FALSUM improved mainnet/testnet rankings, not customer adoption, and not an official H2 entry.

## Next necessary competitive step

This is a meaningful public-target-relevance criterion that model scoring needs, but to establish a **ranking-quality gain**, compare multiple genuinely independent Miner outputs under the **same exact canonical Intent/request conditions**, with permitted usage and independent correctness adjudication. Obtain authorization or authentic public records; do not fabricate comparable results or score published cross-Intent answers as peers.

The official [Telegraph evaluation-material guidance](https://docs.telegraphprotocol.com/docs/bounties/evaluation-material) accepts defensible coverage evidence and reproducible processes; network admission, artifact registration and final hackathon judging are separate decisions.
