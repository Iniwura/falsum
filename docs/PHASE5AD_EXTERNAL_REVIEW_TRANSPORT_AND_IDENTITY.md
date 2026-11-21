# Phase 5AD — respond to the independent developer's transport and identity challenge

**Telegraph Season II Evaluators · external technical feedback received 21 November 2026**

## Attribution and evidence status

The project owner provided detailed technical feedback attributed to a developer outside the FALSUM community. The reviewer stated they inspected original upstream Git blobs, six reviewed advisories and code, but **did not complete an independent forked GitHub Actions run** or run the proposed direct-request counterexample. No public reviewer identity, dated public review URL, reviewer's fork SHA or externally attributable run receipt accompanied this report. Therefore this document credits the **substantive external critique supplied to the owner**, but records **zero verified independent fork replays, zero independently authenticated expert AppSec labels and zero accepted external FALSUM integrations**. An outside human analysis can still be valuable without being expert gold.

The detailed critique is not copied verbatim into source or training data. No private reviewer details or permissions are inferred.

## 1. The high-priority route confusion is real

The prior Phase 5AB `inspect()` classified a record as `CANONICAL_ROUTED_REQUEST_AND_RECEIPT` when `request == {"intent":"SECURITY_REVIEW_GENERAL","params":{"target":"..."}}` and `receipt.intent == "SECURITY_REVIEW_GENERAL"`. It **ignored the top-level original capture `url`**.

This was a real semantic bug for **new/unseen captures**. Under official Telegraph V2, both `POST /engine/v1/ask` (network-routed) and `POST /engine/v1/ask/{minerId}` (direct) can take a canonical `intent + params` body. A direct request with a valid canonical body and matching receipt is **not** a network-routed request.

The fix requires the original source-verified URL to be **exactly** `https://devnode.telegraphprotocol.com/engine/v1/ask` as well as matching request/receipt metadata before assigning the routed classification. `https://devnode.telegraphprotocol.com/engine/v1/ask/77003` remains **direct** even with an otherwise identical canonical body and receipt. A missing, differently hosted, malformed, redirected-looking, query-augmented or ambiguous URL is rejected, not assumed routed. This strict capture-origin check is deliberately **historical and bounded**, not an arbitrary Telegraph endpoint support promise.

This is validation of the **URL recorded in a Git-authenticated historical file**, not independent proof that HTTP was actually sent to that URL. FALSUM makes no live-network trace, payment settlement or Miner routing proof claim from a published capture alone.

**Constructed counterexample:** retain canonical request, receipt Intent and Miner body; alter only the capture's `url` from unqualified `/ask` to `/ask/77003`. The old classifier falsely placed it among routed records. The changed classifier assigns the existing direct-with-canonical-receipt category; its canonical-routed request digest is not eligible for multi-Miner comparisons. Independent source claims still require original Git blob authentication.

**Original historical census is unchanged.** The 12 pinned outside files themselves have **2 recorded unqualified general-route URLs and 10 recorded direct endpoint URLs**, with 2 matching canonical routed request+receipt records, 2 direct with canonical receipt, 6 successful different-Intent receipts and 2 failed responses. The expected identical canonical-request cross-reported-Miner pairs remain zero. The 12 **original immutable Git blobs and previously preregistered source protocol are not changed** by this fix. A replacement or modified original file still fails the frozen Git blob SHA-1 checks.

## 2. Two different Miner ID namespaces

Telegraph's [official x402 inference documentation](https://anjoman.ai/docs/using/x402-inference) explicitly describes `receipt.miner` as an **on-chain registration identifier** and distinguishes it from the `miner_id` in the result body, which denotes the ID selected through `/engine/v1/ask/{minerId}`. The [Telegraph MCP route documentation](https://github.com/telegraphprotocol/telegraph-mcp/blob/main/docs/architecture.md) confirms that the general and direct endpoints are distinct.

Example original source-reported values:

| Original original-capture example | `body.miner_id` | `receipt.miner` | Interpretation |
| --- | --- | --- | --- |
| Routed security diff | 77003 | 3854 | Different namespace values, NOT proof of forged output |
| Direct lodash capture | 190048 | 4787 | Different namespace values, NOT proof of forged output |

FALSUM now exports both values **as explicitly unverified reported identifiers** and never equates them, or infers their mapping or ownership independence. If a direct URL specifies `/ask/190048`, the response body's reported `miner_id` must match `190048` for **that recorded direct request** to be accepted; a deliberately substituted direct-response body ID fails closed. An unrelated receipt registration ID is **not** required to equal either value. A numeric registration ID proves neither on-chain membership nor mapping without actual independent registration/receipt verification.

For routed traffic, the returned body's reported Miner ID is **unverified selection metadata**, not independently established registration identity. A hypothetical multi-Miner candidate is never treated as a fair score or provider-ownership proof.

## 3. Historical six-reference filtering is not an unseen-advisory evaluator

The developer also correctly identified that the existing Phase 5Z/5AA contract is a **strict snapshot** for one package/version and an exact six-reference historical response. A revised result with only five already-filtered references, a seventh reference, an unknown GHSA, multiple affected intervals, conflicting sources, a prerelease or an updated advisory does **not** inherit historical validation. Some such inputs deliberately fail closed.

That conservative failure behavior is intentional for the historical proof, but is a legitimate **adoption and generalization limitation**. Do not claim one six-reference snapshot is a generic advisory scanner, a false-positive/false-negative estimate, a complete live vulnerability database or a trained network evaluator.

A separate new evidence-driven mode would need its own policy, provider metadata, exact package ecosystem version semantics, mixed source versions, per-reference outcomes (`VERIFIED_APPLICABLE`, `VERIFIED_INAPPLICABLE`, `UNKNOWN`, `INSUFFICIENT_EVIDENCE`), protected handling of unknowns and separate held-out tests. It must not silently weaken or bypass the frozen historical reproduction gate. No such generalized evaluation or independently labeled security-accuracy score is claimed in this phase.

## 4. Reproducibility and outside-review proof

The reviewer proposed retaining the original upstream Git commit, the independent fork and commit SHA, local modifications, the actual workflow run URL, the output hashes and any unexpected observations. The [independent reviewer guide](INDEPENDENT_REVIEWER_START_HERE.md) and [public issue form](https://github.com/Iniwura/falsum/issues/new?template=independent-public-reproduction.yml) now request these records. A clean author-controlled GitHub run still does not count as a non-author independent review.

## Regression acceptance

The [Phase 5AB original-source CI workflow](../.github/workflows/phase5ab-original-receipt-comparability.yml) must pass:
1. Constructed canonical payload + direct URL -> explicitly direct, **not** a routed-eligible hash.
2. Missing, wrong-host, altered endpoint or query-string URLs -> fail closed.
3. Direct endpoint / body Miner ID substitution -> fail closed.
4. Distinct receipt-registration and response-body Miner IDs -> valid separate reported namespaces, **not** a forged-identity assertion.
5. Actual upstream original 12 Git blobs -> exact historical partition remains unchanged.
6. Existing Python and browser release/regression checks -> no collateral break.

Passing these tests is evidence that the **identified implementation gap was addressed** for the bounded original-source protocol. It does **not** prove anonymous reviewer identity, an independent forked workflow, expert AppSec correctness, on-chain receipt authenticity, unseen advisory generalization, network quality improvement or hackathon submission.
