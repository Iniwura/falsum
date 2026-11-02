# Phase 3L: PRIVATE evaluation-pool contribution handoff (not a network submission)

**Status:** public, synthetic-only format/transport tooling implemented. **Actual human-authored rows: 0 verified here. Independent expert labels: 0. Network rows uploaded by this tooling: 0. Confirmed eligible rows: 0.** Existing FALSUM draft labels are AI-provisional; the original and Phase 3K models stay blocked.

## Why the submission path changed

The [public Telegraph bounty #96](https://github.com/telegraphprotocol/bounties/issues/96) permits contributing evaluation *preference pairs* for exactly **`SECURITY_REVIEW_GENERAL`** even without an evaluator adapter. Its completion rule is individually uploaded rows becoming **`eligible`** on Anjoman, **not** a GitHub PR, passing local data gate or a status of `accepted` in the HTTP upload response.

The [Anjoman evaluation-material protocol](https://anjoman.ai/docs/scoring/contribute-evaluation-data) specifies JSON Lines with `prompt`, `chosen`, `rejected`, `label_kind: preference_pair`, optional exact `intent_id` and provenance. Uploads use an **EIP-191 signed five-line message** over the SHA256 of the **exact body bytes**, a unique nonce and the network chain ID; Sepolia's documented chain ID is **11155111**. Accepted-to-storage rows initially enter quarantine/admitted stages. **Only `eligible` after a frozen pool snapshot** counts as eligible. The network requires **at least five distinct contributors** before an intent's questions are used. A source URL makes the provenance *attested class*, not a proof of the claim's actual correctness.

The [Telegraph bounty evaluation guidance](https://docs.telegraphprotocol.com/docs/bounties/evaluation-material) forbids publishing actual hidden qualification prompts, expected answers, private diagnostic distributions or customer secrets publicly. FALSUM therefore does **not** commit evaluation rows, hidden answers, reviewer material, signed requests or contributor secrets.

## Delivered in this phase

- [`src/falsum/phase3l_evalpool_preflight.py`](../src/falsum/phase3l_evalpool_preflight.py): standard-library, fully offline `inspect`, `review-index` and `prepare` commands. **No network client, wallet signing method, credential handling or upload.**
- [Adversarial, synthetic-only tests](../tests/test_phase3l_evalpool_preflight.py) plus [Python 3.11/3.12/3.13 CI](../.github/workflows/phase3l-private-evalpool.yml). No real evaluation questions or answers in the test fixtures.
- Strict format checking for the **64 KiB row** and **32 MiB upload**, NFC/whitespace-normalized prompt uniqueness, 85%-similar within-batch prompts, safe HTTPS provenance, exact Intent, plausible similar-length answer pairs, reused stock negative answers, disallowed credential indicators and control characters. This is an **additional local heuristic**, not an implementation of the node's hidden semantic curation or its global duplicate registry.
- A separate *local* per-row review-attestation file, SHA256 bound to the exact JSONL line. Claims are checked for completeness, **not cryptographically authenticated** and not treated as proof of expert identity, independence or semantic correctness.
- A byte-for-byte private JSONL copy, unsigned five-line EIP-191 signing text and **truthful unsubmitted handoff manifest**. Source JSONL and output live only in ignored `private/`.

## Actual operator workflow (no private data goes to GitHub)

Create a local file `private/evalpool/candidates.jsonl`, one **genuinely authored and source-checked human preference pair per line**. **Do not copy FALSUM's AI-provisional research preferences and relabel them as human.** The user must actually write or carefully adjudicate any answers, ensure the worse answer is believable but factually wrong, and verify the live source reference. Do not paste passwords, signed messages, hidden questions or source-private answers into public GitHub comments, the hackathon page or ChatGPT.

A general, *illustrative-only* JSON object shape (NOT an eligible real row) is:

```json
{
  "intent_id": "SECURITY_REVIEW_GENERAL",
  "label_kind": "preference_pair",
  "prompt": "<a real, unique, source-backed security question>",
  "chosen": "<a human-checked better security analysis>",
  "rejected": "<a believable but substantively incorrect analysis of comparable length>",
  "provenance": {
    "source_kind": "human",
    "source_url": "https://github.com/<project>/<actual-public-source>"
  }
}
```

Write that JSON on **one line** when preparing real rows. Keep the line ending LF (`\n`), including after the final row. The CLI requires a provenance URL; a live, working URL and accurate author-origin declaration must be established manually.

**1. Validate without exposing contents:**

```bash
PYTHONPATH=src python -m falsum.phase3l_evalpool_preflight inspect \
  --file private/evalpool/candidates.jsonl
PYTHONPATH=src python -m falsum.phase3l_evalpool_preflight review-index \
  --file private/evalpool/candidates.jsonl \
  --out private/evalpool/review-index.json
```

The local `review-index.json` provides each row's SHA256; its keys are metadata only and must **not** be interpreted as an independent human review. Ask a real reviewer who understands the underlying security question to inspect each actual reference, chosen explanation, wrong explanation, and contradictions. Record their *actual* judgments in a separate file at `private/evalpool/review-attestations.json`:

```json
{
  "schema_version": 1,
  "intent_id": "SECURITY_REVIEW_GENERAL",
  "attestations": [
    {
      "row_sha256": "<first SHA256 from the local review-index>",
      "reviewer_id": "<actual reviewer identifier>",
      "source_and_patch_checked": true,
      "chosen_supported": true,
      "rejected_incorrect": true,
      "conflicts_resolved": true
    }
  ]
}
```

Add one entry **in exact JSONL order** for each row, and set check fields to `true` only after real manual verification. The CLI never invents reviewer responses and intentionally cannot verify that a claimed reviewer is independent or technically qualified. Missing, stale, incomplete or disagreeing checks block packaging.

**2. Prepare a local, unsigned request:**

```bash
PYTHONPATH=src python -m falsum.phase3l_evalpool_preflight prepare \
  --file private/evalpool/candidates.jsonl \
  --review-attestations private/evalpool/review-attestations.json \
  --out-dir private/evalpool/batch-001 \
  --address 0xYOUR_OWN_40_HEX_CHARACTER_ETHEREUM_ADDRESS
```

The address placeholder must be replaced with your real contributor address. The resulting directory contains `PRIVATE-EVALPOOL-ROWS.jsonl` (unchanged bytes), `EIP191-MESSAGE-TO-SIGN.txt` (five lines, **no trailing newline**) and `UNSIGNED-HANDOFF.json` (only counts, hashes and zero-acceptance status). The CLI generates a nonce locally. **Never supply a private key or seed phrase to FALSUM, GitHub, or this chat.** Use a separate wallet or secure local keystore to EIP-191-sign the exact message, then use the official Anjoman **Evaluate** flow or the documented signed node API.

**3. Upload only after genuine review and explicit operator approval:**

The official endpoint is `POST https://devnode.telegraphprotocol.com/api/evalpool/submissions?intent_id=SECURITY_REVIEW_GENERAL&submitter=<your-address>` with headers `Content-Type: application/x-ndjson`, `X-Evalpool-Signature: <actual 65-byte EIP-191 signature>` and `X-Evalpool-Nonce: <nonce on signing message line 4>`. The body must be sent as **`--data-binary @PRIVATE-EVALPOOL-ROWS.jsonl`** so no newline or byte changes invalidate the signature. These details are informational: this repository **does not send the request, sign it or mark it successful**.

**4. Verify actual, not imagined, eligibility:**

In a trusted operator environment, check the real contribution address with the documented public endpoint:

```bash
curl -sS "https://devnode.telegraphprotocol.com/api/evalpool/submissions/mine?submitter=0xYOUR_ADDRESS&intent_id=SECURITY_REVIEW_GENERAL"
```

Read **each** `status` and `reason_code`: `admitted` is not yet `eligible`; `rejected`, `quarantine` or `superseded` do not count. Verify the intent's `active_snapshot`, 5-contributor requirement and epoch activation separately using `GET /api/evalpool/status?intent_id=SECURITY_REVIEW_GENERAL`. Do not publish hidden row hashes/identities if doing so could disclose private evaluation pool material; share with maintainers only the permitted contribution count, status and requested evidence. The bounty is **unfunded**; hackathon prizes and any protocol rewards are separate.

## Honest checkpoint and remaining blockers

This phase implements transport, human-review *attestation shape*, and preflight quality controls. **No actual newly human-authored security questions have been supplied to this tool, no independent reviewer has been authenticated, no signature has been made, and no row has been uploaded or marked eligible.** The public seven-family research corpus and the historical runtime proofs remain useful **source references** for constructing *new* questions, not pre-approved private pool labels. No training or registration is authorized.

The next irreversible step depends on **real human-reviewed private rows and a contributor wallet signature**. The user must deliberately approve and perform an upload; FALSUM can inspect the returned per-row status and help resolve failed rows without exposing their contents.
