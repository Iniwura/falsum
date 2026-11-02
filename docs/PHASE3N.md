# Phase 3N — 20/20 accepted-to-storage, awaiting eligible status

**What was observed:** On 2 November 2026, the operator supplied a screenshot of the signed-in Anjoman **Evaluators → Contribute evaluation material** page for `SECURITY_REVIEW_GENERAL`. Anjoman explicitly reported:

- **"Sent. 20 stored, 0 already there, 0 refused."**
- Under **Your submissions**: **Admitted: 20**, with 20 entries listed.
- No screenshot-confirmed `eligible` rows or frozen snapshot containing these new rows.

This is strong evidence for **successful private upload and initial network curation**, not final acceptance for the bounty. The input's provenance was openly declared `llm`, so the rows should remain identified as AI-assisted/unverified provenance, even if the network later marks them `eligible`. The screenshot, wallet/account details, full prompts, answer pairs, and all row hashes stay **out of the public repository**. The original CI and research-only LoRA release veto are unchanged.

## What has been completed

- **20 of 20 stored, with 0 duplicates or refusals reported by Anjoman at upload.**
- The contributor's row list shows **20 currently admitted**. Per the [official pool status semantics](https://anjoman.ai/docs/scoring/contribute-evaluation-data), `admitted` rows join a frozen pool snapshot at an epoch rollover. Only `eligible` rows count as active pool material for this bounty contribution.
- At the time of the screenshot, the public pool already showed the five-contributor threshold met; this is **aggregate intent information**, not proof of ownership, payment or FALSUM qualification.
- FALSUM Phase 3N's [offline verifier](../src/falsum/phase3n_eligibility_guard.py) can consume an operator-saved `/api/evalpool/submissions/mine` response and produce only status counts, never wallet address, row hashes, case IDs or hidden answer content.
- Its synthetic-only regression tests protect against falsely promoting `admitted`, `quarantine`, `rejected`, `superseded` or `revoked` to `eligible`, as well as incomplete API pagination or row mismatches. CI requires no account tokens or wallet secrets.

## How to verify after the epoch rolls over

Use [Anjoman Evaluate](https://anjoman.ai/dashboard/eval) and scroll to **Your submissions for SECURITY_REVIEW_GENERAL**. A successful rollover should show entries changing from `Admitted` to `Eligible`. If entries are `Rejected` or `Quarantine`, inspect the **reason code**. Do not resend an identical file; the network's duplicate rules can keep an existing case.

Alternatively, on the operator's own machine, save the **private** JSON returned by:

```
GET https://devnode.telegraphprotocol.com/api/evalpool/submissions/mine?submitter=<your-own-public-contributor-address>&intent_id=SECURITY_REVIEW_GENERAL
```

Do not paste the private JSON, hidden row identifiers, signature or the account screenshot into a public issue. To reduce the full, untruncated local result (assuming exactly 20 rows in the account):

```bash
PYTHONPATH=src python -m falsum.phase3n_eligibility_guard \
  --mine-json private/evalpool/anjoman-mine.json \
  --expect-rows 20 \
  --out private/evalpool/status-summary.json
```

If this contributor has more than 20 historical rows, omit `--expect-rows 20` and ensure all API pages are included. If the endpoint or schema is unavailable, rely on the trusted Anjoman UI and leave the status **unknown** rather than inventing zero.

The reduced file contains count and reason-code aggregates only. No user address, row hash, case ID, hidden prompt, answer or reviewer data can appear in the generated summary. The reducer is **not an online verifier**; it trusts the locally saved API response, and the browser or CLI operator must confirm that the response really came from the intended node.

## Next competition and bounty step

The [Telegraph SECURITY_REVIEW bounty #96](https://github.com/telegraphprotocol/bounties/issues/96) states that an individual contributor's evaluation-material portion counts when their rows become `eligible`. **Do not write `/submit` yet** while all 20 are merely `admitted`. Continue to post required `/progress` updates every 72 hours until actual submission.

Once `eligible` is confirmed, prepare a public GitHub comment **without hidden question/answer content**, stating:

- `/submit` for `SECURITY_REVIEW_GENERAL` evaluation material
- The **public contributor wallet address** taken directly from the user's signed Anjoman account (user approval before publishing it)
- The count of rows showing `eligible`, and the intent-specific contribution status
- A link to this reproducible public repository and the official bounty issue
- **No claim of evaluator module registration**. These are distinct paths.

The maintainer still must verify the bounty submission. The hackathon final entry is **separate**, and stronger winning evidence includes eligible rows, source-verifiable public methodology, realistic dependency/API/secrets coverage, and a polished demo with no hidden evaluation material disclosed.

**Current gate:** 20 admitted, **0 currently verified eligible**, **0 registered evaluator modules**, **0 bounty /submit claims**. No invented model success or rewards.
