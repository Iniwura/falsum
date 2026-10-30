# Evidence ledger format

The input is one JSON object with `schema_version: 1`, an `evidence` array, and a `pairs` array. Neither a filename nor `review_status` is proof of a valid security claim.

An evidence record must include: `id`, `ecosystem`, `package`, `version`, `advisory_id` (CVE/GHSA), `verdict` (`affected`, `unaffected`, or `conditional`), `source_url` (HTTPS), `source_excerpt`, `review_status` (`draft`/`reviewed`). A reviewed record also needs `reviewer`, `reviewed_on` (ISO calendar date), and `source_sha256` (hex digest of archived source bytes).

A preference pair must include: `id`, `intent_id: SECURITY_REVIEW_GENERAL`, `split` (`train`, `validation`, `holdout`), `review_status`, `prompt`, `chosen`, `rejected`, and `evidence_ids` referencing reviewed evidence. Reviewed pairs also need `reviewer` and `reviewed_on`.

Export emits only reviewed pairs from the requested split as JSONL `{ "prompt": ..., "chosen": ..., "rejected": ... }` for the official V2 trainer. The gate fails on identical answers, greatly unbalanced lengths, repeated negatives, near-duplicate prompts, and reuse of an advisory across splits.

## Ground truth protocol

1. Fetch the advisory from its publisher or another authoritative primary source. Archive bytes and their SHA-256.
2. Check the package ecosystem, exact version boundary, CVE/GHSA identity, known deployment or exploit preconditions, and fix.
3. Record the source excerpt and independent reviewer identity. Mark `reviewed` only after source verification, not from an LLM assertion.
4. Write plausible, equally detailed chosen and rejected responses; avoid lexical clues and varied boilerplate.
5. Keep all cases sharing the same `(ecosystem, package, advisory_id)` in one split. Never rephrase the same advisory into a hidden test split.
6. Run FALSUM's gate and the upstream kit's `--check-data` independently. Network submission has additional eligibility rules that this code cannot prove.

## Deliberate limits

This gate does not download advisories, inspect the original source snapshot, validate semantic vulnerability truth, enforce that prompts fit ModernBERT's 512-token window, or report Telegraph eligibility. The Phase 2 verifier must add source retrieval and digest checking. A public URL can change; keep an immutable snapshot. An affected-version label is not always an exploitable deployment.
