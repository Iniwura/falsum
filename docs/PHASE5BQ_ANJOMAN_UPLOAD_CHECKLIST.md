# SECURITY_REVIEW_GENERAL upload checklist

This is an owner-gated procedure for the V2 candidate packet. It is not an
upload authorization. The packet is generated material with public source URLs
and `source_kind: generated`. Under the current Anjoman rules, `generated` is
always classified as unverified even when `source_url` is public. Never
describe these rows as human-adjudicated, attested, eligible or
maintainer-accepted before the network confirms those facts.

## Official contract

The target is the child Intent `SECURITY_REVIEW_GENERAL`. The authoritative
family mapping is `SECURITY_REVIEW` in [bounty #96](https://github.com/telegraphprotocol/bounties/issues/96)
and [INTENTS.md](https://github.com/telegraphprotocol/bounties/blob/main/docs/INTENTS.md).
The [official Anjoman contribution documentation](https://anjoman.ai/docs/scoring/contribute-evaluation-data)
specifies one JSON object per JSONL line:

```json
{"prompt":"...","chosen":"...","rejected":"...","label_kind":"preference_pair","intent_id":"SECURITY_REVIEW_GENERAL","provenance":{"source_kind":"generated","source_url":"https://..."}}
```

`prompt`, `chosen` and `rejected` are required. `chosen` and `rejected` must
be nonempty and different. `label_kind` is `preference_pair`; when present,
`intent_id` must equal the upload Intent. The V2 packet uses public advisory
URLs as provenance but deliberately keeps `source_kind` as `generated`, which
the official documentation treats as unverified regardless of the URL. The
current documentation defines `eligible` as a network/freeze state and does
not state that every unverified row is automatically ineligible. Therefore the
only defensible procedure is to send the true generated provenance, never
relabel it as `attested`, and report the actual returned `provenance_class`,
`status` and `reason_code`. This packet has not been uploaded, so it has no
network eligibility result.

The V2 quality gate also records the official prompt and answer length bounds,
Unicode-NFC/casefold/whitespace normalization, the 85% near-duplicate prompt
threshold, paired-length comparability, exact answer-template diversity and
four shortcut audits. The balanced packet has no rejected-answer
error-indicating markers; length, prompt-answer lexical-overlap, recurring
template and punctuation baselines all remain at or below 60% (the observed
maximum is recorded in the packet). It keeps the original V1 packet unchanged
as historical material.

## Reproduce and inspect locally

Run from a clean checkout with the pinned Phase5BO Node dependency available:

```powershell
$env:PYTHONPATH = 'src'
$env:FALSUM_PHASE5BO_NODE_PATH = (Resolve-Path '.phase5bo-node/node_modules').Path
python -m falsum.cli prepare-anjoman-pairs `
  --out review/phase5bq-anjoman-pair-candidate-packet-v2.json `
  --jsonl-out review/SECURITY_REVIEW_GENERAL-v2.jsonl
```

Inspect every prompt, chosen answer, rejected answer, source URL, package
version and quality-audit field. The command only writes new local files; it
does not sign, POST, pay, or change network state. The checked-in V2 preview is
an unsigned review artifact, not an upload receipt.

Before any upload, perform only the documented read-only checks. On the
documented test node, the status endpoint is:

```text
GET https://devnode.telegraphprotocol.com/api/evalpool/status?intent_id=SECURITY_REVIEW_GENERAL
GET https://devnode.telegraphprotocol.com/api/evalpool/submissions/mine?submitter=<owner-address>&intent_id=SECURITY_REVIEW_GENERAL
```

Do not expose the owner address in public reports unless the owner approves it.
`admitted` or an HTTP success is not `eligible`; each row must be checked after
the network's quarantine/freeze process. The pool-wide five-contributor rule
is separate and must be read from the current status response. A successful
POST would not change the packet's generated provenance class or establish
human adjudication.

## Owner-only signing and upload sequence

The official documentation describes the testnet node and chain ID `11155111`.
The upload has no documented fee or bond, but it requires an owner-controlled
EIP-191 signature. No private key, seed phrase or unrestricted signer is ever
placed in this repository, CI, chat or a shell history.

1. Freeze the exact JSONL bytes after review and compute the lower-case SHA-256:

   ```powershell
   (Get-FileHash review/SECURITY_REVIEW_GENERAL-v2.jsonl -Algorithm SHA256).Hash.ToLower()
   ```

2. Generate a fresh 8-128 character nonce and construct the exact message,
   with no extra line or whitespace:

   ```text
   Telegraph eval-pool submission v1
   intent_id: SECURITY_REVIEW_GENERAL
   body_sha256: <lower-case-body-sha256>
   nonce: <fresh-nonce>
   chain_id: 11155111
   ```

3. Have the owner review the exact Intent, endpoint, submitter address, body
   hash, nonce, chain ID, every row and the generated/unverified provenance.
   The owner signs this message with EIP-191 personal-sign in the approved
   wallet. FALSUM does not receive or store the private key.

4. Only after that explicit approval, send the unchanged bytes to the official
   endpoint with the owner address, 65-byte signature and nonce. Use
   `--data-binary` so the signed bytes cannot be rewritten:

   ```powershell
   curl.exe --fail-with-body --silent --show-error `
     -X POST `
     'https://devnode.telegraphprotocol.com/api/evalpool/submissions?intent_id=SECURITY_REVIEW_GENERAL&submitter=<owner-address>' `
     -H 'Content-Type: application/x-ndjson' `
     -H 'X-Evalpool-Signature: <owner-eip191-signature>' `
     -H 'X-Evalpool-Nonce: <fresh-nonce>' `
     --data-binary '@review/SECURITY_REVIEW_GENERAL-v2.jsonl'
   ```

5. Record the response without treating it as eligibility. Re-run the two GET
   checks, retain each returned row `status` and `reason_code`, and only report
   rows as eligible if the returned status is exactly `eligible`. Do not call
   `/submit` for bounty completion until the official workflow shows the
   required eligible material and the owner separately approves that action.

## Exact mission progress drafts

These are drafts for owner review, not posted claims.

For [Model Economy #198](https://github.com/telegraphprotocol/bounties/issues/198):

```text
/progress FALSUM prepared a corrected, unsigned SECURITY_REVIEW_GENERAL JSONL candidate packet from immutable public advisory and registry snapshots. It contains 14 source-backed dependency-security preference pairs with exact package/version/advisory evidence, ecosystem-native PEP 440 or strict npm SemVer semantics, remediation actions, and explicit no-exploitability scope limits. Reproducible checks cover source hashes, exact registry existence, normalized-prompt deduplication, near-duplicate prompts, answer-template repetition, comparable answer lengths, and four shortcut baselines at or below 60%: length, error-indicating keywords, prompt-answer lexical overlap, recurring templates and punctuation style. This is generated/unverified material, not human adjudication, and not a live mission-delivery, adoption or payment claim. Its network eligibility is unknown because it has not been uploaded; the current rules require reporting the actual returned status and provenance class without relabeling. The next owner-gated step is review and, if approved, upload to SECURITY_REVIEW_GENERAL.
```

For [Web3 Native & DeFi #202](https://github.com/telegraphprotocol/bounties/issues/202):

```text
/progress FALSUM contributes a repeatable, source-bound SECURITY_REVIEW triage route for authorized or fixture inputs: resolve affected-version evidence, distinguish supported findings from unsupported or ambiguous evidence, and return bounded BLOCK/REMEDIATE or HOLD/REVIEW actions with cited source material. The current Anjoman packet is generated/unverified candidate material and has not been uploaded or accepted. This does not claim token-risk integration, escrow, payment, trading, exploitation, production delivery or independent adoption. Any future mission evidence must preserve the request, response, source, uncertainty, action and receipt boundary and must not authorize exploitation or real-money activity.
```

## Owner approval checklist

- [ ] Confirm the target is exactly `SECURITY_REVIEW_GENERAL`, not merely the
  `SECURITY_REVIEW` family.
- [ ] Review the V2 packet and all 14 JSONL rows, including every rejected
  answer and source URL.
- [ ] Confirm `source_kind: generated` and the not-human/not-eligible boundary.
- [ ] Confirm the body hash is computed from the exact bytes that will be sent.
- [ ] Confirm the owner address, test node endpoint and chain ID `11155111`.
- [ ] Confirm no private key, seed phrase, unrestricted signer permission or
  payment is involved.
- [ ] Confirm the fresh nonce and EIP-191 message line-for-line.
- [ ] Explicitly authorize the single POST, then separately approve any
  official `/submit` action after row eligibility is independently verified.
- [ ] After upload, retain response JSON and read-only status evidence; report
  `eligible` only for rows whose returned status is exactly `eligible`.
