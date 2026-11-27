# Phase 5BQ — source-backed Anjoman pair preparation

The V2 packet prepares **14 candidate preference pairs** from the immutable
Phase5BO advisory and package-registry snapshots. It is deliberately not an
Anjoman submission: every row is marked `CANDIDATE_NOT_SUBMITTED`, with human
adjudication, network eligibility and maintainer acceptance all false.

Each pair contains:

- a version-applicability question;
- a source-resolved better answer and a deliberate competing boundary answer;
- advisory and registry URLs, SHA-256 digests and snapshot paths;
- exact package-version existence evidence;
- deduplication keys and quality checks; and
- an explicit scope limit that does not claim exploitability; and
- a separate exact JSONL row using `SECURITY_REVIEW_GENERAL` and honest
  `generated`/unverified provenance.

The packet is generated without fetching new evidence:

```text
PYTHONPATH=src FALSUM_PHASE5BO_NODE_PATH=.phase5bo-node/node_modules \
  python -m falsum.cli prepare-anjoman-pairs \
  --out data/phase5bq-anjoman-pair-candidate-packet-v2.json \
  --jsonl-out data/phase5bq-anjoman-upload-preview-v2.jsonl
```

The reference labels are independently re-resolved from the pinned snapshots
and must match the frozen Phase5BO labels. Duplicate normalized questions,
duplicate pair fingerprints, missing registry versions, missing provenance or
opaque answer-token selection fail closed. V2 additionally audits the official
prompt near-duplicate threshold, paired answer lengths, exact answer-template
repetition, rejection-label leakage and four simple shortcut baselines. The
corrected packet contains plausible competing reviews without self-described
error markers; length, error-keyword, prompt-answer lexical-overlap,
recurring-template and punctuation baselines are each at or below 60%. The
packet does not upload rows, claim Anjoman eligibility, prove human AppSec gold
or establish a ranked Telegraph evaluator.

The historical material Intent is `SECURITY_REVIEW_GENERAL`; the authoritative
family mapping to `SECURITY_REVIEW` is recorded in [bounty #96](https://github.com/telegraphprotocol/bounties/issues/96)
and [INTENTS.md](https://github.com/telegraphprotocol/bounties/blob/main/docs/INTENTS.md).
Mission-specific supporting records remain separate under [Model Economy
#198](https://github.com/telegraphprotocol/bounties/issues/198) and [Web3
Native & DeFi #202](https://github.com/telegraphprotocol/bounties/issues/202).

The owner-gated upload procedure, exact signing message, read-only status
checks and progress-message drafts are in
[PHASE5BQ_ANJOMAN_UPLOAD_CHECKLIST.md](PHASE5BQ_ANJOMAN_UPLOAD_CHECKLIST.md).
