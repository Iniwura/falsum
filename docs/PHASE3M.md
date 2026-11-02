# Phase 3M — honest AI-assisted evaluation drafts and live public pool observability

**Scope:** This phase corrects FALSUM's overly restrictive assumption that all eligible preference-pair uploads must be human-origin. The [current Anjoman protocol](https://anjoman.ai/docs/scoring/contribute-evaluation-data) permits `source_kind: llm`, `synthetic`, `generated`, or `model` but treats these rows as **unverified provenance**, even when they link to a real source. The protocol can still subject them to its independent per-row quality and freeze checks. Do **not** relabel AI-assisted draft answers as human or claim that unverified means admitted/eligible.

## Actual delivered functionality

The unchanged **human-origin** Phase 3L preflight mode still requires SHA256-bound review statements before generating an unsigned request. A new **explicit** `--allow-unverified-ai` option enables truthful AI-origin `source_kind` declarations without inventing human reviewers. Mixing human and AI declarations in one file is blocked. The offline preflight continues to check schema, intent, row/body limits, approximate duplicates, negative-answer reuse, public HTTPS source links and file-byte preservation. The handoff manifest explicitly says **unverified** and **0 independent expert labels**. The prepared output directory is private (`0700`) and files are written with `0600` permissions on POSIX systems. Neither mode signs nor uploads anything.

A second module, [`phase3m_public_pool_status.py`](../src/falsum/phase3m_public_pool_status.py), uses only a fixed **GET** to the *public aggregate* status endpoint for `SECURITY_REVIEW_GENERAL`. It can report pool-wide eligible rows, submitter threshold, and snapshot state. It never accesses a contributor's address, `/mine` records, hidden row contents, signer keys, or wallet data. When network access or schema validation fails, its report says **unavailable**, never zero. Pool-wide counts are not evidence of FALSUM-owned contributions.

The [Phase 3M CI](../.github/workflows/phase3m-honest-ai-and-pool.yml) tests human-regression and unverified-AI paths on Python 3.11, 3.12, and 3.13, then performs a read-only aggregate status probe. It publishes only aggregate status, and **never** private evaluation prompts or answers.

## Local private workflow for AI-assisted candidates

Create a local, **not committed**, UTF-8 JSONL file in `private/evalpool/candidates.evalpool-private.jsonl` with the exact `SECURITY_REVIEW_GENERAL` intent, `preference_pair` label, a better answer and a plausible but wrong answer. Declare provenance **honestly**:

```json
{"intent_id":"SECURITY_REVIEW_GENERAL","label_kind":"preference_pair","prompt":"...","chosen":"...","rejected":"...","provenance":{"source_kind":"llm","source_url":"https://github.com/<owner>/<repo>/commit/<real-commit>"}}
```

The placeholders are schema illustrations only. **No real proposed hidden test cases or answer keys are committed to this repository.**

Check locally:

```bash
PYTHONPATH=src python -m falsum.phase3l_evalpool_preflight inspect \
  --file private/evalpool/candidates.evalpool-private.jsonl \
  --allow-unverified-ai
```

After careful source/factual review, and only when the operator wants a signable, still-unsubmitted handoff, run:

```bash
PYTHONPATH=src python -m falsum.phase3l_evalpool_preflight prepare \
  --file private/evalpool/candidates.evalpool-private.jsonl \
  --allow-unverified-ai \
  --address 0xYOUR_REAL_40_HEX_ETHEREUM_ADDRESS \
  --out-dir private/evalpool/unsigned-batch-001
```

This needs **no fabricated human-review file** and provides `PRIVATE-EVALPOOL-ROWS.jsonl`, `EIP191-MESSAGE-TO-SIGN.txt`, and `UNSIGNED-HANDOFF.json`. An actual wallet EIP-191 signature, explicit submission approval, optional real human review, and per-row `eligible` verification remain entirely operator-controlled. Do not share a private key, seed, or signed hidden test content in GitHub/ChatGPT.

Read the aggregate intent status only:

```bash
PYTHONPATH=src python -m falsum.phase3m_public_pool_status \
  --out private/evalpool/public-intent-status.json
```

For **your own** row state you must independently use the documented `GET /api/evalpool/submissions/mine?submitter=<your public address>&intent_id=SECURITY_REVIEW_GENERAL` with a real contributor address. No data in this repo establishes ownership, actual admission, `eligible` status, expert accuracy or evaluator registration. A network status of `accepted` at upload time is only storage admission, not `eligible`. The bounty [#96](https://github.com/telegraphprotocol/bounties/issues/96) counts your part only after actual `eligible` rows or a passing evaluator module and an appropriate `/submit`.

## Limits

This change is **not** an evaluator accuracy improvement. The old and Phase 3K LoRAs remain quarantined after 0/3 context reversals in the latest separate-project experiment. A source URL plus a coherent AI-authored answer is not proof of independent semantic quality. The operator should prefer source-correct, distinct, realistic security review cases with plausible wrong answers, and avoid making deployment-exploitation claims not established by the source. The protocol itself can reject them for near duplication, poor structure, provenance or curation failures.
