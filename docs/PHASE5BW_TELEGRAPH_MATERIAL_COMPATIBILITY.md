# Phase 5BW — Telegraph evaluation-material compatibility

## Purpose

This is a read-only compatibility audit of the pinned public AdversarialEval
`SECURITY_REVIEW_GENERAL` preference-pair corpus against Anjoman's
published evaluation-material contract. It verifies the row shape and
documented size/normalization constraints. It does not submit rows, sign a
payload, inspect private pool content, or claim network eligibility.

## Authoritative contract

- [Anjoman: Contribute Evaluation Data](https://anjoman.ai/docs/scoring/contribute-evaluation-data)
  (updated 1 November 2026): judgment material is JSON Lines, one object per
  line and one Intent per upload. Preference pairs use `prompt`,
  `chosen`, `rejected` and `label_kind: preference_pair`.
  `intent_id` is optional but must match when present. Provenance records
  `source_kind` and `source_url`.
- The guide documents prompt bounds of 16–16,000 characters, answer bounds of
  8–32,000 characters, a 64 KiB row limit, NFC/whitespace prompt
  normalization, and a minimum of five distinct contributors before question
  material is used.
- [Telegraph Intent catalogue](https://github.com/telegraphprotocol/bounties/blob/main/docs/INTENTS.md)
  and [bounty #96](https://github.com/telegraphprotocol/bounties/issues/96)
  map `SECURITY_REVIEW_GENERAL` to the judgment family
  `SECURITY_REVIEW`. The catalogue's answer shape is
  `verdict`, `vulnerability_count`, `issues`, and
  `summary`. The adapter is registered on the family, not the child
  Intent.

## Pinned external material

The audit reads the MIT-licensed `Ritapossible/AdversarialEval` snapshot
at commit `09f9fa4a584b513720b215731baf54187039ac10`. Its published test
file contains 40 preference pairs from two outside authors (20 each). The
upstream metadata classifies all 40 as AI-assisted and author-reviewed; none
is fully human-written. The published adapter report states 31/40 (77.5%),
but this project replays only the raw-score arithmetic. It does not rerun the
adapter inference.

The Phase 5BW workflow now validates every pinned row against the documented
structural contract and emits the exact counts and maximum row size in its
machine-readable artifact. It also records:

- whether all prompts are unique after the documented NFC/whitespace
  normalization;
- prompt, chosen-answer and rejected-answer length ranges;
- `preference_pair` labels, optional Intent identity and HTTPS provenance;
- the exact `source_kind` values without rewriting them.

## What this does not prove

No row was uploaded or signed. No Anjoman row status was observed, so the
audit does not label any row `admitted`, `eligible` or active.
The node's provenance classification is also not inferred from the URL or
the `ai_assisted` tag. The two external dataset authors are not counted
as Anjoman contributors. The five-contributor activation requirement remains
a separate network condition.

FALSUM's own Phase 5BQ packet is a different 14-pair source-backed candidate
set with `generated` provenance. It remains unsubmitted and
unadjudicated. Passing a local schema check does not convert either corpus
into accepted Telegraph material.

The audit does not score FALSUM, reproduce the external adapter, establish
human AppSec ground truth, change a ranking, verify an independent application
integration, or claim customer adoption. No wallet, signature, payment,
account-setting or submission action is part of this phase.

## Reproduction

The workflow runs automatically when the pinned ingestion code, tests,
protocol or this document changes. The command is:

```bash
PYTHONPATH=src python -m falsum.phase5bw_adversarialeval_ingestion \
  --out phase5bw-evidence/PHASE5BW-ADVERSARIALEVAL.json
```

The generated report is write-once. Hosted workflow artifacts are the
authoritative run output; the repository stores the protocol and code, not
private evaluation material.
