# Phase 5BV — read-only Anjoman pool status

**Purpose:** verify the public aggregate state of the SECURITY_REVIEW_GENERAL
judgment pool, rather than treating one contributor's eligible rows as proof
that the pool is active.

## Official protocol facts

The [Anjoman contribution guide](https://anjoman.ai/docs/scoring/contribute-evaluation-data)
describes a five-contributor minimum for judgment questions and defines
eligible rows as inclusion in a frozen snapshot. It documents an aggregate
endpoint exposing contributor counts and both the latest and active snapshots.
It also states that there is no public endpoint for per-row ranking-use
records.

The live node response observed on 2026-11-28 reported min_submitters = 3,
while the guide describes five. This is a documentation/runtime discrepancy.
The implementation reads the node's min_submitters field and does not
hard-code either value. The live node field is the configured threshold for
that observed response; the documentation remains the published general rule.

The official [SECURITY_REVIEW bounty #96](https://github.com/telegraphprotocol/bounties/issues/96)
says an individual's contribution counts once their rows are eligible;
maintainer acceptance and actual network use remain separate decisions.

## What the check reads

It performs one unauthenticated GET:

https://devnode.telegraphprotocol.com/api/evalpool/status?intent_id=SECURITY_REVIEW_GENERAL

The script stores only:

- aggregate counts by row state;
- total and eligible contributor counts;
- the node-reported minimum contributor threshold;
- current epoch;
- row count, submitter count and activation epoch for the latest and active
  snapshots.

It does not request a contributor address, the per-contributor submissions
endpoint, row IDs, prompts, answers, signatures or private content. It does
not sign, upload, register, submit, pay or write to the network.

## Observed result

Hosted read-only run:
https://github.com/Iniwura/falsum/actions/runs/46119192105

At 2026-11-28T07:00:50Z, the node reported:

- 1,379 eligible rows and 44 rejected rows;
- 11 total and 11 eligible submitters;
- node-configured minimum of 3 submitters;
- active snapshot: 1,379 rows, 11 submitters, activation epoch 11;
- latest snapshot equals the active snapshot;
- current epoch 70.

This confirms the aggregate SECURITY_REVIEW_GENERAL judgment pool had a
qualifying active snapshot at observation time. It does not identify which
contributors or rows were included.

## Interpretation

active_pool_available_for_current_epoch is true only when the active snapshot
contains rows and meets the node-reported contributor minimum.
latest_snapshot_is_active separately identifies whether the most recent
frozen snapshot has reached the active epoch. A newer snapshot can be waiting
while the previous snapshot remains active.

This aggregate endpoint cannot prove that FALSUM's 20 eligible rows are in
the active snapshot or were used for ranking. The report therefore hard-codes
those contribution-specific claims to false. It also does not prove
maintainer acceptance, canonical evaluator registration or a ranking change.

## Reproduce

    PYTHONPATH=src python -m unittest discover -s tests -p 'test_phase5bv_anjoman_pool_status.py' -v
    PYTHONPATH=src python -m falsum.phase5bv_anjoman_pool_status --out /tmp/ANJOMAN-POOL-STATUS.json

The live command requires public network access to the documented Anjoman
endpoint. GitHub Actions runs the same read-only check and uploads a
machine-readable aggregate artifact. If the endpoint is unavailable, no
fallback is treated as live evidence.

## Limits

- One Intent: SECURITY_REVIEW_GENERAL.
- Aggregate pool state only; no contributor-specific active-snapshot membership.
- No independent human AppSec adjudication.
- No proof of maintainer approval, registered evaluator, provider ranking
  improvement, mission completion or commercial adoption.
