# Phase 5BV — read-only Anjoman pool status

**Purpose:** verify the public aggregate state of the SECURITY_REVIEW_GENERAL
judgment pool, rather than treating one contributor's eligible rows as proof
that the pool is active.

## Official protocol facts

The [Anjoman contribution guide](https://anjoman.ai/docs/scoring/contribute-evaluation-data)
defines eligible as inclusion in a frozen snapshot. Judgment questions are
used only after the pool has material from at least five different
contributors. The aggregate endpoint exposes contributor counts and both the
latest and active snapshots. The guide also states that there is no public
endpoint for per-row ranking-use records.

The official [SECURITY_REVIEW bounty #96](https://github.com/telegraphprotocol/bounties/issues/96)
says an individual's contribution counts once their rows are eligible;
maintainer acceptance and actual network use remain separate decisions.

## What the check reads

It performs one unauthenticated GET:

https://devnode.telegraphprotocol.com/api/evalpool/status?intent_id=SECURITY_REVIEW_GENERAL

The script stores only:

- aggregate counts by row state;
- total and eligible contributor counts;
- the minimum contributor threshold;
- current epoch;
- row count, submitter count and activation epoch for the latest and active
  snapshots.

It does not request a contributor address, the per-contributor submissions
endpoint, row IDs, prompts, answers, signatures or private content. It does
not sign, upload, register, submit, pay or write to the network.

## Interpretation

active_pool_available_for_current_epoch is true only when the active snapshot
contains rows and meets the documented minimum contributor count.
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
