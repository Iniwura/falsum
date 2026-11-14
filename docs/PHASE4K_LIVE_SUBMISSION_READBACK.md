# Phase 4K — actual public contributor-row status readback

**November 14, 2026 | Telegraph Season II / Evaluators / SECURITY_REVIEW_GENERAL**

## Purpose

The previous **20 Eligible** evaluation-material rows were reported from the contributing account on November 2 and announced in the public [bounty /submit](https://github.com/telegraphprotocol/bounties/issues/96#issuecomment-6588168396), but the earlier screenshot was not independently verified against the current node. Phase 4K adds an **actual live, read-only node check** using Anjoman's [documented API](https://anjoman.ai/docs/scoring/contribute-evaluation-data). A CI run records exactly what the publicly accessible node responds **at that moment**; it cannot backdate or fake a result.

The source commenter, and a single contributor wallet address already stated in that comment, are checked against the public GitHub API. The address is passed only to the documented Anjoman node GET endpoint. The report **never displays the address or any row hashes, case IDs, private prompts or A/B answers**.

**This tool does not sign, submit, buy, train, register an evaluator, contact reviewer accounts, or modify any Anjoman state.**

## Reproduce

Clone the public repository with Python 3.11 or later and run:

```bash
PYTHONPATH=src:tests python -m unittest discover -s tests -p test_phase4k_submission_readback.py -v
PYTHONPATH=src python -m falsum.phase4k_submission_readback --out ./phase4k-new-report.json
```

On Windows PowerShell, set `$env:PYTHONPATH = 'src'` before the second command. Use a new output filename each time; older evidence reports are never silently overwritten.

The same tests and actual live GET probe run in [Phase 4K Actions](../.github/workflows/phase4k-submission-readback.yml) on this code's PR, on changes to this phase, and manually through the GitHub Actions workflow-dispatch button. The CI result includes a 90-day JSON artifact with only count aggregates, timestamp, source comment checksum, status and limitations. The workflow itself can pass even if the live node is temporarily unavailable; **check the report's `live_readback_completed` flag and `status`**, not just its green CI icon.

## Exact interpretation

- `PUBLIC_SUBMITTER_ROW_COUNT_MATCHES_REPORTED_20_ELIGIBLE`: the public node returned 20 rows in eligible state for the address declared in the contributor's public /submit comment. This is read-only observation, **not maintainer approval or independently verified source/label correctness**.
- `PUBLIC_SUBMITTER_HAS_MORE_THAN_20_ELIGIBLE_ROWS`: live node lists more than the original reported 20; this is not falsely reduced to 20.
- `PUBLIC_SUBMITTER_HAS_FEWER_THAN_20_ELIGIBLE_ROWS`: live node lists fewer than reported; inspect network changes and do **not** call the earlier evidence currently confirmed.
- `LIVE_CONTRIBUTOR_READBACK_UNAVAILABLE_NOT_ZERO`: GitHub or the Anjoman node was unreachable, redirected, rate-limited, malformed or inconsistent, or the original public comment changed. The result is **unknown**, not zero or confirmed eligible.

Input safety: exact known GitHub comment, verified public commenter, Intent and reported count; fixed allowlisted node endpoint; HTTPS only; strict nonredirecting reads; paginated rows with bounded length and duplicate protection; fixed allowed status names; aggregate-only export. Tests use **synthetic** wallet and row content, never privately held evaluation pairs.

## What remains unproven

A public comment claiming an address is **not cryptographic proof of address ownership**. A row appearing Eligible does **not** mean independent AppSec review, semantic correctness, maintainer bounty approval, inclusion in the active ranking snapshot, adapter registration, improved model accuracy or a submitted H2 entry.

FALSUM's original quarantined reward-model research results remain unchanged (Phase 4H: 5/8 researcher-source matches and 1/4 complete source-sensitive reversals versus 4/8 constant choice on the same eight conditions). This phase upgrades a **network-status evidence gap**, not the original model, its benchmark or the already published static judge site.

## Follow-up

After a genuine completed readback, save the actual CI URL as source and quote its observation time. If the node returns unknown or fewer than 20 Eligible rows, the final submission must retain that limitation. Request maintainer feedback separately on [bounty #96](https://github.com/telegraphprotocol/bounties/issues/96); the prior bounty claim was automatically released on November 5, and that is a separate process from row status and from the official Season II hackathon entry.
