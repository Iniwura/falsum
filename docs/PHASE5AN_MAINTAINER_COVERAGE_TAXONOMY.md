# Phase 5AN — source-maintainer feedback and coverage taxonomy

On November 24, the Gig Guard account [swiftbotlabs publicly reviewed the original FALSUM replay](https://github.com/Iniwura/falsum/issues/97#issuecomment-7126424685). The source maintainer confirmed the 12 planted decisions, 22 audited-v7 decisions, 41 receipt joins and the historical planted-bug SHIP without a security answer. The developer clarified that the seven audited-v7 missing records were zero-cost pre-request holds caused by the 2,000-character input limit, not failed review requests in that run. Their app's existing v7 fix is theirs, not FALSUM's.

[FALSUM's public response](https://github.com/Iniwura/falsum/issues/97#issuecomment-7126449742) independently checked the three original ledgers at the existing pinned commit. This is an actual external source-maintainer review of the retrospective findings, not proof of a fork execution, FALSUM customer integration, expert AppSec gold or accepted ranking improvement.

The additive Phase 5AN taxonomy verifies the existing original Git identities and recognizes an input-limit preflight hold only when the exact recorded reason, length above 2,000, HOLD verdict, empty evidence, zero cost, zero receipts, and empty event batch all agree. Ambiguous missing records stay unexplained. It preserves earlier failures even when latest-case coverage uses a later preflight hold. Existing Phase 5AJ/5AK protocols and original measured counts are unchanged.

## Verified original-source reproduction

[Successful Phase 5AN post-merge replay](https://github.com/Iniwura/falsum/actions/runs/45369264734) passed, including Python 3.11, 3.12 and 3.13; [PR #102](https://github.com/Iniwura/falsum/pull/102) merged after 21/21 checks. All six post-merge main workflows passed on `b120bfba`.

| Original population | Recorded answer | Explicit recorded failure | Input-limit preflight hold |
| --- | ---: | ---: | ---: |
| Planted | 2 | 10 | 0 |
| Audited-v7 | 15 | 0 | 7 |
| Latest scale cases | 103 | 4 | 22 |

The 22 scale preflight cases have recorded lengths of 2,018–6,605 characters and all have an earlier recorded security failure. The seven audited-v7 preflight cases reconcile to a subset of those 22, so do not add the populations. The planted security error events are nine recorded HTTP 500 context deadlines and one fetch failure. The source maintainer described the earlier overlength refusals; the replay verifies the existence of earlier recorded failures, not independently authenticated live transport or the complete reason for every earlier error.

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_phase5an_coverage_taxonomy.py' -v
PYTHONPATH=src python -m falsum.phase5an_coverage_taxonomy --out phase5an-report.json
```

No wallet, paid call, or new network registration. The output is historical decision-event classification, not a security clearance or independent expert evaluation. No review or purchase event is fabricated. The reviewer may correct the interpretation by linking the exact record.
