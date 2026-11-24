# Phase 5AG: source-grounded multiecosystem per-reference evaluation

**Distinct from the original fixed lodash/Telegraph historical source gates.** This phase implements a bounded per-reference classifier that can handle reviewed advisory source records and target package versions without requiring the frozen historical six-reference response shape.

## Temporal freeze and real upstream provenance

The source roster and **13 expected constructed test cases** were committed first (commit `178178b05ea6d440c3f07ee165a53c4097994ba6`), before the evaluator implementation. The roster Git blob identity is `c396cede959429ff32eff499156961e17546b3e3`. All three complete public upstream GitHub-reviewed advisory JSON blobs were copied byte-exactly from `github/advisory-database` commit `76955defc62d048f8f7cc68bc39a2f6dd1899ebe` and compared to their upstream Git blob SHA-1 prior to writing.

The added independent *source records* cover npm/axios and RubyGems/rack, including separate version intervals, 4-component releases and an unsupported prerelease interval. New source data is authentic; expected labels are **author-constructed**, not independent AppSec gold or independent Miner outputs.

| GHSA ID | Package | Original Git blob SHA-1 |
| --- | --- | --- |
| `GHSA-wf5p-g6vw-rhxx` | npm / axios | `ed4df0a27ba60625f1c70cc2baa6173516a16aa2` |
| `GHSA-xj5v-6v4g-jfw6` | RubyGems / rack | `dbc8a211717f5c99a5cb5f7793f8975710a0aa3a` |
| `GHSA-7mqq-6cf9-v2qp` | RubyGems / rack | `92126024d57ffd07b7469dad7f6e98a9a0078170` |

## Run an offline per-reference evaluation

From repository root, on Bash:

```bash
PYTHONPATH=src python -m falsum.cli review-verified-references \
  --ecosystem npm --package axios --version 1.5.0 \
  --reference GHSA-wf5p-g6vw-rhxx \
  --out /tmp/phase5ag-axios-applicable.json
```

For Windows PowerShell set `$env:PYTHONPATH = 'src'` and run the same `python -m ...` command on a single line with an output path such as `phase5ag-axios-applicable.json`. Output is create-only and will never overwrite an earlier result.

More challenges:

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_phase5ag_reviewed_reference_evaluator.py' -v
PYTHONPATH=src python -m falsum.cli review-verified-references \
  --ecosystem RubyGems --package rack --version 3.2.5 \
  --reference GHSA-xj5v-6v4g-jfw6 \
  --reference GHSA-7mqq-6cf9-v2qp \
  --out /tmp/phase5ag-rack-per-reference.json
```

The Rack 3.2.5 case must classify the first historical GHSA as `VERIFIED_INAPPLICABLE` and the second as `VERIFIED_APPLICABLE`. The prerelease-linked range at Rack 3.0.5 must return `INSUFFICIENT_EVIDENCE` rather than an unsupported claim about version ordering.

## Phase 5AH — adversarial interval-order hardening (24 November 2026)

The parser now rejects overlapping, descending and inclusive-endpoint-reentered event intervals as `INSUFFICIENT_EVIDENCE`, even when an earlier interval already matched the target release. Legitimate disjoint and adjacent (exclusive `fixed` boundary) intervals remain supported. Dedicated tests demonstrate those cases. This is a **constructed adversarial correctness regression**, not a newly adjudicated source, expert gold label or extra holdout dataset.

The three original upstream Git blobs, frozen protocol SHA and 13 preregistered expected cases are **unchanged**. Phase 5AH does not change the historical lodash gates, source provenance, advisory freshness claims or real network outcomes.

## Contract and limitations

- Every result is one of `VERIFIED_APPLICABLE`, `VERIFIED_INAPPLICABLE`, `UNKNOWN_SOURCE`, `INSUFFICIENT_EVIDENCE`; each decision carries an explanatory reason code, authoritative frozen source URL, blob identity and timestamp when one exists.
- The source authority comes only from byte-exact upstream Git identities in the pinned repository roster. Caller claims of prior verification, unknown IDs and duplicate aliases cannot grant verified status. A single tampered trusted source rejects the entire evaluation.
- Numeric 3- or 4-part version intervals and OSV `introduced`, `fixed`, `last_affected` events are handled conservatively. Prerelease version ordering, novel range types, missing target context or conflicting/incomplete evidence remain insufficient.
- This is **not** a package scanner, live advisory update service, comprehensive source feed, general semantic vulnerability accuracy proof or automatic security approval. `coverage_is_complete=false` and `security_clearance_granted=false` are unconditional.
- The new cases do not prove arbitrary package coverage, independent developer adoption, human expert accuracy labels, a registered network evaluator, paid settlement, or a Telegraph network ranking improvement. Original Phase 5Y/5Z/5AA historical results remain untouched.
- Expanding to another advisory requires independent upstream review, pinning the immutable source bytes and version rules, and freezing the new evaluation cases before measuring output accuracy. No uncontrolled live-source trust promotion is supported.
