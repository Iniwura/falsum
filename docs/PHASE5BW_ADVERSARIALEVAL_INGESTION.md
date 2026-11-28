# Phase 5BW — independent AdversarialEval corpus ingestion and overlap audit

**Status:** protocol frozen before candidate implementation. This is a public-source ingestion and reproducibility result, not a FALSUM accuracy benchmark.

The original protocol was committed at `2026-11-28T07:32:17Z` in [`79e914d`](https://github.com/Iniwura/falsum/commit/79e914ddb2c611627bb4d1ea26aa0ec992a3b569); the first candidate module commit followed at `07:33:46Z`. The original timestamp field had used the run-start time and was corrected in a metadata-only follow-up. The source roster, hashes, overlap rule and expected rows were unchanged.

## Frozen external source

The source is [Ritapossible/AdversarialEval](https://github.com/Ritapossible/AdversarialEval), pinned at commit [09f9fa4a584b513720b215731baf54187039ac10](https://github.com/Ritapossible/AdversarialEval/commit/09f9fa4a584b513720b215731baf54187039ac10), under its pinned [MIT license](https://github.com/Ritapossible/AdversarialEval/blob/09f9fa4a584b513720b215731baf54187039ac10/LICENSE).

The protocol pins Git blob identities for the README, license, upstream row-identity helper, 40-pair JSONL, metadata JSONL, freeze report, score report, raw score JSON and registration rule. It also checks the published test and metadata SHA-256 values:

- Test JSONL: `66b37e83df6391bb9364112e11747bad95b3afa0e32d4bda0290f5c5fc49e81b`
- Metadata JSONL: `7cc55e20d0527c9f96f24b390cfbcebead13a60be9865e38d7691f3716d8f32f`

The metadata has 40 rows: Fexx 20 and Lino 20. Every row is marked author-reviewed and AI-assisted; no row is fully human-written. The ingestion code reproduces the upstream NFC/whitespace-normalized SHA-256 row identity and requires exact one-to-one matches between pairs, metadata and raw score records.

## Published result replay

The external raw score file contains 40 unique pair results. Recomputing each correctness flag from its chosen/rejected scores gives:

| External adapter result | Count |
| --- | ---: |
| Correct | 31 |
| Incorrect | 9 |
| Ties | 0 |
| Accuracy | 77.5% |
| 95% Wilson interval | 62.5–87.7% |

This is arithmetic replay of the external project's published adapter output. The model inference was not rerun. The external report states a strongest shortcut judge of 60%; the shortcut predictions are not all in the pinned raw score file, so that number remains an external report claim rather than an independent replay here.

The external project's pre-registered rule required at least 80% accuracy and a 65% Wilson lower bound. Its own report says the result missed both and recommends DO NOT REGISTER. The project owner later registered by explicit override. This is not a FALSUM result and is not a claim that the external adapter passed its own rule.

## FALSUM public-source overlap

Before implementation, the protocol froze four public FALSUM source-inventory files at main commit `888afe14a5d75160963f5a85169fc3f8d6f85ec7`:

- `docs/CORPUS.md`
- `data/advisory-queue.json`
- `data/draft-scenarios.json`
- `data/draft-pr-benchmark.json`

They contain 35 distinct CVE/GHSA identifiers. The 40 external pairs contain 11 distinct identifiers.

| Classification | Result |
| --- | ---: |
| Public-source overlap | 1 pair, 2 identifier strings |
| Public-source-disjoint candidates | 9 pairs, 6 distinct GHSA identifiers |
| Pairs without an extractable CVE/GHSA identifier | 30 |

The one overlapping pair is row 9, identity `880bfff3b78c94ba18dcda4dc9197435253a832dd020dc6f02ed18c00b43815c`, containing CVE-2025-27152 / GHSA-JR5F-V2JV-69X6. The nine candidate row identities and their six GHSA identifiers are recorded in the frozen JSON protocol and machine-readable output.

**The nine candidates are not a blind or eligible held-out set.** The private contents of FALSUM's historical evaluation material are not available for source-identity comparison. This audit proves only disjointness from the four pinned public inventory files. It does not prove private-pool disjointness, independent human gold, or generalization.

## Why no FALSUM score is reported

The external corpus is a pairwise reward-model test: each item supplies a prompt, a chosen answer and a rejected answer. FALSUM's current source-integrity and response-action checks are not a compatible pairwise reward-model endpoint for these mixed prose/JSON pairs. Running a verdict-only parser or returning HOLD on unsupported shapes would not be a fair context-aware comparison. The nine public-source-disjoint candidates also cannot be treated as held out while private overlap is unknown.

Accordingly, Phase 5BW does **not** report FALSUM accuracy, false acceptance, false rejection, coverage, abstention, or improvement. It does not train or call a model, upload material, register an adapter, change rankings, or contact another maintainer.

## Reproduce

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_phase5bw_adversarialeval_ingestion.py' -v
PYTHONPATH=src python -m falsum.phase5bw_adversarialeval_ingestion --out /tmp/PHASE5BW-ADVERSARIALEVAL.json
```

The [Phase 5BW workflow](../.github/workflows/phase5bw-adversarialeval-ingestion.yml) fetches only immutable public raw URLs, checks Git blob identities and SHA-256 values, replays the published score arithmetic, checks source overlap, and uploads a sanitized JSON artifact. It does not include prompt or answer text in the artifact.

## Limits and next gate

- External independent authorship is documented by the external project's metadata; both authors used AI assistance and reviewed their own pairs.
- The adapter inference and shortcut predictions were not rerun.
- FALSUM's four-file public inventory is bounded; private source overlap remains unknown.
- No independent FALSUM reproduction, ResQ maintainer review, Anjoman row acceptance, or Telegraph ranking change is established.
- A matched-input comparison requires an evaluator interface that can meaningfully score both answers on the same task and access to a corpus proven disjoint from FALSUM's private training/evaluation sources. Neither condition is currently met.

No internal score change is justified by this ingestion result alone.
