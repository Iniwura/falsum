# Phase 5CA — VADER external human-scored corpus freeze

## Purpose

Phase 5CA introduces a real external response-quality corpus for the Evaluators track. It is a pre-inference data-integrity and source-split phase. It does not train or score a FALSUM candidate, upload evaluation material, or claim network adoption.

The source is the CC-BY-4.0 [AfterQuery/VADER dataset](https://huggingface.co/datasets/AfterQuery/vader), pinned to dataset revision 9bef4b3b1994ce138d8a043b68ab0d8a81d8472d. The accompanying paper is [VADER: A Human-Evaluated Benchmark for Vulnerability Assessment, Detection, Explanation, and Remediation](https://arxiv.org/abs/2505.19395).

The paper reports 174 real-world vulnerability cases. Six external LLMs produced responses. Each response was scored by at least two independent security-expert evaluators who were blind to model identity. The published total is 0–10, comprising Explanation (0–2), Remediation (0–5), and Other (0–3). The public CSV contains the published per-response total and component scores, not the individual raters' raw score sheets.

The six model identities are Claude 3.7 Sonnet, Gemini 2.5 Pro, GPT-4.1, GPT-4.5, o3, and Grok 3 Beta. Their answers are model-generated. They must never be described as human-authored answers.

## Frozen source and join contract

The protocol is [data/phase5ca-vader-corpus-protocol.json](../data/phase5ca-vader-corpus-protocol.json). It pins:

- the immutable Hugging Face dataset revision;
- vader.csv and graded.csv Git blob SHA-1 identities;
- the exact six-model schema and score ranges;
- the source-repository normalization and holdout hash;
- the known public FALSUM source inventory to exclude from the reserved holdout;
- the derived-preference margin threshold of 2 points;
- the requirement not to use VADER for candidate training.

The two CSVs must be joined by their stable ID field, never by the displayed Case number. The public files can number the same stable record differently. Case-number differences are recorded and do not change the join. Unmatched IDs and mismatched repository/CWE/severity/description records are excluded and reported. No retrospective repair or manual row selection is permitted.

The source split is grouped by canonical GitHub repository and uses a score-blind SHA-256 bucket. Repositories already in the listed public FALSUM source inventory are excluded from the reserved holdout. The inventory is explicitly partial, not a claim to cover all historical FALSUM work.

## What this does and does not establish

The VADER scores are authentic published human-expert references. Pairwise preferences with a total-score margin of at least 2 are derived from those scores for a future ranking comparison. They are not original pairwise annotations. Near-ties and exact ties are excluded from that derived preference set.

The public API does not expose per-row membership or source identities for the user's 20 private Anjoman-eligible rows. Therefore overlap between VADER and private Anjoman material is **unknown**. The reserved holdout is only demonstrably disjoint from the explicitly listed public FALSUM sources. It is not yet valid to call it fully disjoint from the private pool or model pretraining.

The source dataset's original GitHub link in the paper is currently inaccessible; the pinned Hugging Face dataset snapshot is the source used here. The workflow verifies exact file bytes against the frozen Git blob IDs before parsing. It writes only aggregate metrics, stable IDs, source hashes, and a reserved roster artifact. It does not copy raw model answers into FALSUM.

No third-party code or tests are executed. No model inference, training, paid API call, wallet/signature action, network upload, or official submission occurs in this phase.

## Next benchmark stage

Only if the ingestion manifest passes the frozen minimums:

1. Reconstruct bounded source context for the reserved cases from their published case archives. Reject unsafe archive paths and never execute third-party code.
2. Freeze the exact prompt/answer bytes and exclude any response that exceeds the official 512-token input cap. Report exact coverage and abstention.
3. Compare on identical inputs:
   - **Verdict-only baseline:** exact CWE and severity matching, scored only against the VADER Other component (not misrepresented as a full 10-point evaluator).
   - **Context-aware evidence baseline:** source-bound CWE, patch-path/hunk applicability, and test-plan correspondence checks, without executing third-party code.
   - **FALSUM:** a research-only ModernBERT LoRA rebuilt from the existing frozen 60-pair Phase 3K research corpus. VADER is not used for training or tuning.
4. Report Spearman correlation, derived pairwise preference accuracy, coverage/abstention, component metrics, and repository-clustered uncertainty. Preserve negative results.

The previous original LoRA artifact is unavailable and the old model remains quarantined. Rebuilding a research candidate is a new inference experiment, not restoration of the old checkpoint and not permission to register it.

## Reproduction

    PYTHONPATH=src python -m unittest discover -s tests -p 'test_phase5ca_vader_corpus.py' -v
    PYTHONPATH=src python -m falsum.phase5ca_vader_corpus --out /tmp/PHASE5CA-VADER-CORPUS-MANIFEST.json --roster /tmp/PHASE5CA-VADER-RESERVED-HOLDOUT-ROSTER.json

The [Phase 5CA workflow](../.github/workflows/phase5ca-vader-corpus.yml) performs the same authenticated download and publishes the aggregate manifest and reserved roster as a GitHub Actions artifact. That run is author-operated CI, not independent reproduction.

## Authenticated ingestion result — 28 November 2026

The pinned source bytes were authenticated and the ingestion workflow completed, but the corpus **did not pass the frozen readiness gate**. This is a negative benchmark result, not a candidate score.

[Hosted Phase 5CA run](https://github.com/Iniwura/falsum/actions/runs/46136480080) · [aggregate manifest and reserved roster artifact](https://github.com/Iniwura/falsum/actions/runs/46136480080/artifacts/15260111211)

| Audit field | Observed |
| --- | ---: |
| Parsed VADER source rows | 177 |
| Parsed graded rows | 173 |
| Malformed VADER records | 0 |
| Malformed graded records | 60 |
| Stable IDs present in both files | 173 |
| Matched cases after metadata validation | 159 |
| Source-only stable IDs | 4 |
| Score-only stable IDs | 0 |
| Repository/CWE/severity/description mismatches excluded | 12 |
| Invalid source-metadata records excluded | 2 |
| Displayed Case-number mismatches (not used for joining) | 159 |
| Reserved public-inventory-disjoint holdout | 43 cases / 39 repositories |
| Derived total-score preferences with margin >= 2 | 389 |
| Candidate inference / training | Not run |

The graded CSV has 233 physical records: 173 valid rows and 60 malformed records. The frozen protocol expected 174 rows in each file. The VADER file has 177 valid rows, while the graded file has 173 valid rows. The sanitized malformed examples include non-record/diff-like fragments; no row was repaired, guessed, or manually selected.

The manifest marks the benchmark **not ready** because of the frozen row-count mismatch, malformed graded records, source metadata exclusions, invalid metadata, and four unmatched source IDs. The 159 matched cases and 43-case holdout are large enough for the declared minimums, but those counts do not override the data-integrity blockers.

No verdict-only baseline, context-aware baseline, or FALSUM candidate was run. The 389 pairwise preferences are derived from published human-expert total scores; they are not original pairwise labels. Private Anjoman source overlap remains **UNKNOWN**. This author-operated CI run is not independent reproduction.

Do not relax the frozen 174-row expectation, repair malformed rows after inspection, or treat the reserved public-only holdout as disjoint from private material or model pretraining. The next valid step is an authoritative corrected immutable source revision or a separately frozen authentic paired corpus with defensible references. Until then, Phase 5CA is a reproducible ingestion harness and a documented source-data blocker, not measured evaluator improvement.

## Authenticated ingestion result — 28 November 2026

The pinned source bytes were authenticated and the ingestion workflow completed, but the corpus **did not pass the frozen readiness gate**. This is a negative benchmark result, not a candidate score.

[Hosted Phase 5CA run](https://github.com/Iniwura/falsum/actions/runs/46136480080) · [aggregate manifest and reserved roster artifact](https://github.com/Iniwura/falsum/actions/runs/46136480080/artifacts/15260111211)

| Audit field | Observed |
| --- | ---: |
| Parsed VADER source rows | 177 |
| Parsed graded rows | 173 |
| Malformed VADER records | 0 |
| Malformed graded records | 60 |
| Stable IDs present in both files | 173 |
| Matched cases after metadata validation | 159 |
| Source-only stable IDs | 4 |
| Score-only stable IDs | 0 |
| Repository/CWE/severity/description mismatches excluded | 12 |
| Invalid source-metadata records excluded | 2 |
| Displayed Case-number mismatches (not used for joining) | 159 |
| Reserved public-inventory-disjoint holdout | 43 cases / 39 repositories |
| Derived total-score preferences with margin >= 2 | 389 |
| Candidate inference / training | Not run |

The graded CSV has 233 physical records: 173 valid rows and 60 malformed records. The frozen protocol expected 174 rows in each file. The VADER file has 177 valid rows, while the graded file has 173 valid rows. The sanitized malformed examples include non-record/diff-like fragments; no row was repaired, guessed, or manually selected.

The manifest marks the benchmark **not ready** because of the frozen row-count mismatch, malformed graded records, source metadata exclusions, invalid metadata, and four unmatched source IDs. The 159 matched cases and 43-case holdout are large enough for the declared minimums, but those counts do not override the data-integrity blockers.

No verdict-only baseline, context-aware baseline, or FALSUM candidate was run. The 389 pairwise preferences are derived from published human-expert total scores; they are not original pairwise labels. Private Anjoman source overlap remains **UNKNOWN**. This author-operated CI run is not independent reproduction.

Do not relax the frozen 174-row expectation, repair malformed rows after inspection, or treat the reserved public-only holdout as disjoint from private material or model pretraining. The next valid step is an authoritative corrected immutable source revision or a separately frozen authentic paired corpus. Until then, Phase 5CA is a reproducible ingestion harness and a documented source-data blocker, not measured evaluator improvement.
