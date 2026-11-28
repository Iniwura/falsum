# Phase 5CB — VADER graded workbook cross-format audit

## Why this phase exists

Phase 5CA authenticated the pinned VADER CSV files but found 60 malformed physical records in `graded.csv`, source-identity mismatches, invalid source metadata, and unmatched stable IDs. It correctly stopped before candidate scoring.

The same immutable Hugging Face revision publishes a separate `graded.xlsx` workbook. Phase 5CB authenticates that exact file and checks whether it is a structurally sound serialization of the same scored records.

This is a second file in the same dataset revision. It is **not** an independent dataset, a corrected revision, or evidence of candidate improvement.

## Frozen inputs

- Dataset: [AfterQuery/VADER](https://huggingface.co/datasets/AfterQuery/vader), CC-BY-4.0.
- Revision: `9bef4b3b1994ce138d8a043b68ab0d8a81d8472d`.
- Workbook: `graded.xlsx`, SHA-256 `9da644c6e9012fe124b95bd4460853ba045cafe78d26110e5cedde34dc20f158`.
- Workbook Xet identity: `0326e16365c63e3e7ad11c0a89cf4ca88ab8d2f4f44da3682512ff36544ad5fe`.
- Source metadata: the already authenticated `vader.csv`.
- CSV comparison: `graded.csv`, authenticated against its original Git blob SHA-1.
- Join key: stable `ID` only. Displayed Case numbers are never join keys.
- Holdout: the Phase 5CA score-blind, repository-grouped SHA-256 rule. Known public FALSUM repositories are excluded. The source inventory is partial.
- Candidate scoring, training, inference, and network upload are out of scope.

## Parser and audit behavior

The production parser uses Python's standard library (`zipfile`, `xml.etree.ElementTree`, and `decimal`). It does not require `openpyxl` or execute workbook formulas.

The audit:

1. Downloads the workbook only from the pinned Hugging Face revision and checks the exact SHA-256 before parsing.
2. Rejects unsafe ZIP member paths, macro content, external workbook links, DTD/entity declarations, formulas, malformed XML, and unsupported cell types.
3. Requires exactly one worksheet with the frozen Phase 5CA graded schema.
4. Validates stable IDs, source metadata, all six model responses, component-score ranges, and component-to-total sums.
5. Joins the workbook to authenticated source metadata by stable ID and reports unmatched IDs and metadata mismatches.
6. Compares workbook rows with valid rows from the original CSV. It reports content differences and unmatched IDs without repairing or selecting records.
7. Writes only aggregate counts, hashes, and a score-blind holdout roster. Raw model answers and human scores are not uploaded as artifacts.

Any workbook/CSV difference or source metadata mismatch is a blocker requiring source-owner resolution before candidate scoring. The audit does not decide which representation is correct.

## Reproduction

Python 3.11 or newer:

    PYTHONPATH=src python -m unittest discover -s tests -p 'test_phase5cb_vader_xlsx_audit.py' -v
    PYTHONPATH=src python -m falsum.phase5cb_vader_xlsx_audit --out /tmp/PHASE5CB-VADER-XLSX-MANIFEST.json --roster /tmp/PHASE5CB-VADER-HOLDOUT-ROSTER.json

The [Phase 5CB GitHub Actions workflow](../.github/workflows/phase5cb-vader-xlsx-audit.yml) repeats the authenticated download and publishes only the aggregate manifest and score-blind roster. That workflow is author-operated CI, not independent reproduction.

## Authenticated result — 28 November 2026

The exact workbook and both CSV files were authenticated at the frozen revision. The parser contract tests and actual-source audit passed on the exact PR head.

[Hosted Phase 5CB run](https://github.com/Iniwura/falsum/actions/runs/46138606549) · [aggregate manifest and score-blind roster artifact](https://github.com/Iniwura/falsum/actions/runs/46138606549/artifacts/15260840970) · [PR #137](https://github.com/Iniwura/falsum/pull/137)

| Audit field | Observed |
| --- | ---: |
| Authenticated workbook bytes | 918,085 |
| Workbook physical data rows | 174 |
| Valid workbook rows | 172 |
| Malformed workbook rows | 2 |
| Duplicate stable IDs | 0 |
| Incomplete six-model answers | 0 |
| Invalid component-score rows | 0 |
| Valid VADER source rows | 177 |
| Valid graded CSV rows | 173 |
| Malformed graded CSV physical records | 60 |
| Workbook/source metadata IDs matched | 160 |
| Source metadata identity mismatches | 12 |
| Source-only IDs excluded | 5 |
| Displayed Case-number mismatches (not used for joining) | 160 |
| Reserved public-inventory-disjoint holdout | 43 cases / 39 repositories |
| XLSX/CSV common stable IDs | 171 |
| Identical XLSX/CSV rows among common IDs | 171 |
| Differing XLSX/CSV rows among common IDs | 0 |
| Workbook-only IDs versus valid CSV | 1 |
| CSV-only IDs versus workbook | 2 |

The two malformed workbook rows have no parseable CWE identifier. The workbook has fewer malformed rows than the CSV, but it is not a clean replacement: two workbook records fail parsing, 12 source metadata identities disagree, and the workbook and valid CSV have three unmatched IDs in total. The frozen readiness gate therefore remains **blocked** for:

- `malformed_workbook_rows`;
- `source_metadata_identity_mismatches`;
- `xlsx_csv_cross_format_differences_require_source_owner_resolution`.

The 43-case / 39-repository roster meets the public-inventory holdout minimums, but that does not override integrity failures. Private Anjoman overlap remains **UNKNOWN**, and overlap with model pretraining is not established as absent.

No row was repaired, manually selected, or promoted to gold. No verdict-only baseline, context-aware baseline, or FALSUM candidate was run. No inference, training, paid call, wallet/signature action, network upload, or official submission occurred. This is a negative source-integrity result, not a benchmark result.

All eight GitHub Actions workflows passed on exact PR head `db2d4bda4ff2a7d1ad073a9185f196236465def2`: Phase 5CB authenticated audit, Foundation tests on Python 3.11/3.12/3.13, Windows CRLF reproducibility, independent reviewer replay, Phase 5AG contract, PR counterfactual gate, Telegraph diagnostic gate, and Playwright/accessibility. [PR #137](https://github.com/Iniwura/falsum/pull/137) was merged as [commit `53cba9c22821494c4a90b8727cfe5a964a4e4146`](https://github.com/Iniwura/falsum/commit/53cba9c22821494c4a90b8727cfe5a964a4e4146). The Vercel preview status was rate-limited by the free-tier daily deployment cap; it is not a code-test result and no paid upgrade was attempted. The CI is author-operated and is not independent reproduction.

## Decision gate and next step

Candidate scoring may proceed only after an authoritative corrected immutable source revision or explicit source-owner resolution accounts for the two malformed workbook rows, 12 metadata mismatches, and three cross-format unmatched IDs. Do not relax the frozen criteria or repair the records after seeing the result.

Even after source resolution:

- The public holdout is only disjoint from the listed public FALSUM source inventory.
- Overlap with the 20 private Anjoman rows is **UNKNOWN**.
- Model-pretraining overlap is **UNKNOWN**.
- VADER answers were generated by six external LLMs, not human-authored.
- Pairwise preferences derived from aggregate human scores are not original pairwise labels.
- No Telegraph network improvement, active pool usage, accepted material, or official score is implied.

Until the data owner resolves the source-integrity issues, Phase 5CB is a reproducible ingestion harness and a documented blocker, not measured evaluator improvement.
