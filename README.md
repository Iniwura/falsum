# FALSUM

**Every claim stands trial.**

An evidence-grounded security evaluation research project for [Telegraph Season II](https://hackathon.telegraphprotocol.com/). FALSUM targets the `SECURITY_REVIEW_GENERAL` child Intent and the `SECURITY_REVIEW` evaluator family, as described by [bounty #96](https://github.com/telegraphprotocol/bounties/issues/96).

## Phase 1 + Phase 2a: foundation and source snapshots

This repository starts with an **offline, fail-closed data quality gate** for security evaluation material. It catches malformed provenance, unreviewed evidence, duplicated negatives, easy length shortcuts, near-duplicate prompts, and advisory leakage across train/validation/holdout splits. It exports the exact `prompt` / `chosen` / `rejected` JSONL format used by the official training kit.

**Phase 2a can now fetch immutable OSV advisory snapshots and check supported version ranges. It does not prove exploitability, independently review advisories, train a model, provide a network scorer, or claim accepted Telegraph evaluation material.** A reviewer and source snapshot must establish ground truth independently. All examples in unit tests are invented and must not be submitted.

## Run locally (Python 3.11+)

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m falsum validate path/to/ledger.json
PYTHONPATH=src python -m falsum export path/to/ledger.json --split train --out path/to/train.jsonl
PYTHONPATH=src python -m falsum fetch-osv GHSA-jr5f-v2jv-69x6 --directory data/snapshots
PYTHONPATH=src python -m falsum check-osv data/snapshots/GHSA-jr5f-v2jv-69x6.json --advisory GHSA-jr5f-v2jv-69x6 --ecosystem npm --package axios --version 1.8.2 --expect unaffected
```

`pip install -e .` is optional for the `falsum` console command.

See [Evidence format and quality guarantees](docs/EVIDENCE.md), [Source snapshots and trust boundaries](docs/SOURCES.md), and [Architecture and build gates](docs/ARCHITECTURE.md).

## Official V2 compatibility

The [current Telegraph scoring-adapter kit](https://github.com/telegraphprotocol/telegraph-wasm-baseline) uses a **ModernBERT LoRA reward model → ONNX FP32 → WASI WASM** pipeline with ABI v2 and a 512-token model cap. The adapter runs offline and cannot retrieve new CVE facts during scoring. FALSUM's evidence ledger is a training and evaluation preparation system, not an alternative adapter runtime. Tokenizer conformance, training, ONNX export, WASM package reproducibility, and endpoint validation are **not yet implemented**.

## Trust model

- `review_status: reviewed` records *human attestation*, not automated confirmation of advisory authenticity.
- A `source_sha256` records an external source snapshot checksum. The Phase 2a snapshot audit can now verify the digest against a local OSV archive; the base ledger gate alone validates only its form.
- Cite primary advisories, pin the version and affected conditions, and keep the original evidence snapshot in a reproducible archive before material submission.
- No synthetic identities, false network claims, real credentials, or private vulnerability disclosures in public datasets.
- Keep training data separate from independent test cases. No evaluation submissions before the evidence is source-verified.

## Status

Phase 1 + Phase 2a (offline verified, network fetch untested in CI). **Not an active scoring adapter. No network registration or judge acceptance is claimed.**

## Phase 2b — public-advisory draft corpus (not submitted)

The repository includes pinned OSV-format snapshots from GitHub's reviewed
advisory database for Axios and two different Jinja2 CVEs. Version-boundary
checks include the important OSV `ECOSYSTEM` format for stable npm and PyPI
versions. Unsupported version syntax returns `unknown`, not an unsafe clean
result. **All real-source cases remain `draft`, not independently human-reviewed.**

```bash
PYTHONPATH=src python -m falsum validate data/draft-ledger.json
PYTHONPATH=src python -m falsum audit-snapshots data/draft-ledger.json --directory data/snapshots --include-drafts
PYTHONPATH=src python -m unittest discover -s tests -v
```

Read [corpus provenance and review boundary](docs/CORPUS.md). This is evidence
preparation, not model training, a scorer, or eligible Telegraph pool material.

## Phase 2c — security-review application scenarios (draft only)

Twelve additional **hypothetical, non-submitted** cases test configuration,
secret-handling, SSRF, Actions token privileges, and TLS certificate-validation
preconditions. Cases are partitioned by rule family and source across training,
validation, and holdout. All linked guidance is **unpinned** and every case
remains `draft`, with no human review or network-eligibility claim.

```bash
PYTHONPATH=src python -m falsum check-scenarios data/draft-scenarios.json
# This export intentionally refuses unreviewed/unpinned material:
PYTHONPATH=src python -m falsum export-scenarios data/draft-scenarios.json --split train --out train.jsonl
```

Read [Phase 2c casebook, provenance and promotion gates](docs/SCENARIOS.md).
The program does **not** analyze real repositories, detect real secrets, or
replace human review. It must not be represented as a deployed security scanner
or an accepted Telegraph scoring adapter.

## Phase 2d — pinned application-security guidance

Four upstream documentation revisions have been pinned, with curated SHA-256 verified excerpt manifests. Run `PYTHONPATH=src python -m falsum audit-scenarios data/draft-scenarios.json`. See [Phase 2d provenance](docs/PHASE2D.md). All scenario cases are still drafts; no independent human review, eligible Telegraph rows, model or scorer is claimed.

## Phase 2e — official dataset-gate diagnostic

A [pinned upstream Telegraph training-kit check](docs/PHASE2E.md) now runs in CI on quarantined **draft-only** rows. The official check is currently expected to **fail** because the training partition contains six pairs and the upstream 2% single-negative rule requires at least 50 unique rows. This is deliberate transparency, not a passing data gate, not a trained model, and not network eligibility.

## Phase 2f: pinned GitHub advisory research queue

The [32-advisory research queue](data/advisory-queue.json) provides a reproducible **draft-only** pipeline for synthetic affected/fixed-version tasks (potentially 52 training, 6 validation, 6 holdout comparisons). Use `PYTHONPATH=src python -m falsum.advisory_corpus data/advisory-queue.json --out build/phase2f-quarantined` with outbound GitHub access. The workflow never marks rows reviewed, trains a model, or claims Telegraph eligibility. See [Phase 2f notes](docs/PHASE2F.md).

## Evidence-present security judgment benchmark (Phase 2h)

Our initial GHSA-ID prompts did not give the model the affected-version boundary it would need for reasoning. We now build a **second, draft-only evidence-grounded benchmark** from pinned source events, plus missing-evidence controls designed to catch confident guessing. Run `PYTHONPATH=src python -m falsum.grounded_eval data/advisory-queue.json /path/to/DRAFT-ONLY-corpus.json --out /tmp/falsum-grounded`. See [evidence availability and scoring protocol](docs/PHASE2H.md). These are not independently reviewed cases, model scores or accepted Telegraph evaluation material.
