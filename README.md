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
