# Phase 5BX — independent cargo-audit baseline on ResQ Solana

**Purpose:** compare FALSUM's existing two-case SemVer result with the real RustSec cargo-audit tool on the exact same pinned application lockfile and advisory snapshot.

This is a post-hoc independent-tool corroboration. FALSUM had already been run on these two cases before the Phase 5BX baseline protocol was frozen. It is not a blind holdout.

## Frozen inputs

- Application: [resq-software/programs](https://github.com/resq-software/programs/commit/76ac2d3765b7d5defa403c1b141e898782b4c923), exact Cargo.lock Git blob 73f06efd4b385fb1629ccf06d2e1f540d42c47d7
- Locked package: **anchor-lang 1.0.0-rc.4**
- RustSec database: [c5279d0](https://github.com/rustsec/advisory-db/commit/c5279d0b0c9e8b70df666eb6d1edbabcfd1176bd)
- Advisory records: **RUSTSEC-2026-0144** and **RUSTSEC-2026-0146**, with exact Git blob pins in the [protocol](../data/phase5bx-cargo-audit-resq-baseline-protocol.json)
- Baseline: **cargo-audit 0.22.2**, Rust **1.88.0**

The roster and baseline version were committed before the adapter implementation. The exact advisory files are checked out and their Git blob IDs verified before cargo-audit runs.

## What runs

The workflow installs the pinned tool, checks out the pinned RustSec commit, and runs:

    cargo audit --no-fetch --stale --no-yanked \
      --db /path/to/pinned-advisory-db \
      --file /path/to/pinned-Cargo.lock \
      --json

It runs from a temporary directory outside the ResQ repository. It does not build the application, run its build scripts, or execute project code. The no-fetch and stale flags keep the selected advisory database fixed; no-yanked avoids a live crates.io yanked-version lookup.

The full lockfile is scanned by cargo-audit. FALSUM is compared only on the two frozen anchor-lang package/advisory pairs. A finding is matched by the exact advisory ID, package name, and locked package version. An absent finding is treated as inapplicable only after the package/version and advisory source blobs are independently verified.

## Metrics

The JSON artifact reports:

- full-lockfile dependency and finding counts from cargo-audit;
- FALSUM coverage and abstentions on the two selected pairs;
- candidate/cargo-audit agreement, false-acceptance and false-rejection disagreements;
- independent semver@7.8.6 / cargo-audit agreement;
- the exact findings returned for the full lockfile.

The false-acceptance/rejection labels are relative to cargo-audit, not human AppSec gold. Any disagreement is preserved in the report; the workflow does not force a preferred result.

## Reproduce

The hosted [Phase 5BX workflow](../.github/workflows/phase5bx-cargo-audit-resq-baseline.yml) performs the complete install, immutable database checkout, source verification, full lockfile scan, comparison, and sanitized artifact upload.

The existing [Phase 5BU Solana lockfile harness](PHASE5BU_RESQ_SOLANA_APP_LOCKFILE.md) remains the source of the FALSUM candidate and independent SemVer reference results.

## Limits

- One pinned Solana application, one anchor-lang version, and two selected advisory pairs.
- cargo-audit is a credible ecosystem tool reference, not human AppSec adjudication.
- FALSUM is not represented as scanning all dependencies in the ResQ lockfile.
- No program source, deployed binary, reachability, runtime behavior, transaction, validator, or security clearance is tested.
- No ResQ maintainer review or independent application adoption is claimed.
- No Anjoman acceptance, Telegraph ranking change, or network scoring improvement is claimed.
