# Phase 5BY — ResQ Solana RustSec advisory expansion

**Purpose:** extend the existing ResQ Cargo.lock compatibility harness beyond
anchor-lang and replay four additional real package/advisory findings from the
exact RustSec snapshot already scanned by cargo-audit.

## Frozen inputs

- Application: https://github.com/resq-software/programs/commit/76ac2d3765b7d5defa403c1b141e898782b4c923
- Exact Cargo.lock blob: 73f06efd4b385fb1629ccf06d2e1f540d42c47d7
- RustSec database: https://github.com/rustsec/advisory-db/commit/c5279d0b0c9e8b70df666eb6d1edbabcfd1176bd
- Baseline: cargo-audit 0.22.2, Rust 1.88.0
- New case roster and source blobs: data/phase5by-resq-rustsec-advisory-expansion-protocol.json

The four new package/advisory pairs were selected from the previously completed
full-lockfile cargo-audit result and frozen before this FALSUM candidate
implementation. The baseline therefore predates the candidate protocol. This
is not a blind benchmark.

## Why this extension exists

The full ResQ lockfile contains 805 dependencies. The prior Phase 5BX adapter
compared FALSUM with cargo-audit only on two anchor-lang pairs. The same
cargo-audit run found four other package advisories. Phase 5BY checks whether
FALSUM's source-bound version-applicability logic can reproduce those four
actual findings, rather than leaving them as unexamined baseline output.

| Package | Locked version | RustSec advisory |
| --- | ---: | --- |
| crypto-bigint | 0.5.5 | RUSTSEC-2026-0387 |
| curve25519-dalek | 3.2.0 | RUSTSEC-2024-0344 |
| ed25519-dalek | 1.0.1 | RUSTSEC-2022-0093 |
| url | 2.5.8 | RUSTSEC-2026-0592 |

The URL advisory contains function-scope metadata. Phase 5BY records that
metadata but only checks package-version applicability, matching the scope of
the cargo-audit dependency finding. It does not inspect whether ResQ calls
those functions.

## Candidate semantics

RustSec treats the union of versions.patched and versions.unaffected
requirements as versions that are not affected. If neither list contains a
range, RustSec treats all versions as affected. FALSUM uses its own Python
SemVer parser for the candidate decisions and compares it with both
cargo-audit 0.22.2 and an independent semver@7.8.6 range reference. The
comparator subset is deliberately narrow; unsupported syntax abstains. Exact
source blobs are verified before parsing.

The context-aware references are the real cargo-audit 0.22.2 full-lockfile
result and the independent semver@7.8.6 range resolver. A citation-only
baseline marks every advisory applicable. Two earlier anchor-lang negatives
are retained as calibration controls only; they are not held-out cases.

## Results

The authoritative machine-readable result is the hosted
Phase 5BY workflow artifact. The workflow records:

- four new package/advisory pairs and two prior calibration controls;
- candidate coverage, abstentions and agreement with cargo-audit and semver@7.8.6;
- false acceptances and false rejections relative to cargo-audit;
- the citation-only control's false-applicable decisions;
- the complete cargo-audit findings from the 805-dependency lockfile.

A result that ties cargo-audit is compatibility evidence, not measured
improvement over that credible baseline. The four new cases are all
cargo-audit-positive, so specificity on the new cases is not measured.

## Reproduce

The hosted workflow pins Python 3.11, Node 22, semver@7.8.6,
cargo-audit 0.22.2, Rust 1.88.0, the ResQ source commit and the RustSec
database commit. It checks out the database, verifies every advisory blob,
runs source-backed tests, replays the full lockfile baseline, and uploads both
machine-readable reports.

## Limits

- One Solana application and one RustSec database snapshot.
- Four new positive cases; two prior calibration negatives.
- Same RustSec source family and same application as Phase 5BX; not an
  independent source-family holdout.
- cargo-audit is a credible tool reference, not human AppSec gold.
- FALSUM is not represented as scanning all 805 dependencies.
- No Solana program source, call graph, runtime behavior, transaction,
  validator, function reachability or exploitability is tested.
- No ResQ maintainer adoption, independent reproduction, Anjoman acceptance,
  Telegraph ranking change or network improvement is claimed.
