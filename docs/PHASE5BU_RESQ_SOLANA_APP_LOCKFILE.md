# Phase 5BU — ResQ Solana application Cargo.lock compatibility

**Scope:** a reproducible compatibility result against a real external Solana Anchor application. This is not a full dependency audit, program scanner, security clearance, or independent adoption.

## Frozen application and source identities

Before candidate implementation, the [protocol JSON](../data/phase5bu-resq-solana-lockfile-protocol.json) pinned the ResQ Programs repository at commit [76ac2d3765b7d5defa403c1b141e898782b4c923](https://github.com/resq-software/programs/commit/76ac2d3765b7d5defa403c1b141e898782b4c923). The protocol verifies Git blob identities for the README, workspace Cargo.toml, Anchor.toml, and the 235 KB Cargo.lock. The workspace contains resq-delivery, resq-airspace, and resq-gating. The locked anchor-lang version is exactly 1.0.0-rc.4.

The same protocol pins RustSec advisory database commit [c5279d0b0c9e8b70df666eb6d1edbabcfd1176bd](https://github.com/rustsec/advisory-db/commit/c5279d0b0c9e8b70df666eb6d1edbabcfd1176bd) and the original Markdown blobs for:

- [RUSTSEC-2026-0144](https://rustsec.org/advisories/RUSTSEC-2026-0144.html), affected anchor-lang >=1.0.0, <1.0.2.
- [RUSTSEC-2026-0146](https://rustsec.org/advisories/RUSTSEC-2026-0146.html), affected anchor-lang >=1.0.0-rc.1, <1.0.0-rc.2.

The exact half-open ranges are parsed from the pinned RustSec TOML frontmatter. Unsupported or more complex range shapes fail closed.

## Matched-input comparison

The input is the one actual locked anchor-lang 1.0.0-rc.4 package record and two advisory records. Each package-advisory pair is passed to:

1. A citation-only control that treats the advisory's presence as applicability and ignores the version.
2. An independent semver@7.8.6 reference resolver using satisfies(range, {includePrerelease: true}).
3. FALSUM's Python SemVer parser and source-bound RustSec interval handling.

The prerelease is before stable 1.0.0, so it is outside RUSTSEC-2026-0144's interval. It is after the fixed 1.0.0-rc.2 boundary, so it is also outside RUSTSEC-2026-0146's interval. The precommitted reference result is therefore INAPPLICABLE for both pairs.

The CI artifact reports exact sample sizes, coverage, abstentions, candidate/reference agreement, and disagreements. Any false-acceptance/rejection counters are explicitly relative to the SemVer library reference, not human AppSec gold. The citation-only control is included as a weak control, not the main quality baseline.

## Reproduce

```bash
npm install --prefix .phase5bu-node --ignore-scripts --no-audit --no-fund semver@7.8.6
FALSUM_PHASE5BO_NODE_PATH='$PWD/.phase5bu-node/node_modules' PYTHONPATH=src python -m unittest discover -s tests -p 'test_phase5bu_resq_solana_lockfile.py' -v
FALSUM_PHASE5BO_NODE_PATH='$PWD/.phase5bu-node/node_modules' PYTHONPATH=src python -m falsum.phase5bu_resq_solana_lockfile --out RESQ-SOLANA-LOCKFILE.json
```

The workflow fetches only immutable public GitHub raw URLs and verifies each Git blob before parsing. It also uploads the machine-readable result as a CI artifact.

## Limits

- One application, one resolved package version, and two advisory pairs. This is not a comprehensive Cargo.lock audit.
- No Solana program source, deployed binary, validator, transaction, or runtime behavior was inspected.
- The SemVer reference is an independent library implementation, not human AppSec gold.
- A version being outside these two advisory intervals is not a security clearance.
- This is owner-run compatibility evidence. No ResQ maintainer review, application adoption, or Telegraph network use is claimed.
