# Phase 5BO - ecosystem-native semantics and offline registry evidence

Phase 5BN is preserved unchanged. Phase 5BO is a separate implementation and
experiment that addresses its two observed abstentions without package-specific
exceptions.

## What changed

The candidate now uses ecosystem-native rules:

- PyPI versions are parsed and ordered with PEP 440 through `packaging==26.4`.
  This resolves legacy spellings such as `0.6c11` and `0.1pre` as versions,
  while invalid strings remain UNKNOWN.
- npm versions use strict SemVer precedence, including prerelease identifiers
  such as `0.20.0-0`, `1.7.0-beta.0`, and `2.0.0-rc1`.
- Multiple range blocks are unioned, so disjoint affected intervals are not
  collapsed into one boundary.
- Unsupported range kinds, malformed events and incomplete range evidence fail
  closed to `UNKNOWN_OR_INSUFFICIENT`.

The implementation is intentionally separate from the Phase5BN candidate. The
reference check uses `packaging.SpecifierSet` for PyPI and the official
[`semver@7.8.6`](https://github.com/npm/node-semver) implementation for npm.
The reference is a semantic resolver check, not human AppSec adjudication.

## Snapshot-backed protocol

The fixed roster contains 14 cases across six advisory records and two
ecosystems:

- 2 Phase5BN regression cases: `pymongo@0.1pre` and `setuptools@0.6c11`;
- 12 additional unseen cases across Axios, Jinja2, Shescape and PrismJS;
- 4 real prerelease cases;
- Axios cases spanning two disjoint affected intervals.

The raw PyPI/npm registry responses are committed under
`data/phase5bo-registry-snapshots/`. Each snapshot has a sidecar URL, byte
length and SHA-256 digest. The audit verifies those bytes and verifies every
claimed package version against the captured response. It performs zero live
registry reads, so an unchanged external registry is not a reproducibility
prerequisite. The advisory source bytes are snapshotted as well.

## Answer-claim evaluation

Every case has three complete structured claim/action options:
affected/block-or-upgrade, inapplicable/no-action-for-this-advisory, and
unresolved/abstain-and-request-evidence. Opaque tokens are assigned
independently and are not mapped from the reference label. The candidate emits
a structured decision and action; the evaluator selects the unique option
whose structured claim matches both. Only after selection is the claim
compared with the frozen reference. The prose attached to each option is
display text, not a natural-language model answer and is not parsed or scored.

The committed result is:

| Policy | Correct | Denominator |
| --- | ---: | ---: |
| Improved candidate | 14 | 14 |
| Frozen external semantic reference | 14 | 14 |
| Structured claim/action selection | 14 | 14 |

These are semantic and protocol regression results. They do not earn points
automatically, prove customer adoption, establish exploitability or qualify as
independent human security gold.

## Reproduce offline

```text
python -m pip install --no-deps packaging==26.4
npm install --prefix .phase5bo-node --ignore-scripts --no-audit --no-fund semver@7.8.6
set PYTHONPATH=src
set FALSUM_PHASE5BO_NODE_PATH=.phase5bo-node/node_modules
python -m falsum.cli audit-ecosystem-semantics --out phase5bo-result.json
python -m unittest discover -s tests -p "test_phase5bo_ecosystem_semantics.py" -v
```

Hosted CI repeats this offline replay across Python 3.11, 3.12 and 3.13 in
[run 45972932870](https://github.com/Iniwura/falsum/actions/runs/45972932870).
ACP is suspended and no payment, deposit, signer change or Telegraph
transaction is part of Phase 5BO.
