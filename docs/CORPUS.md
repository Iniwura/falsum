# FALSUM real-advisory diagnostic corpus (draft, **not eligible**)

This repository contains three **source-pinned** GitHub-reviewed GHSA advisories
in the OSV JSON format and a small **draft** preference casebook.

- Axios `GHSA-jr5f-v2jv-69x6` / `CVE-2025-27152`: absolute URL overrides `baseURL` under relevant input/header conditions; fixed in npm axios `1.8.2` in the 1.x release series.
- Jinja2 `GHSA-q2x7-8rv6-6q7h` / `CVE-2024-56326`: indirect `str.format` sandbox bypass relevant to attacker-controlled templates and suitable custom filters; fixed in `3.1.5`.
- Jinja2 `GHSA-cpwx-vrp4-4pq7` / `CVE-2025-27516`: sandbox `|attr` bypass relevant to attacker-controlled templates; fixed in `3.1.6`.

The two Jinja vulnerabilities deliberately test the same package and `3.1.5`
version with different advisory results. **Package-version status is not an
exploitability finding**. A correct review must also establish the vulnerable
code path, whether attackers can reach it, compensating controls, and whether
other vulnerabilities affect the package.

## Provenance

The `data/snapshots/{GHSA}.json` files are exact copies of their published
OSV-format advisory JSON from GitHub's `github/advisory-database` repository
at the pinned commit recorded in each `.meta.json`. They were retrieved with
an authenticated GitHub repository-read action. The sidecar contains the exact
pinned raw URL, SHA-256 of the archived file bytes, byte count and advisory ID.
CI checks the digests and version verdicts again. Hash verification does not
replace advisory publisher identity verification.

## Run the current gates

```bash
PYTHONPATH=src python -m falsum validate data/draft-ledger.json
PYTHONPATH=src python -m falsum audit-snapshots \
  data/draft-ledger.json --directory data/snapshots --include-drafts
PYTHONPATH=src python -m unittest discover -s tests -v
```

## Review and submission boundary

All cases remain `draft`: source identity and status are checked
programmatically, but **no independent human security reviewer has signed off**.
These examples do not constitute submitted, `admitted`, `eligible` or frozen
Anjoman material. They are much too small to measure model accuracy or establish
a generalization claim. No data upload should occur from this file.

Before making genuine submission material, review each prompt, evidence source,
and `chosen`/`rejected` pair for true security nuance; add counterexamples,
withheld advisory groups, and real application contexts; remove shortcuts,
then submit through the official curator and record each row's actual state.
Avoid treating simple affected-version statements as confirmation of exploitability.

## Version parser safety

For OSV `ECOSYSTEM` ranges, the offline checker handles *only* exact stable
`major.minor.patch` numbers in npm or PyPI; for OSV `SEMVER` it handles strict
SemVer. Non-stable PyPI versions, PEP 440 epochs, local versions, npm prereleases
in ECOSYSTEM ranges, `GIT` ranges, and unsupported range events are `unknown`.
This prevents a missing or unsupported range from being mislabelled as safe.
For general production use, replace this limited parser with tested,
ecosystem-native version libraries rather than expanding string comparisons.

Specifications: https://ossf.github.io/osv-schema/ and
https://docs.telegraphprotocol.com/docs/scoring/contribute-evaluation-data
