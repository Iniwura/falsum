# FALSUM Phase 2a: source snapshots and conservative version checks

This subsystem makes an important separation: **a verified source snapshot is not a
verified vulnerability conclusion**. It is a provably pinned copy of a public
OSV record, with an explicit, *limited* interpreter of version ranges. A
human must still review code paths, deployment conditions, advisory nuance,
source currency and any severity assignment.

## Commands

```bash
# Requires internet access. This pins the exact response bytes and metadata.
PYTHONPATH=src python -m falsum fetch-osv GHSA-jr5f-v2jv-69x6 --directory data/snapshots

# Reads only local files. Exits 0 when status matches; exits 2 on unknown or mismatch.
PYTHONPATH=src python -m falsum check-osv \
  data/snapshots/GHSA-jr5f-v2jv-69x6.json \
  --advisory GHSA-jr5f-v2jv-69x6 --ecosystem npm --package axios \
  --version 1.8.2 --expect unaffected

# Optional quality gate *after* source-matched evidence has been added to ledger.
PYTHONPATH=src python -m falsum audit-snapshots data/ledger.json --directory data/snapshots
```

The Axios example is a **published advisory**, but the command is not evidence
that it has been fetched or tested against the live OSV service here. Its result
must be confirmed by a real local fetch and checked against primary publisher
sources before any material is marked reviewed or submitted.

## Trust boundaries

- `fetch-osv` only accepts valid CVE/GHSA IDs. Its only remote host is
  `https://api.osv.dev/v1/vulns/{id}`. The downloader refuses redirects,
  cross-host response URLs, malformed JSON, mismatched IDs and files over 3 MB.
- Stored `{id}.json` contains the **raw response bytes**. Sibling
  `{id}.meta.json` records retrieved UTC time, OSV canonical ID, byte count,
  source URL, requested ID and SHA-256. Existing snapshots are immutable; a
  changed upstream advisory needs a **new, separately archived revision**.
- `verify_snapshot` recomputes the digest and checks the advisory ID. The
  digest proves local consistency; it does **not** independently authenticate
  the database publisher or keep an upstream advisory from later changing.
- `version_status` supports exact listed affected versions and strict SemVer
  `SEMVER` range events (introduced/fixed/last_affected/limit). `fixed` and
  `limit` are exclusive; `last_affected` is inclusive. Build metadata does not
  change precedence. `ECOSYSTEM` stable three-component npm/PyPI intervals are supported narrowly;
  other `ECOSYSTEM`, `GIT`, unsupported version syntax, malformed events,
  or incomplete coverage produce `unknown` instead of a guessed `unaffected`.
- `unaffected` means only **outside the supported affected ranges in one
  advisory**. It does not mean an application is secure, the dependency has
  no other CVEs, or that its deployment conditions have been reviewed.
- `audit-snapshots` checks that each reviewed record's source URL and hash
  match the archive, its excerpt occurs in OSV summary/details, and its
  affected/unaffected version verdict agrees with the supported interpreter.
  Records with `conditional` applicability require additional evidence and
  cannot be auto-certified by this gate.
- Do not commit leaked keys, unpublished vulnerabilities, private application
  evidence, or personally identifying data. Security responses should not
  include real credentials even when demonstrating secret-detection quality.

## Current limits and next evidence requirement

This upgrade does **not** establish that any production vulnerability case is
reviewed, that data was accepted by Anjoman, or that a scoring module runs.
All repository unit tests use mock OSV documents. We still need source snapshots
retrieved in a networked environment, independent primary-source checks,
version/condition review, and held-out preference material. The upload quality
rules and official V2 tokenizer gate remain separate.

Specification: https://ossf.github.io/osv-schema/
API: https://github.com/google/osv.dev/blob/master/docs/api/get-v1-vulns.md
Official scoring kit: https://github.com/telegraphprotocol/telegraph-wasm-baseline

## Source-pinned draft examples

Phase 2b includes exact, digest-checked GitHub-reviewed OSV-format source files
under `data/snapshots/` and their provenance sidecars. They use a pinned
`github/advisory-database` commit rather than an unversioned API response.
Use `audit-snapshots --include-drafts` to verify draft evidence without
misrepresenting it as independently reviewed material. See `docs/CORPUS.md`.
