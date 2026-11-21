# Phase 5AA — Offline, original-Git-verified reviewed-source application gate

**Scope:** Six historical GitHub-reviewed advisory files for `npm:lodash@4.17.15`. No new Miner calls, networks, model scores, expert labels or external integrations are represented by this feature.

## Why

Phase 5Z made a real downstream decision: deny one unrelated original third-party paid-flagged security answer, and suppress the same GitHub-reviewed version-inapplicable advisory reference in each of two direct-provider results. However, every local application invocation fetched six reviewed upstream sources. That creates an avoidable network dependency for reproducing or embedding the reference filter.

Phase 5AA introduces a **portable six-source bundle** that carries original reviewed advisory **bytes**, authenticated against the immutable six Git blob SHA-1 identities and exact version ranges pinned in Phase 5Y. The bundle does **not** include full third-party Miner response bodies. It cannot be used to claim current advisories, independent review quality, a registered network evaluator or a fair canonical Miner leaderboard.

## Developer flow

Run from the repository root with Python 3.11+:

```bash
python -m pip install --no-deps -e .

# One-time online acquisition: fetch and authenticate all 6 pinned Git advisory files.
falsum bundle-reviewed-advisories --out reviewed-lodash-2026.json

# Afterwards, reproduce an actual application decision using local inputs,
# entirely offline. The source file is verified from Git blobs in the bundle.
falsum filter-security-references \
  --role direct_deps_dev_ghsa \
  --request-json my-exact-request.json \
  --response-json my-provider-response.json \
  --reviewed-bundle reviewed-lodash-2026.json \
  --out my-display-only-references.json
```

The local request and response must match Phase 5Z's exact provider shape and target. An example request for the `direct_deps_dev_ghsa` role:

```json
{
  "method": "GET",
  "endpoint": "/query",
  "payload": {"system": "npm", "pkg": "lodash", "ver": "4.17.15"}
}
```

Without `--reviewed-bundle`, the existing online source fetching behavior remains unchanged. With `--reviewed-bundle`, **all three local input arguments are required**. The original 3-provider research replay remains online because its outside original Miner captures are not included in this cache.

## Trusted and untrusted boundaries

- Frozen population: exactly six original GHSA IDs and their CVE aliases, original raw Git source SHA-1, exact `npm/lodash` entry and numeric introduced-inclusive/fixed-exclusive interval. All six must verify before an application result can be displayed.
- Source acquisition: downloads the six reviewed original documents, validates each complete SHA-1 and affected version semantics, then writes a **new, write-once** JSON file. No altered source content may be exported as verified.
- Offline invocation: checks a bounded regular JSON file, rejects duplicate JSON object keys, unexpected fields, wrong pinned Git commit, missing or extra source records, non-canonical base64 and tampered original Git bytes. The same original package/alias/interval checks run again using those bytes. No calls to the GitHub advisory source are necessary during consumption.
- Output: positive decisions remain `DISPLAY_REVIEWED_VERSION_APPLICABLE_REFERENCES_ONLY`, never a safety approval. The local caller's response **never** gets `original_external_capture_git_verified=true`. The offline source snapshot does not claim current advisory freshness.
- An attacker can edit any user-provided local provider request/response. No local flag can authenticate a payment, ownership or source provenance. The bundle verifies *reviewed advisory source bytes*, not a third-party Miner's identity or response authenticity.
- This is a fixed, research-selected historical reference set. Unknown advisory IDs fail closed. It is **not** a complete dependency vulnerability scanner, arbitrary-package resolver, comprehensive recall check, sealed holdout or general semantic evaluation model.

## Reproducibility proof

The Phase 5Z CI workflow now runs the Phase 5AA constructed adversarial suite on Python 3.11, 3.12 and 3.13. Its separate live-source job fetches the original three outside Miner reports and six reviewed source files, exports the bundle and reruns the same historical decisions with network access disabled for reviewed-source loading. It asserts equality of exact displayed and suppressed identities against the original online decision report and verifies the local CLI path with false `original_external_capture_git_verified` and false freshness values. Deliberately altered bundle bytes must fail.

The offline feature adds **zero new external independent observations**: the real-world sample remains three original outside reports, two direct target-bound answers, six reviewed GHSA records and one distinct inapplicable reference. The new negative inputs are author-constructed tests, not original new Miner responses or third-party developer adoption.

**CI evidence:** consult the most recent passing [Phase 5Z live source and Phase 5AA bundle workflow](../.github/workflows/phase5z-original-reviewed-advisory-consumption.yml). Do not claim this release is complete until the branch and final main workflows pass.
