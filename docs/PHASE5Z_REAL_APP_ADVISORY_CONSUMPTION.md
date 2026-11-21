# Phase 5Z — A security application that filters real Miner advisory claims

**FALSUM · Telegraph Season II Evaluators · SECURITY_REVIEW_GENERAL (plus distinct direct SECURITY_REVIEW family)**

## The downstream decision that matters

FALSUM now has an **executable application-consumption API**. Instead of deciding a response is trustworthy because HTTP status is 200 or a response has a paid flag, a consuming application performs two checks:

1. **Task identity:** Is this security output genuinely bound to the requested npm package and exact version? A generic 100-advisory feed from the original routed capture is denied.
2. **Claim applicability:** Do the exact independently maintained original GitHub-reviewed advisory records say each referenced GHSA/CVE concerns **npm lodash 4.17.15**, under its exact package name and numeric affected-version interval? Inapplicable references are suppressed before display.

The application returns **DISPLAY ONLY** for reviewed version-applicable advisory references, including each upstream source URL, immutable Git blob SHA-1, GHSA/CVE identifier and exact affected interval. It never reports that a package is safe, a vulnerability is exploitable, or that an external reported payment was independently settled.

## Three original public providers, not a fair network leaderboard

All three original outside records were [published by a separate PR Guard project](https://github.com/anvithagowda098/pr-guard) and are fetched from one immutable original external Git commit. The **six separately maintained GitHub-reviewed original advisory JSON files** are also downloaded and SHA-verified at a pinned original advisory-database Git commit.

| Original reported Miner | Original request channel | Original response | Expected downstream application action |
| --- | --- | --- | --- |
| 77003 | Routed canonical `SECURITY_REVIEW_GENERAL` | 100 unrelated unscoped GHSA records | Deny the entire feed |
| 190048 | Direct `GET /query`, receipt `SECURITY_REVIEW` | Six target-bound GHSA identifiers | Allow display of five reviewed applicable references, suppress one |
| 77010 | Direct `GET /query`, receipt `SECURITY_REVIEW` | Six target-bound OSV/CVE references | Allow display of five reviewed applicable references, suppress one |

The two inapplicable original references point to **the same one uniquely reviewed advisory**, GHSA-f23m-r3pf-42rh / CVE-2026-2950. The affected interval for **the exact package `npm / lodash`** begins at 4.17.23 and ends before 4.18.1. It does not contain the requested 4.17.15. Similarly named `lodash.*` subpackage ranges cannot be substituted for `lodash`.

**Never call this 12 new independent cases.** There are 12 reported advisory reference instances across two original Miner captures, six distinct reviewed advisories and one unique inapplicable advisory. Other references are *version-applicable according to reviewed records*, not independently proven exploitable or complete coverage.

**Never call this a fair same-Intent provider ranking.** The routed original receipt reports `SECURITY_REVIEW_GENERAL` and the direct receipts `SECURITY_REVIEW`; request bytes differ. Reported Miner IDs are distinct, but ownership independence and payment settlement are not authenticated. No new Telegraph request or paid execution is made.

## Preimplementation registration

The exact output contract, source population, original target, expected actions and major caveats were frozen **before writing the Phase 5Z implementation** in [Phase 5Z frozen application protocol](../data/phase5z-frozen-app-consumption-protocol.json), Git blob SHA-1 `46b42a68360e5f9011a2d60abd25db81176a4a73`.

The original protected source-selection protocols remain independently pinned:

- [Phase 5X original three-provider target observations](PHASE5X_ORIGINAL_THREE_MINER_LODASH_TARGET_EVIDENCE.md).
- [Phase 5Y original independently GitHub-reviewed version interval accuracy](PHASE5Y_INDEPENDENT_GHSA_VERSION_APPLICABILITY.md).

This stage **composes** those genuinely separate original external and reference sources into a usable downstream filter. It does not invent additional external source data.

## Use it

From the repository root, Python 3.11 or later:

~~~bash
python -m pip install --no-deps -e .

# End-to-end replay of all three actual published outside provider captures.
# Downloads and verifies nine original Git-blob-fingerprinted public files.
falsum filter-security-references --out original-safe-advisories.json

# Call the same strict filter on locally supplied request/response JSON.
# This mode never claims the caller input was an original captured Miner response.
falsum filter-security-references \
  --role direct_deps_dev_ghsa \
  --request-json my-request.json \
  --response-json my-response-body.json \
  --out my-sanitized-references.json
~~~

The local caller mode supports only the original fixed target and known original reviewed advisory roster. It is **not yet a general-purpose arbitrary-package resolver**. Unknown GHSA/CVE references, a mismatch in reported Miner identity or exact request target, an ambiguous alias, a malformed source, a forged original reference interval, or a missing original public Git record fail closed. The filter never promotes caller-supplied responses to independently authenticated original captures and never copies whole original third-party bodies to output.

### Production consumption pattern

An application may render items under `display_references` **only** after receiving `action=DISPLAY_REVIEWED_VERSION_APPLICABLE_REFERENCES_ONLY`; it should omit items under `suppressed_references`. Both lists carry provenance URLs and immutable review IDs to support independent checks. If the action is denial, show no claimed security advisories from that output. A separate security review is needed before approving a package, deployment, transaction or security-sensitive action.

The reference application is suitable for reproducible offline integration testing. The user must explicitly understand that **displaying reviewed version-applicable security advisories is not endorsing their correctness beyond the exact reviewed affected package/version range**.

## Actual original CI evidence

[Phase 5Z original upstream online verification workflow](../.github/workflows/phase5z-original-reviewed-advisory-consumption.yml) requires all Python 3.11–3.13 adversarial suites to pass, followed by an actual fetch of three original external capture Git blobs and six independently reviewed GitHub advisory blobs. It rejects forged package, version, provider, source identity or missing advisory list tests.

Record numerical outcomes and actual artifact hashes **only after** the online original-source job succeeds. Unit-test-generated normalized source rows are deliberately synthetic and cannot establish an original third-party capture.

## Honest competition limits

- **Real:** A bounded application can suppress an externally observed advisory false positive and decline an entirely unrelated reported-paid security feed.
- **Not proven:** A registered Telegraph evaluator, an improvement in canonical same-Intent routing or network leaderboard, app adoption by an outside developer, a trained model that beats baselines, expert-validated security accuracy, original outside paid settlement, comprehensive advisory recall or a secret independent holdout.
- **No demo or official submission:** This is a technical release and independently reproducible source-backed reference implementation, not the final hackathon entry.

The next evaluation improvement requires more genuinely comparable same-canonical-Intent Miner outputs, independent source adjudication, or an actual third-party integration. Additional author-built variations on the same three public examples cannot substitute for those.

## Verified actual original source verification outcome

The [original successful GitHub Actions run](https://github.com/Iniwura/falsum/actions/runs/44906868471) completed **4/4 jobs**: Python 3.11, 3.12 and 3.13 adversarial contracts plus a separate online source loader which actually retrieved **three original outside Miner Git blobs and six independently maintained reviewed advisory Git blobs**.

Its original unmodified source-verified aggregate yielded:

| Outside report | Original reference count | Sanitized display-only count | Suppressed | Security approval |
| --- | ---: | ---: | ---: | --- |
| Reported Miner 77003 routed | 100 unscoped | 0 | Entire feed denied | Never |
| Reported Miner 190048 direct | 6 | 5 | 1 version-inapplicable GHSA | Never |
| Reported Miner 77010 direct | 6 | 5 | 1 version-inapplicable CVE alias for the same GHSA | Never |

All application decisions include direct primary reviewed-source URLs and immutable Git SHA-1 provenance. The original source verified report exposes **no complete outside Miner response body**, no paid-request secrets and no user input. Local caller-supplied data is always reported as unverified; it can never set the original-capture proof flag.

**Original immutable evidence archive**: Actions artifact **14708530673**; original ZIP SHA-256 `bdc6dff92d144817f95349d8d08957bf6cc91f11ed1ece21c810ddb026191b6d`; contained safe aggregate JSON SHA-256 `68487eeb9c569257351f7be51d273d33fbab970fa1b63abb9001ddb0aa7f8165`.

[Permanent measured evidence ledger](../evidence/phase5z-2026-11-21-genuine-miner-advisory-consumption-output.json).

This original run measures **one applied version-inapplicability finding repeated by two different reported Miners**, not two distinct reviewed false-positive vulnerabilities. It also does not change Telegraph's live network rankings or establish any independent production integrator adoption.
