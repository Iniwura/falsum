# Phase 5E — Verify the actual public five-source release, not only old routes

**Telegraph Season II · Evaluators · SECURITY_REVIEW_GENERAL · November 19, 2026**

## The production mismatch

The exact [Phase 5D five-source implementation](https://github.com/Iniwura/falsum/pull/60) is merged and passed all 16 pull-request workflows. Yet the public Vercel alias still resolves to deployment dpl_3jwCXD1ygDetYJSqpsDYhtPXDFbz, commit a337de847806558b6078935fbdde46f2b4f5ea51 (older Phase 5A/PR #57). That deployment predates the fifth Flask public workbench. The original [Phase 4C production smoke test](../.github/workflows/phase4c-live-production-smoke.yml) checks the existing /proof/ model-score and / challenge routes and can pass even when /witness/ is stale. **A passing old-route smoke must not be presented as five-source release verification.**

A verified attempt to deploy the fully tested current main SHA 061a6a7dd82618e344adb98dd128ef69ec7565a3 to the original linked project returned Vercel **402 api-deployments-free-per-day** after more than 100 free-plan deploy requests in 24 hours. The environment does not have a Vercel CLI fallback. No other project, billing upgrade, or unstated production promotion was used. [Tracked release blocker](https://github.com/Iniwura/falsum/issues/61).

## November 20 verification update: latest production alias now assigned

The authenticated Vercel API now reports deployment **dpl_6F56yGJhrpHa7Qbg5jGQUB2Cfm66** as READY and targeted to **production**, for the reviewed main commit **f0f3ffec3e957223a422c31d5983247397e5b7bf** (Phase 5F PR #63). Its alias list explicitly contains **falsum-evidence-lab.vercel.app**, so the earlier per-day deployment-quota blocker has been resolved at the hosting-platform level. The earlier stale-alias and HTTP 402 observations above are preserved as historical observations, not current status claims.

**Live HTTPS byte-for-byte source content is not automatically proven by Vercel metadata.** Phase 5G closes this verification gap: after merging the workflow change to main, GitHub Actions will run the actual network-dependent Phase 5E proof (as well as its Python self-tests). This live job will remain excluded from pull-request checks and will refuse to produce a PASS if the public site is stale, protected, unreachable or not an exact five-source match.

## Independent live production freshness check

[Verifier](../src/falsum/phase5e_production_freshness.py) generates an expected source report from the real five-stage evidence:

- Four original immutable source-tested repairs across Koa/Hono/two LangChain patches
- A separate archived original Flask source/test execution protected by the exact original Actions ZIP SHA, parent/fix Git blobs, test source and fixed source
- Five stages across four repositories; 80 deterministic claim/receipt combinations: 10 SUPPORTED, 10 CONTRADICTED, 60 ABSTAIN

It fetches **only** these two public HTTPS paths from the existing alias:

- https://falsum-evidence-lab.vercel.app/witness/FIVE-AUTHENTIC-UPSTREAM-SOURCE-REGRESSIONS.json
- https://falsum-evidence-lab.vercel.app/witness/

The downloaded JSON must equal the entire locally authenticated report, not just a case count or app version string. The HTML must expose the populated source-data container and the new five-stage interface. A four-case alias, missing fifth Flask case, tampered Git source receipt, missing or extra JSON values, stale HTML or redirected endpoint makes the verifier **fail**. Live verification emits a write-once proof receipt including SHA-256s of the exact expected and actual canonical JSON and actual HTML. No secrets, paid inference, API keys, wallets or external human submissions are required.

The comparison cannot claim a deploy or release from a synthetic fixture. The --offline-json and --offline-html flags explicitly label the result OFFLINE_UNTRUSTED_FIXTURE, never as PUBLIC_HTTPS_VERCEL_ALIAS, even if all expected source facts match.

## Run once after the hosting quota resets

Run the strict actual public check from the exact reviewed main branch:

    PYTHONPATH=src python -m falsum.phase5e_production_freshness \
      --root . \
      --out phase5e-public-five-source-release-attestation.json

Or dispatch [Phase 5E production release verification](../.github/workflows/phase5e-live-production-source-freshness.yml) manually. As of Phase 5G, the workflow's three Python offline adversarial jobs still run in normal pull-request CI, but the **actual read-only public HTTPS byte-match also runs automatically for a reviewed push to main**. It never runs as a substitute for PR unit tests. On main release the live job retries a bounded six attempts, 15 seconds apart, to allow Vercel's alias mapping to settle. All failures remain failures; after the sixth unsuccessful live comparison no success artifact is produced. The manual dispatch remains available for an independent live rerun without changing source files.

The live check must produce PHASE5E_LIVE_PRODUCTION_FIVE_SOURCE_WITNESS_EXACTLY_MATCHES_REPRODUCIBLE_BUILD with actual_production_content_verified=true, 5 original source stages, 4 repositories and 80 constructed source-bound outcomes. It must not claim trained-model generalization, qualified human expert gold, new Anjoman rows, a registered evaluator, production exploitability, or official H2 entry.

## Release steps and acceptance

Once deployment capacity is available: verify the exact reviewed main SHA, create a preview in the **same Vercel project**, inspect preview /witness/, /proof/, /compare/, then release the reviewed version to the production alias. Execute the live Phase 5E check. Record Vercel deployment ID, SHA, alias, proof receipt and PASS in [issue #61](https://github.com/Iniwura/falsum/issues/61); only then close that issue. A stale alias remains an open launch blocker even though the local site and 16 CI workflows pass.

The honest evidence boundary is **verified historical source consistency**, not natural-language evaluator accuracy, model improvements or independent AppSec human adjudication. No demo/video or official hackathon entry is filed by this gate.
