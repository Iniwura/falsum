# Phase 4R — Actual upstream before/after regression execution

**FALSUM · Telegraph H2 Evaluators · SECURITY_REVIEW_GENERAL · 18 November 2026**

## Why this check matters

Previous Phases 4P–4Q checked exact upstream source/test Git commit and blob identities and performed a source-bound AI review. That was evidence of authentic source, **not proof the historical tests were actually executed**. Phase 4R adds a genuine, independently rerunnable runtime counterfactual for two previously unseen upstream codebases, with the source and test file pinned to the SHA-1 Git blob IDs from the Phase 4P freeze.

[Real GitHub Actions workflow](../.github/workflows/phase4r-real-upstream-regression.yml) · [Fail-closed Python receipt validator](../src/falsum/phase4r_real_upstream_regression.py) · [Adversarial tests](../tests/test_phase4r_real_upstream_regression.py)

## Three executions per case

1. **Parent original control (expected PASS).** Checkout the exact public original upstream parent SHA in a clean Git worktree. Install its pinned project dependencies with install hooks disabled. Run its actual pre-fix upstream tests.
2. **Parent plus fixed upstream regression (expected FAIL).** Keep the original parent source SHA byte-identical; replace **only** the selected test file with the exact regression test file from the fixed upstream SHA. Execute the newly introduced security regression and confirm an expected behavioral assertion failure, not a missing dependency, compilation error or timeout.
3. **Fixed source plus identical fixed upstream regression (expected PASS).** Checkout the exact fixed upstream Git commit, use its original pinned test file, run the same new security test and require success. Git SHA, direct parent relationship, source/test Git blob hashes, named test and all three exit statuses must agree.

A green result proves a **narrow historical branch behavior change observed through the real project's own regression runner**, not a universal security guarantee, live browser exploit, deployment assessment, trained evaluator improvement or independent AppSec gold label. A missing test or unexpected environment failure blocks the result.

## Case A: Koa 3's protocol-relative redirect

Git repository: `koajs/koa`. Parent `433b20c9e5954113e8d7a23a25e9d5bb750c3034`; fix `769fd75cc6b30d72493b370b5a3ae2332ca03c5b`. Test `__tests__/response/back.test.js` using upstream `node:test` and Node 24. The new upstream regression named “should fix Trailing Double-Slash security issue” asserts that the untrusted `//evil.com/login/` Referrer falls back to a local path. The old immediate `referrer.startsWith('/')` early branch accepts that value. The fixed source removes the bypass.

**Expected counterfactual error:** assertion failure showing the unsafe protocol-relative location rather than the fallback. The changed upstream security test is **not authored by FALSUM**.

**Specific limit:** the fixed Koa code compares `url.host` to `ctx.host`, not full `URL.origin`. It cannot be promoted as a universal same-origin/scheme-preserving sanitizer. Production exploitability remains unknown.

## Case B: Hono's `text/ping` CSRF filter

Git repository: `honojs/hono`. Parent `d88fab372415277a9e540e895650943dd08eef4a`; fix `bf16471913b5199212dac33f5d170f94745dd26a`. Test `src/middleware/csrf/index.test.ts`, using the upstream Vitest runner and `pnpm@12.6.0` with Node 24. The new upstream `hyperlink auditing` block tests `text/ping` with MIME case variation, cross-origin 403/no-handler, and same-origin success.

**Expected counterfactual error:** cross-origin parent responds **200** when the fixed test expects **403**. The fixed source adds `text/ping` to the CSRF content-type regular expression, so the existing origin and fetch-site checks become effective for this MIME type.

**Specific limit:** the upstream test simulates HTTP request headers with `app.request()`, not a real browser hyperlink audit with victim cookies, a state-changing application handler or live deployment. That must not be invented as an end-to-end browser exploit.

## Evidence and safety boundaries

The checkout is pinned by immutable complete Git SHA, not `main`, a moving release tag or package registry metadata. Source and test file hashes are checked before package installation and again after execution. The direct Git parent of the fixed commit is checked. A fixed regression that fails to load, is skipped, fails for a missing package, or passes on the vulnerable parent is **not accepted** as a security finding.

The workflow has **read-only GitHub permissions**. Package installs use pinned `package-lock.json` or `pnpm-lock.yaml`, with lifecycle scripts disabled, and run only public upstream tests. CI artifacts contain result counts, source/test hashes and log hashes but not original private Telegraph evaluation prompts or answers. No actual malicious outbound payload, real user tokens, paid Telegraph requests or customer data are required.

**Source proof ≠ independently verified model labels.** Phase 4R does not invent human reviewers, add new Anjoman Eligible preference pairs, register an evaluator adapter, measure new hidden scoring, or prove a real-world exploit. It improves the *mechanistic accuracy* and reproducibility of FALSUM's public evaluation material.

## How to inspect

Open the [workflow](../.github/workflows/phase4r-real-upstream-regression.yml) and each `koa`/`hono` matrix job. Each produces a compact JSON proof if and only if all three executions and all Git/blob/assertion controls pass. You can reproduce from the repository using `workflow_dispatch` after checking the pinned public source.

If the dependency package or upstream runner cannot be installed, the matrix job must remain red; **do not infer counterfactual correctness from code inspection or from simulated/unit tests written inside FALSUM**. Any environment limitation should be dated, documented and repaired before promotion.

The LangChain Core two-stage source case is retained as [unexecuted upstream patch evidence](PHASE4P_OPEN_RESPONSE_SOURCE_REVIEW.md) until a comparable repeatable real suite is available. It is not silently included in the executed-case numerator.

**Internal deadline target:** November 22, without lowering the evidence or acceptance bar. **Official H2 deadline:** December 1, 2026, 23:59 UTC. Demo work is still paused by operator instruction.
