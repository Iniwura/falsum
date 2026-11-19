# Phase 4Z — First new source-project security test after the four-case freeze

**FALSUM · Telegraph Season II · Evaluators · `SECURITY_REVIEW_GENERAL` · November 19, 2026**

**Status: proposed source case until the actual new GitHub Actions run passes.** This case was selected by the FALSUM researcher after previous model-development work. It is **not an independent reviewer nomination, a blind model holdout or scored model generalization**.

[Authentic upstream Flask patch](https://github.com/pallets/flask/commit/8705dd39c4fa563ea0fe0bf84c85da8fcc98b88d) · [Published GHSA-m2qf-hxjv-5gpq](https://github.com/pallets/flask/security/advisories/GHSA-m2qf-hxjv-5gpq) · [Frozen source/test selection](../data/phase4z-flask-new-source-lock.json) · [Actual execution workflow](../.github/workflows/phase4z-flask-upstream-regression.yml) · [Verifier](../src/falsum/phase4z_flask_upstream_runtime.py).

## Why Flask is a materially new case

The existing four authenticated FALSUM upstream test witnesses cover Koa redirects, Hono CSRF and two different LangChain prompt loader repairs. Flask's historical permanent-session cookie cache-header issue is a **different upstream project and a different security mechanism**. FALSUM had not previously included this Flask case in its four-stage source-evidence index. This broadens public candidate source coverage, without claiming that the original trained model correctly judges it.

The upstream fix addresses **missing `Vary: Cookie` when a permanent session cookie is refreshed without application code accessing or changing session state**. Depending on a shared cache's configuration, the omitted header can allow the response with a renewed session cookie to be cached in a way that is not partitioned by Cookie. A controlled in-process Flask test is **not** evidence that any deployed cache disclosed a real user's cookie.

## Exact frozen upstream source and test

| Pin | Verified public Git identity |
| --- | --- |
| Repository | `pallets/flask` |
| Single direct parent | `9532cba45d2339e90ebf04f178b1e4f2064e7328` |
| Original upstream fix | `8705dd39c4fa563ea0fe0bf84c85da8fcc98b88d` |
| Source | `src/flask/sessions.py` · parent blob `1334184e...` · fix blob `e5650d68...` |
| Test | `tests/test_basic.py` · parent blob `32b41b63...` · fixed-author blob `ca373dca...` |
| Original upstream baseline | `test_session_vary_cookie` |
| Original upstream added regression | `test_session_refresh_vary` |
| Public advisory | `GHSA-m2qf-hxjv-5gpq` · `CVE-2023-30861` |

The often-cited `70f906c51ce4...` security fix reference is a **merge commit with two parents**, so it is **not** the correct single-parent counterfactual stage for our verifier. The above `8705dd39...` implementation commit has exactly the pinned `9532cba4...` direct parent and includes the upstream-authored source/test changes.

## The required three source executions

1. **Unmodified original parent:** execute the original upstream `test_session_vary_cookie` against the exact old commit. Require PASS to show the legitimate existing session-header behavior still works.
2. **Old source + new upstream test:** copy only the **fixed commit's exact upstream test file** onto the old commit worktree; retain the old source byte-identical. Run the newly added `test_session_refresh_vary`. Require FAIL for the expected `Vary` header assertion/key error. A missing dependency, missing test, import failure, or setup error is **not** a valid negative result.
3. **Original fixed source + identical new upstream test:** run the identical test on the original fixed commit. Require PASS. Recheck both source/test Git blob identities and that the fixed commit has exactly one known parent.

The [Phase 4Z workflow](../.github/workflows/phase4z-flask-upstream-regression.yml) uses Python 3.11, controlled historical compatible dependencies and only the upstream Flask test client. It runs in GitHub Actions without opening a web server, contacting a target, using real credentials, querying a paid API or writing customer data. It retains the bounded JSON result and SHA-256 log digests if verification succeeds.

Run the adversarial integrity checks locally, without installing Flask:

```bash
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_phase4z_flask_upstream_runtime.py' -v
```

**This command alone does not reproduce the actual Flask fix.** For source-execution proof, check the new GitHub Actions run and its real checkout, pytest, return-code and verifier logs. Do not turn a synthetic/mock unit fixture into live proof. A failed or missing CI run means the new case is **unverified**.

## Evaluation limits that cannot be skipped

- **New public candidate upstream project: 1**, but **new independent human security gold labels: 0**.
- **New model scored on the Flask case: 0**. The quarantined LoRA's previous negative score is unchanged.
- **Previously admitted four-case deterministic typed checker: unchanged**. A new Flask source case isn't automatically accepted by a verifier hard-coded to four authenticated receipts. It must gain an authenticated case-specific receipt and explicit source admission before that evaluator could judge Flask regression claims.
- **Fresh independent blind holdout: not established**. This was researcher-selected and public historical code; reviewers and pretrained models may have been exposed. The stronger externally selected and preregistered challenge protocol is tracked separately in [new-case nominations #54](https://github.com/Iniwura/falsum/issues/54).
- **No independent AppSec certification, deployed exploit verification, new Anjoman Eligible row, accepted bounty, registered evaluator adapter or official H2 submission** comes from this source test.

One actual new test is useful **mechanistic coverage evidence**, not by itself the measurement-improvement proof needed to win the Evaluators track. A future score must show unchanged evaluator outputs on externally selected new cases, credible independent adjudication, baselines, failures and abstention/coverage rates.
