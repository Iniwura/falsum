# FALSUM Phase 3I — Independent real runtime family: Requests 2023 proxy credentials

**This phase verifies a *second* historical library behavior family**, distinct from Phase 3H's Starlette directory containment. It runs the actual installed Requests 2.30.0 and 2.31.0 `Session.rebuild_proxies` implementations. No HTTP connection, HTTP redirect, secret, target application, exploitation attempt or externally provided source is involved.

## Authentic historical evidence

The original upstream Requests source and regression-test patch are pinned in [the original real-fix source queue](../data/real-fix-queue.json):

- [Exact Requests repair commit](https://github.com/psf/requests/commit/74ea7cf7a6a27a4eeb2ae24e162bcc942a6706d5) — `requests/sessions.py` only adds a `Proxy-Authorization` header for non-HTTPS when proxy credentials exist.
- [Upstream security advisory GHSA-j8r2-6x86-q33q](https://github.com/psf/requests/security/advisories/GHSA-j8r2-6x86-q33q), CVE-2023-32681.
- [Requests 2.31.0 release notes](https://github.com/psf/requests/releases/tag/v2.31.0) explicitly identify 2.30.0 as affected and 2.31.0 as the repair.

The source corpus already checked the exact upstream commit, single parent, source file post-fix Git blob and regression test post-fix Git blob. The Phase 3I runtime checks enforce these same identities and require each *installed* version to expose the correct `rebuild_proxies` implementation and source-file fingerprint.

## What this actually executes

Five hardcoded `requests.Request` objects are prepared in memory and passed into **the real installed** `Session.rebuild_proxies(prepared_request, proxies)` method. The only credential pair is a conspicuously artificial `falsum-test:never-a-secret`, the proxy address is `proxy.invalid`, and the target is `falsum.example.invalid`. `trust_env=False` forbids environment-derived proxy settings. The system **never calls `Session.send`, a transport adapter, or an HTTP endpoint**.

| Controlled behavior | Installed Requests 2.30.0 | Installed Requests 2.31.0 |
| --- | --- | --- |
| HTTPS + synthetic credentialed proxy | `Proxy-Authorization` present | Absent |
| HTTP + synthetic credentialed proxy | Present | Present |
| HTTPS + anonymous proxy | Absent | Absent |
| HTTPS + no proxy | Absent | Absent |
| HTTPS + no proxy + pre-existing fake header | Removed | Removed |

An expected header is checked against the **exact synthetic demo credential value** but neither the Base64 value nor actual credential text is written to the published reports. A failed or surprising observation terminates the CI job. All unchanged controls must stay identical across versions.

This establishes that the actual installed library's *proxy header reconstruction* is different on the published historical boundary. It does **not** simulate an actual network redirect or prove that any credential reached a destination server.

## Reproduce

Run offline tests using Python 3.11+:

```bash
PYTHONPATH=src:tests python -m unittest discover -s tests -p test_phase3i_requests_runtime.py -v
```

In a fresh Python 3.11 environment with `pip install requests==2.30.0`:

```bash
PYTHONPATH=src python -m falsum.phase3i_requests_runtime run \
  --version 2.30.0 \
  --queue data/real-fix-queue.json \
  --repo-root . \
  --out /tmp/requests-230.json
```

In a *separate fresh environment* with `pip install requests==2.31.0`, run the same command with `--version 2.31.0 --out /tmp/requests-231.json`. Then use any Python 3.11 environment to compare:

```bash
PYTHONPATH=src python -m falsum.phase3i_requests_runtime compare \
  --before /tmp/requests-230.json \
  --after /tmp/requests-231.json \
  --out /tmp/requests-two-release-delta.json
```

The [Phase 3I workflow](../.github/workflows/phase3i-requests-runtime.yml) isolates installation and execution for both versions, verifies package versions, runs source-bound tests, retains bounded evidence artifacts and fails unless the two real reports demonstrate the intended single behavior reversal. **Only a passing live workflow can substantiate that real installed framework behavior was observed; unit-test fixture results alone do not.**

## Research boundary and next milestone

Phase 3H and Phase 3I now cover two different categories: **filesystem path containment** and **proxy credential handling**. Both were *already researched and included in the public source corpus*, so neither is an untouched holdout or an independent AppSec reviewer judgment.

- **Zero** human-adjudicated labels, accepted Anjoman rows or registered evaluators are created in Phase 3I.
- **Zero** model scores are computed. The Phase 3D ModernBERT **0/2 contextual reversal** quality veto remains in effect.
- A passing historical runtime behavioral check is not sufficient for a claim of independent evaluator accuracy or a successful hackathon submission.

Next: freeze genuinely project- and version-disjoint evaluation material, request independent expert validation, and measure the actual model's context-sensitive ranking on those unseen tasks before retraining, registration or `/submit`.
