# Phase 3H — Two real installed Starlette versions, one controlled security-boundary difference

**Status: research-only execution evidence.** This phase compares a historical affected and patched *library runtime*, not an arbitrary repository audit, independently adjudicated security answer, LoRA model improvement, or accepted Telegraph evaluator contribution.

## Scope and provenance

The pinned [upstream Starlette security patch](https://github.com/Kludex/starlette/commit/1797de464124b090f10cf570441e8292936d63e3), [GHSA-v5gw-mw7f-84px](https://github.com/Kludex/starlette/security/advisories/GHSA-v5gw-mw7f-84px) and [release notes](https://www.starlette.io/release-notes/) document the 2023 StaticFiles containment change from character-based `os.path.commonprefix` to path-aware `os.path.commonpath`. The historical `CVE-2023-29159` affects the 0.26.1 release and was corrected in 0.27.0. The existing Phase 3F source manifest pins the exact fix commit, source Git blob and upstream regression-test Git blob.

Unlike Phase 3F's upstream *source-only* observation, Phase 3H invokes the **actual installed** `StaticFiles.get_path` and `get_response` functions from both exact historical framework versions, in separate GitHub Actions jobs. Only local, temporary synthetic directories are created. There is no web server, HTTP request, network destination, customer data or arbitrary code execution from reviewer input.

### What the controlled test must demonstrate

| Synthetic temporary path | Historical 0.26.1 | Fixed 0.27.0 |
| --- | --- | --- |
| In-root `index.txt` | 200 | 200 |
| Nonexistent `does-not-exist.txt` | 404 | 404 |
| Outside-root sibling with unrelated directory name | 404 | 404 |
| Outside-root sibling sharing the permitted root's name prefix | **200** | **404** |

The input is hardcoded and the sibling file contains only the literal `harmless-falsum-review-fixture-not-sensitive`. A 200 indicates the real installed old library returns a FileResponse for the intentionally allowlisted harmless outside-root fixture. The fixed release must reject it. The three controls must behave identically across both versions. The tool validates that the returned path cannot point anywhere other than the exact test fixture.

If any version is wrong, either runtime code does not match the upstream behavior boundary, source identity was modified, the runtime result differs, or the three unaffected controls change, **the CI job fails**. The workflow independently checks the installed distribution metadata and records a SHA256 of the actual runtime implementation, with a separate `pip freeze` manifest for each matrix job.

## Reproduction (CI is the authoritative cross-version execution)

Run the offline tamper-focused unit tests from the repository:

```bash
PYTHONPATH=src:tests python -m unittest discover -s tests -p test_phase3h_starlette_runtime.py -v
```

Two fresh Python 3.11 environments are required for the real dynamic check, one with `starlette==0.26.1` and the other with `starlette==0.27.0`. In each environment:

```bash
PYTHONPATH=src python -m falsum.phase3h_starlette_runtime run \
  --version 0.26.1 \
  --queue data/real-fix-train-candidates.json \
  --repo-root . \
  --out /tmp/STARLETTE-0.26.1-REAL-RUNTIME.json
```

Replace the version and output filename in the second environment, then compare the two generated JSON reports using:

```bash
PYTHONPATH=src python -m falsum.phase3h_starlette_runtime compare \
  --old /tmp/STARLETTE-0.26.1-REAL-RUNTIME.json \
  --fixed /tmp/STARLETTE-0.27.0-REAL-RUNTIME.json \
  --out /tmp/REAL-VERSION-CONTRAST-RESEARCH-ONLY.json
```

The [Phase 3H Actions workflow](../.github/workflows/phase3h-starlette-real-delta.yml) runs both environments in isolated jobs and fails unless the before/after difference is observed *and* the negative controls are unchanged. A JSON report alone is not trusted attestation; provenance comes from GitHub's actual passing workflow and package installation logs.

## What this establishes and what it does not

**Establishes, once CI has passed:** The installed historical Starlette versions have different behavior for a bounded, artificially created same-prefix directory sibling; the observed difference matches the cited upstream security patch. This adds actual runtime observation rather than relying only on published source diffs.

**Does not establish:** An exploit in another public project or in a production deployment; the current security of an arbitrary user's application; zero risk for the patched library in every configuration; independent AppSec expert labels; newly eligible question-pair submissions to Anjoman; a passing model accuracy score; a trained model improvement; or any live Telegraph registration.

The Starlette project and advisory were already studied for Phase 3F. This example is **not a fresh independent holdout** and must not be used as an alleged model generalization benchmark. The prior `ModernBERT` **0/2** Phase 3D context-reversal failure and release veto are unchanged.

**Next:** add a second distinct historical behavior family; obtain actual AppSec reviewer judgments; define genuinely disjoint model evaluation, then re-run the genuine Foundation/LoRA scoring before considering `/submit`.
