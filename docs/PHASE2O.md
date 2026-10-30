# Phase 2O — Real public security-fix evidence (four independently maintained projects)

**Status (30 October 2026): actual upstream commits verified; all judgments unreviewed.** FALSUM has moved past its exclusively fictional PR benchmark by constructing an evidence packet from **real, public security-fix changes**. This adds source realism, *not* a gold-standard evaluator dataset. Previous ModernBERT results are not transferred to this material without a real checkpoint evaluation.

## Pinned cases

| Real upstream project | Published issue | Immutable patch | Critical applicability boundary |
| --- | --- | --- | --- |
| [Requests](https://github.com/psf/requests) | [CVE-2023-32681](https://github.com/psf/requests/security/advisories/GHSA-j8r2-6x86-q33q) | [74ea7cf7a6a27a4eeb2ae24e162bcc942a6706d5](https://github.com/psf/requests/commit/74ea7cf7a6a27a4eeb2ae24e162bcc942a6706d5) | Header leakage is conditional on the configured credentialed proxy and redirects to HTTPS, not every request |
| [aiohttp](https://github.com/aio-libs/aiohttp) | [CVE-2024-23334](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-5h86-8mv2-jq9f) | [1c335944d6a8b1298baf179b7c0b3069f10c514b](https://github.com/aio-libs/aiohttp/commit/1c335944d6a8b1298baf179b7c0b3069f10c514b) | Static-route path traversal requires the relevant static-file configuration, notably follow_symlinks behavior |
| [Jinja](https://github.com/pallets/jinja) | [CVE-2025-27516](https://github.com/pallets/jinja/security/advisories/GHSA-cpwx-vrp4-4pq7) | [065334d1ee5b7210e1a0a93c37238c86858f2af7](https://github.com/pallets/jinja/commit/065334d1ee5b7210e1a0a93c37238c86858f2af7) | Sandbox escape presupposes attacker-controlled templates, not simply Jinja being installed |
| [Axios](https://github.com/axios/axios) | [CVE-2025-27152](https://github.com/axios/axios/security/advisories/GHSA-jr5f-v2jv-69x6) | [02c3c69ced0f8fd86407c23203835892313d7fde](https://github.com/axios/axios/commit/02c3c69ced0f8fd86407c23203835892313d7fde) | JavaScript absolute-URL override behavior with baseURL. The 0.x fix adds an **opt-in allowAbsoluteUrls:false guard**; do NOT assume all default usage becomes safe |

The short descriptions are **source-publication claims to examine**, not independent assessor findings. Reviewers may agree, disagree, or mark uncertain. None is a fully independent, held-out model-evaluation row.

## New implementation

- **Pinned queue**: [data/real-fix-queue.json](../data/real-fix-queue.json) stores each full commit SHA, its exact single parent SHA, target source path and Git blob object ID, target regression-test path and Git blob ID, GHSA, CVE, and a deployment hypothesis to verify. Exactly one project/family per case prevents accidental project reuse in this seed.
- **Immutable change audit**: [src/falsum/real_fix_corpus.py](../src/falsum/real_fix_corpus.py) fetches the official public GitHub API commit at its immutable SHA; requires the expected parent, exact canonical commit URL, file statuses and Git blob IDs; and captures the original unified code and regression-test patches. It rejects missing/oversized patches and drifted identifiers. It calculates SHA-256 digests for the patch bytes and canonical case manifest.
- **Actual parent-to-fix replay**: [src/falsum/real_fix_replay.py](../src/falsum/real_fix_replay.py) fetches the original public source/test file bytes at BOTH the pinned parent and fix commits, computes actual Git blob digests, applies the unified hunks with zero fuzz and strict line counts, and requires a byte-for-byte reconstruction of the upstream post-fix file. Code and tests are checked separately: 8 file transitions for 4 cases.
- **Reviewer packet**: generates one question set per case, with precise diff, upstream public advisory link, regression-test diff, provenance and applicability prompts. It deliberately supplies **NO candidate chosen/rejected preference, no independent validation attestation, and no automatic promotion to Anjoman eligible material**.
- **Offline adversarial tests**: reject wrong parents, wrong source or test blob IDs, changed source lines, truncated patches, cross-project reuse, forged status, mismatched replay, wrong line counts and unsafe paths.

## Reproducible commands

Using Python 3.11+ and outbound GitHub access:

~~~bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_real_fix_*.py' -v
PYTHONPATH=src python -m falsum.real_fix_corpus \
  --queue data/real-fix-queue.json \
  --out /tmp/real-source-evidence.json \
  --reviewer-out /tmp/real-expert-questions.json
PYTHONPATH=src python -m falsum.real_fix_replay \
  --evidence /tmp/real-source-evidence.json \
  --out /tmp/real-patch-replay.json
~~~

The CLI deliberately refuses overwriting existing output. The official [real-fix evidence workflow](../.github/workflows/real-fix-evidence.yml) runs these operations and uploads a short-lived, explicitly quarantined artifact. GitHub network or source failures fail the job instead of being relabeled as correctness.

**Four-project verification update (30 October 2026):** [CI run 41130722345](https://github.com/Iniwura/falsum/actions/runs/41130722345) verified 4 immutable public patch commits, 8 exact source/test file transitions, and 6 generated pre-fix questions within ModernBERT's static token budget. Longest was 286 of 384 permitted task tokens. See [Phase 2P](PHASE2P.md) for the separately quarantined model prompts and provenance.

## What this does not establish

- **Security answer ground truth**: The GitHub repository publishes a security fix; we have not had an independent reviewer validate the answer FALSUM should prefer under each deployment context.
- **Independent generalization**: Four repositories across four vulnerability classes cannot establish model accuracy, and all references are public. They have not been used as a sealed or untouched test benchmark.
- **A valid negative**: An applied patch may repair a specific defect, but this does NOT prove the whole project is safe or that a generic clean security review is correct. We deliberately do not label the post-fix revision as "secure".
- **Telegraph readiness**: There are zero independently approved case labels, no valid real-world test score, no verified ONNX/WASM deployment or active evaluator registration.

## Next evidence gate

Independent AppSec reviewers should review the source-fix and tests without relying on a generated preferred answer, cite precise lines and deployment prerequisites, and state limitations and uncertainty. Lock project-separated train/validation/holdout partitions *before* producing actual pairwise preference labels. Only verified, carefully scoped labels should become candidate data; they must still satisfy Anjoman's separate eligibility gate. The [existing external review request](https://github.com/Iniwura/falsum/issues/1) remains open.

The four-project, Python/JavaScript evidence corpus is deliberately distinct from the fictional PR fixtures and from the training input that produced the initial ModernBERT pilot.
