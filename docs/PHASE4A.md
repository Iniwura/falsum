# Phase 4A — genuine original-model scores on new pinned source catalogue cases

**12 November 2026. Research-only, external-label-free, no model release.**

## Question

Will FALSUM's **unchanged quarantined original ModernBERT LoRA** rank answers differently when the installed version changes from an affected release to a patched release?

Phase 3Y measured four failed before/after fact-reversal groups on known Axios and Django functions (4/8 provisional matches; **0/4 complete reversals**). Phase 3Z then generated six narrowly scoped, verifiable questions across *three other package projects*. Phase 4A passes the genuine source-verified Phase 3Z task/answer texts to the **pinned official Telegraph Foundation ONNX/WASI scoring runtime**, twice per input, and evaluates model-vs-catalogue agreement.

## Six frozen facts

The source is not written by this scoring job. It is the exact 13,479-byte verified Phase 3Z JSON from [successful source run #43286926731](https://github.com/Iniwura/falsum/actions/runs/43286926731), SHA256 **82347910cb443f2b1cbde565107dbbd280f40e884ca45f2abfd501a8a5d108a8**. This same digest is pinned in [our permanent receipt](../evidence/phase3z-2026-11-12-pinned-real-advisory-receipt.json) and rechecked before input generation. Phase 3Z verified the GitHub-reviewed advisory JSON's exact Git blobs at immutable commit b2a0c7d47ab94089f8774eacdc65ad80f2457170 and six actual not-yanked PyPI releases. It does not establish executable vulnerabilities or deployment reachability.

| New package project | Catalogue-affected version | Catalogue-fixed version | A/B candidate texts |
| --- | --- | --- | --- |
| docling-core | 2.48.3 | 2.48.4 | Identical |
| hydra-core | 1.3.7 | 1.3.8 | Identical |
| python-multipart | 0.0.25 | 0.0.26 | Identical |

Within each pair, the narrow expected source-catalogue preference changes **A to B**. Both trivial constant-choice baselines match **3/6**. This is a real, mechanically derived *version-interval fact*, not professional security-review accuracy. These are public source examples, neither an untouched model-pretraining holdout nor independently AppSec-approved preference labels.

## How genuine scoring is verified

[Official runtime workflow](../.github/workflows/phase4a-real-version-model-probe.yml) downloads the actual successful Phase 3Z source artifact and authenticates the SHA256 bytes. It then downloads the unchanged original Phase 3B research LoRA from its recorded CI artifact at run 41304788714, checks the **3d269cc0…** model fingerprint, and downloads checksum-pinned Foundation JSON, ONNX model, WASI runtime and official tokenizer. The Go scorer is built from the pinned Telegraph adapter kit commit 1ed063e2f0066cfaf0e124d66ec6a17b7a6121fd.

The tokenization stage refuses truncation and accepts only correctly framed real tokenizer inputs (up to 256 tokens, below the official 512 cap). For six source conditions and two candidate answers, it runs **12 independent score inputs / 24 repeat-verified genuine Foundation inferences**. The audit requires the *official* model manifest, exact Foundation/model/tokenizer hashes, loaded WASI engine, stage-1 verification, repeat consistency and actual f32 score bits.

The final report contains all six scores and preferences, full-reversal group checks, source provenance, frozen-input hash, exact score bit patterns and constant-A/B baseline results. **CI success means provenance and scoring integrity, not that the evaluator performed well.** A 0/3 or 3/3 model reversal result is reported verbatim. Any error fails CI; it is never replaced with mock scores.

## Reproduce

Run the same [GitHub Actions workflow](../.github/workflows/phase4a-real-version-model-probe.yml) from the public repository; it requires no wallet, real secret or production application. The source stage must retrieve the exact Phase 3Z archive while it is retained by GitHub Actions. The known research-LoRA artifact also remains time-limited. The resulting artifact retains all real score receipts and inputs.

Offline test-only guard checks:

~~~bash
PYTHONPATH=src python -m unittest discover -s tests -p test_phase4a_real_model_probe.py -v
~~~

The unit test intentionally uses **synthetic tokens and fake scores** to challenge all parser and release boundaries. These are NOT actual model measurements. Only the genuine source-bound official inference workflow's report can establish observed old-model preferences.


## Actual original-model observations — 12 November 2026

**Original runtime success ≠ model quality success.** The actual [Foundation ONNX/WASI scoring workflow](https://github.com/Iniwura/falsum/actions/runs/43289770022) completed with **12 genuine model score packets / 24 bit-consistent inferences**. [Original official output artifact](https://github.com/Iniwura/falsum/actions/runs/43289770022/artifacts/13976527819) contains the frozen input IDs, official manifest, individual f32 bit-encoded scores, and final auditor report. [Permanent bit-exact failure record](../evidence/phase4a-2026-11-12-real-original-model-failure.json) is independently checked by the release-blocking CI stage.

| Package | Source-affected version (expected A) | Source-fixed version (expected B) | Model choice on both | Correct context reversal |
| --- | --- | --- | --- | --- |
| docling-core | 2.48.3 | 2.48.4 | A / A | **Fail** |
| hydra-core | 1.3.7 | 1.3.8 | A / A | **Fail** |
| python-multipart | 0.0.25 | 0.0.26 | A / A | **Fail** |

- **3/6** agreement with the narrow, mechanically derived GHSA advisory-version facts.
- **0/3** complete affected-to-fixed preference reversals; the model did not change its winner in any of the three changed-version groups.
- **3/6** matches for constant-A **and** constant-B trivial baselines on this balanced test.
- Exact result JSON SHA-256: **9a7dc55b7838fba00504663ea2a06fba3fddb8b344f003f5c57565af0d8361df**. Source report SHA-256: **82347910cb443f2b1cbde565107dbbd280f40e884ca45f2abfd501a8a5d108a8**.

This result is **not** evidence that 50% is general AppSec accuracy. It is a measured tendency to choose the same answer text despite an explicit dependency-version change, on three public, source-verified examples. These were previously unstudied by our source-case pipeline but are public and not demonstrably absent from model pretraining.

**Decision: failed quality gate; do not register the original LoRA.** A model that only matches a constant-choice heuristic here is not ready. For the November 17 finish line, focus on stronger independently verifiable evaluation material and genuine external review. A replacement evaluator must be evaluated on new, sealed and independently adjudicated material, without using these public failed examples as an invisible holdout.

## Release decision

Until independent review, a new project-disjoint sealed test set, and satisfactory comparative model results exist, the original LoRA remains quarantined. **Phase 4A never retrains or registers** anything. It does not alter the 20 previously Anjoman-eligible user material rows, mint new network-eligible records, or modify the production UI. Phase 4A is a diagnostic step toward a robust evaluation-material submission, not independent evidence of security accuracy or a better evaluator.
