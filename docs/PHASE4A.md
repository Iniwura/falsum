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

## Release decision

Until independent review, a new project-disjoint sealed test set, and satisfactory comparative model results exist, the original LoRA remains quarantined. **Phase 4A never retrains or registers** anything. It does not alter the 20 previously Anjoman-eligible user material rows, mint new network-eligible records, or modify the production UI. Phase 4A is a diagnostic step toward a robust evaluation-material submission, not independent evidence of security accuracy or a better evaluator.
