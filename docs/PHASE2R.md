# Phase 2R — Actual Telegraph ABI-v2 research WASM build

**Result on 30 October 2026: ONNX export, WASI compilation, official packaging and deterministic byte identity all PASSED.** The resulting module is **QUARANTINED** and **NOT eligible for registration**. Its underlying trained model performed poorly on contextual code reviews.

## Immutable input and evidence

The official [successful build run 41132003351](https://github.com/Iniwura/falsum/actions/runs/41132003351) used:

- Original CPU research checkpoint: [context-training run 41126779406](https://github.com/Iniwura/falsum/actions/runs/41126779406), artifact 13011655915. It was produced from **58 automatically drafted, unreviewed** preference comparisons.
- Official Telegraph exporter/packager: [telegraphprotocol/telegraph-wasm-baseline](https://github.com/telegraphprotocol/telegraph-wasm-baseline) pinned at commit **5fa5d68bbcf76aaa2093c5d0578f53462bc0e36e**.
- Backbone: **answerdotai/ModernBERT-base**, official V2 tokenizer, fp32 merged LoRA reward model.
- Before running export, the workflow verified the SHA-256 of all actual LoRA adapter files against the saved score report and research decision. The prior decision stayed **BLOCKED_RESEARCH_ONLY**, registration authorization false, independent reviews zero and PR validation accuracy **1/4 (25%)**.
- No reward dataset, model or artifact was uploaded to Anjoman or registered on Telegraph.

## Real build chain

1. Download archived official V2 pilot checkpoint, verify source decision and actual local adapter hashes.
2. Invoke the official ONNX exporter to merge ModernBERT and LoRA in CPU float32; output model has dynamic sequence length, input_ids and attention_mask and one score logit.
3. Use the official Rust bake_wasm.sh and oxionnx WASI guest to embed the real model in a wasm32-wasip1 binary with an input-file command interface.
4. Package the resulting guest through the actual official Go adapterbuild CLI. The intent catalog resolves **SECURITY_REVIEW_GENERAL to hybrid** (not judgment-only); builder writes ABI v2 metadata, checks WASI shape and compiles the artifact, and packages twice to demand byte-identical output.
5. Upload a **research-only** short-lived artifact containing the actual final WASM, manifest, export audit and logs, but no network registration or publishing.

## Verified model / package identities

| Artifact / property | Measured value |
| --- | --- |
| Model ONNX size | **599,024,135 bytes** |
| ONNX SHA-256 | **3f373ea41ae27c64931798cf7b5a7037ed2beeaa0ca5be047ce5c118e68df91d** |
| Final model WASM size | **601,181,412 bytes** |
| Final WASM SHA-256 | **52db6ad999cd262af915b6b908dcead7920bc08036cdfae01fee60bfd196d6e8** |
| Final WASM Keccak-256 | **0x8aa7a9560f7b40d3f1358a26d6b5e8522729d388e82455e1ab3fa76d21015d92** |
| ABI / runtime / class | **2 / onnx_f32 / hybrid** |
| Token cap | **512** |
| Official deterministic packaging | **2 builds, identical SHA-256** |
| Official packager structural verification | **true** |
| Exporter PyTorch fixed-input reference | **-0.4765053391456604** |
| Context-sensitive PR validation of the underlying model | **1/4 (25%)** |
| Independent human-validated security data | **0** |
| Anjoman eligible rows / network registration | **0 / none** |

The package's hexadecimal and SHA identifiers come directly from the official GitHub Actions log and attached manifest, not a filename guess.

[Download the archived experimental WASM and manifest](https://github.com/Iniwura/falsum/actions/runs/41132003351/artifacts/13013677262). The uploaded artifact is roughly 556 MB compressed and is scheduled to expire **2 November 2026 at 21:36 UTC**. Do not distribute or submit it as a reliable evaluator.

## Verified REAL WASI model execution on the same checkpoint

The independent [actual Wazero execution workflow 41132583676](https://github.com/Iniwura/falsum/actions/runs/41132583676) completed **successfully**. It downloaded the official packaged research WASM from the earlier run, rechecked the exact **601,181,412-byte** package's SHA-256, official ABI v2/hybrid metadata and source research quarantine, and executed the module with the same ten token IDs used in the official Python export.

| Model scorer | Measured float32 output |
| --- | ---: |
| Original PyTorch merged LoRA scorer | -0.4765053391456604 |
| Actual Wazero WASI packaged module | -0.4765051305294037 |
| Absolute score difference | **0.0000002086162567138672** |
| WASI execution time reported | **9,171 ms** |

The predeclared maximum permitted absolute delta was **0.05**, so the actual difference passed by a large margin. This provides **single-input numerical fidelity evidence**, not a ranking-quality or live-node acceptance score. The successful [short-lived score report artifact](https://github.com/Iniwura/falsum/actions/runs/41132583676/artifacts/13013642937) expires on **6 November 2026**.

The scored execution had **0 approved human review labels**, **0 network-eligible training rows**, and **no registration/publishing**. Wazero execution is not equivalent to the network's own module acceptance or multi-candidate ranking under its deadline and resource constraints.

## Important limits and next technical checks

**Official packaging success only proves structural feasibility**, not model fidelity, execution under the target network's node, or answer-ranking quality. The official builder checks the WASI command shape and compiles it; the node's actual fixed smoke score, time and resource limits are a separate step.

To probe execution rather than only package shape, the repository includes:

- [tools/research_wasi_smoke.go](../tools/research_wasi_smoke.go), a Wazero WASI runner pinned to the exact artifact SHA and official exporter input token IDs. It compares the module's actual finite FP32 score against the PyTorch export reference with a declared maximum absolute difference of 0.05.
- [The actual runtime smoke workflow](../.github/workflows/research-wasi-smoke.yml). It consumes the archived WASM without retraining or repackaging and archives its measurement or failure logs. That workflow now **passed** on one frozen input, with an absolute score delta of about 2.09e-7; see the measured results above.

Even if one runtime score matches, that would NOT establish the evaluator ranks security answers correctly. A real held-out, independently reviewed benchmark, correct hybrid comparator integration and acceptance by the network are still mandatory.

## Permanent, inspectable evidence after artifact expiration

The short-lived 601 MB GitHub artifact is not the only record. [A compact source-controlled evidence manifest](../evidence/research-wasm-runtime-2026-10-30.json) retains the official package hashes, ABI/class metadata, exact immutable kit commit, two-build reproducibility, actual WASI score and all unverified/blocked research status flags, linking to the primary GitHub Actions logs. Its [regression tests](../tests/test_research_wasm_evidence.py) reject drift toward invented eligibility or numerical results. This is an auditable transcription of CI evidence, not cryptographically signed network acceptance.

## Overall status

The builder milestone proves we can technically create an official-format model package on GitHub-hosted CPU resources without owning a GPU or VPS. **It does not rescue an ineffective model** or establish question-pair contribution eligibility. Further model training should wait on independent AppSec labels, more realistically scoped security review questions and a larger project-separated holdout.
