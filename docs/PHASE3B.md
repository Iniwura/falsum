# Phase 3B — Current shared Foundation delta export, real official structural PASS

**Verified 1 November 2026. Research-only checkpoint, NOT registered and NOT validated for security correctness.**

## Important platform change on 1 November 2026

The [latest official shared Foundation Model migration guide](https://anjoman.ai/docs/scoring/upgrade-shared-foundation) says that new full-model float \`.wasm\` adapters for judgment/hybrid intents are **no longer accepted**. Validators now load a common ModernBERT Foundation Model and accept a **LoRA delta package in \`.safetensors\`**. The historically claimed [SECURITY_REVIEW bounty #96](https://github.com/telegraphprotocol/bounties/issues/96) still mentions \`.wasm\`, but this is superseded by the current protocol requirements. The current Telegraph kit's Stage 1 parser establishes that this **\`SECURITY_REVIEW\` evaluator family is \`hybrid\`**.

## Actual work performed

[Successful CI run 41304788714](https://github.com/Iniwura/falsum/actions/runs/41304788714) used our **existing, genuinely trained Phase 2U ModernBERT LoRA checkpoint** from [training run 41283929744](https://github.com/Iniwura/falsum/actions/runs/41283929744), not random placeholder tensors and not a synthetic model score.

- Old exact PEFT adapter file-manifest SHA256: \`a20bdc0ffdc9ee776877e60b5c19c225d9279467d005916a6978db1650482d33\`; the original trained adapter was checked before export.
- New official pinned kit commit: \`telegraphprotocol/telegraph-wasm-baseline@1ed063e2f0066cfaf0e124d66ec6a17b7a6121fd\`.
- Official Foundation: \`modernbert-base-lora16-v1\`, model SHA256 \`0a49b325304bb4cf292e683929689d0457966be264f60bfc94d0072b614bf8e6\`.
- Official published Foundation \`foundation.json\` SHA256: \`f7de64b999acd3f735118fbe5999abf251fdf188f9797e3a4e36c54ee9e4dbbe\`.
- The original saved tokenizer SHA differs from the Foundation's canonical tokenizer: \`3703d011...\` vs \`67bc76f8...\`. The CI compared **the complete parsed JSON**, found **all fields equal except \`truncation.max_length\`** (old 512, official 1536), and verified identical Right/LongestFirst/stride 0 semantics. FALSUM trained at the exact 512-token cap that the node still supplies. The CI created a **separate export-only copy** with the canonical tokenizer bytes. The archived original model and its provenance were never changed. An actual tokenizer vocabulary or pre-/postprocessor difference would have failed closed.
- The official exporter generated a real **rank-8 delta package** and the official Go \`adapterbuild lora\` validator accepted its final package under **class \`hybrid\`**, not \`judgment\`. The class mismatch was caught and fixed during CI. This is not a user-chosen arbitrary classification.

### Official verified package result

| Field | Official structural result |
| --- | --- |
| Intent/family | \`SECURITY_REVIEW\` |
| Class | \`hybrid\` |
| ABI | \`lora-v1\` |
| File | \`SECURITY_REVIEW.safetensors\` |
| Size | \`6,776,908\` bytes |
| Layers' LoRA rank | 8 |
| LoRA alpha | 32 |
| Target modules | \`Wi\`, \`Wo\`, \`Wqkv\` |
| Tensors | 178 |
| Node token cap | 512 |
| Final package SHA256 | \`3d269cc080538b6a13ae8e5fbb8526921ffe9689c1a6f62f9a6161a9d4680fbc\` |
| Final package Keccak256 | \`0xf8f94708f30ed31b6f0825dbffb235fa60b0e71b76fde39dbc696cf277ef8aa7\` |
| Official Stage 1 structure parser | **PASS** |
| Foundation model actually loaded and scored | **NO** |
| Remote runnable endpoint available | **NO** |
| Hidden security evaluation | **NOT ATTEMPTED** |
| Registered/active on network | **NO** |

The official exporter logged a package hash before the final builder validation; **use the builder's final package hash shown above**, which is the hash of the file the builder accepted. The passed CI separately verified this final hash matched the bytes of the final package.

[Quarantined actual model/package artifact](https://github.com/Iniwura/falsum/actions/runs/41304788714/artifacts/13082304092) is retained only temporarily. **Do not publish or register this candidate just because it passed structural checks.**

## Reproduce the safe package migration

The [pinned GitHub Actions workflow](../.github/workflows/phase3b-shared-foundation-delta.yml) performs all required steps: download the original saved real model from its Actions run, verify the exact old model manifest, check research-only status, obtain and hash-verify the official Foundation and tokenizer, insist that only safe truncation metadata differs, run the official new exporter on the separate canonical-tokenizer copy and invoke the **official current kit's own Go structural parser**.

The [offline research-identity gate](../src/falsum/phase3b_delta_readiness.py) is tested with [seven adversarial tests](../tests/test_phase3b_delta_readiness.py) covering SHA mismatch, unsupported LoRA rank/modules and fake human/network approval.

### Why it is still not submission-ready

**We solved package format, not reward-model judgment quality.** Our source-separated Phase 2U/2V tests still showed **0/3** complete two-context preference reversals, despite tiny official synthetic heldout tests passing. Those labels were provisional, not independently expert-approved. The package checker returned \`verification.stage1=true\` but \`verification.loaded=false\`.

The official [evaluation-data rules](https://anjoman.ai/docs/scoring/contribute-evaluation-data) also require original realistic human-quality preference pairs and at least five contributors across the network's pool before questions are used. FALSUM does **not** have confirmed eligible Anjoman rows.

The [new runnable endpoint](https://anjoman.ai/docs/scoring/upgrade-shared-foundation) must score the same Foundation and delta and echo score identities, with substantial RAM, and our cost-limited environment does **not** yet have that service.

## Build priorities after 3B

1. **Real end-to-end Foundation+delta score smoke**, not just structural checks, using the published engine/model hashes in a safe isolated CI job and frozen inputs. A successful smoke still is not hidden evaluation.
2. **Independent security review/material quality**. Get credible source-constrained answer preferences from humans, expand beyond an aiohttp-only data slice into code, CVEs, secrets and API misconfiguration, and measure project-separated diagnostic performance. Do not label AI preferences as experts.
3. **Runnable executor and actual evaluator submission path**: document/verify feasible memory and hosting costs, test the required echo-identity protocol and registration prerequisites. Do not incur bond costs until quality and runtime are defensible.

**Current status: genuine compatible delta artifact, not active evaluator and not verified eligible hackathon output.**
