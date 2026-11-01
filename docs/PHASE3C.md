# Phase 3C — Real loaded Foundation Model and repeat-deterministic security scores

**Verified 1 November 2026. Real ONNX/WASI scoring using the actual trained Phase 2U LoRA. Not model-accuracy certification or network registration.**

## Why this matters

Before Phase 3C, FALSUM had a genuine ModernBERT LoRA trained with Telegraph's official trainer and re-exported to the current shared-Foundation safetensors delta format. [Phase 3B](PHASE3B.md) passed the current official **Stage 1 structural validation**, but the node checker explicitly returned \`verification.loaded=false\` because it did not load the full Foundation graph or run inference.

Phase 3C closes that infrastructure gap. We now know our actual previously trained checkpoint can be loaded and scored through the **same published 599 MB ONNX Foundation and 2.7 MB WASI engine** as the current official builder runtime. That result is much stronger than structural packaging alone.

## Verified official scoring pipeline

[Actual successful GitHub Actions run 41306369871](https://github.com/Iniwura/falsum/actions/runs/41306369871) performed all of the following:

1. Restored our original [Phase 3B real converted LoRA](https://github.com/Iniwura/falsum/actions/runs/41304788714/artifacts/13082304092), **not a fake adapter**, and verified its full saved package SHA256 \`3d269cc080538b6a13ae8e5fbb8526921ffe9689c1a6f62f9a6161a9d4680fbc\`.
2. Checked out immutable official Telegraph engine/builder kit commit \`1ed063e2f0066cfaf0e124d66ec6a17b7a6121fd\`.
3. Downloaded **four official Foundation assets**, verifying each against its exact release SHA256: \`foundation.json\`, \`foundation_lora_fp32.onnx\`, \`foundation_engine.wasm\` and \`tokenizer.json\`.
4. Parsed the canonical tokenizer and generated **real Task/Answer token ID vectors** for two security-review answers. Inputs had 100 and 93 tokens (under the node's 512-token limit).
5. Compiled the current official \`cmd/adapterbuild\` Go tool, then invoked it with \`--foundation-onnx\`, \`--engine\`, \`--engine-hash\` and the actual token-ID files for each answer.
6. The official adapter builder **loaded** our hybrid security adapter on the Foundation and **scored each answer twice**. Each pair of repeats returned exactly identical float32 bits.
7. Validated the builder's JSON output and real score bits. The [Phase 3C report guard](../src/falsum/phase3c_score_report.py) refuses a structural-only score, absent Foundation-load proof, any wrong package/Foundation/tokenizer hash, non-finite float32 score or missing repeatability proof.
8. Archived bounded real runtime logs and score manifests, without republishing the 600 MB Foundation weights.

## Actual measured model results

Illustrative question, explicitly **not human-reviewed ground truth**:

> Review aiohttp Python static routing. The actual installed package is aiohttp 3.10.11. The route uses follow_symlinks=True. Is CVE-2024-23334 confirmed?

| Answer description | Actual official score bits | float32 score |
| --- | --- | ---: |
| Cautious: 3.10.11 is newer than the 3.9.2 fix; do not claim this CVE is confirmed; review other risks separately | \`0xbf52c0e6\` | **-0.82325590** |
| Overclaim: the literal flag proves this historical CVE even on patched versions | \`0xbf80182c\` | **-1.00073767** |

Observed cautious-minus-overclaim margin: **+0.17748177**. Because the higher numeric score ranks first, the model preferred the cautious answer on *this one synthetic question*.

The official builder reported \`verification.stage1=true\`, \`verification.loaded=true\`, \`verification.repeats=2\` for both distinct model inputs. **Four real inference scores** completed. This verifies that the scoring infrastructure works and is bit-deterministic for these inputs. It is not independent security evaluation and provides no reliable estimate of precision, recall or generalization.

The previous source-separated [Phase 2U research diagnostics](PHASE2U.md) still showed **0/3** complete counterfactual-context preference-family reversals. This one positive example must not override those failures.

## Hashes and reproducibility

The exact published Foundation release is \`modernbert-base-lora16-v1\`.

| Verified component | SHA256 |
| --- | --- |
| Official Foundation manifest | \`f7de64b999acd3f735118fbe5999abf251fdf188f9797e3a4e36c54ee9e4dbbe\` |
| Foundation ONNX model | \`0a49b325304bb4cf292e683929689d0457966be264f60bfc94d0072b614bf8e6\` |
| Official WASI inference engine | \`77643d6e1176ab8744801cef93ccb844d0136ed32b8daa865d541f37d13292de\` |
| Canonical official tokenizer | \`67bc76f8b9386efba1a761c1c8e5ad439fd0eaf1c2826e9dd1a205c7af4dc456\` |
| Our actual rank-8 \`SECURITY_REVIEW.safetensors\` | \`3d269cc080538b6a13ae8e5fbb8526921ffe9689c1a6f62f9a6161a9d4680fbc\` |

The [source-owned Phase 3C GitHub workflow](../.github/workflows/phase3c-real-foundation-score.yml) is the repeatable source of truth. Its actual bounded [runtime evidence artifact 13082973270](https://github.com/Iniwura/falsum/actions/runs/41306369871/artifacts/13082973270) includes real official Go JSON score manifests, repeat checks, token vectors and engine logs. Artifacts are temporary; [permanent summary evidence](../evidence/phase3c-2026-11-01.json) preserves all important identities and numeric scores.

The CI passed **12 adversarial Phase 3C score-provenance tests** plus **7 original Phase 3B checkpoint tests**, and the repository's [foundation test suite](https://github.com/Iniwura/falsum/actions/runs/41306369794) also passed **495 tests** (one skipped). The original official Telegraph diagnostic data gate passed as well.

## Security and research boundaries

The security question is a small *source-owned* scenario. Neither answer constitutes independently approved label material. Real framework version/exploit adjudication on an external application and real hidden network scoring have not occurred.

- Real model runtime integration **YES**.
- Exact shared Foundation and package identities verified **YES**.
- Two score results, each repeated twice deterministically **YES**.
- Independent, blinded AppSec preference ground truth **NO**.
- Reliable project-separated context reversal **NOT DEMONSTRATED**.
- Production evaluator endpoint **NO**.
- Eligible Anjoman evaluator training pairs **NOT CONFIRMED**.
- Registered, accepted or live Telegraph \`SECURITY_REVIEW\` evaluator **NO**.

**The next engineering milestone is quality, not packaging:** use the *same loaded Foundation runtime* to test paired counterfactual contexts and measure how reliably preferences reverse when a dependency version, attacker-controlled path or configuration changes. Then obtain independently adjudicated examples and scope an affordable real executor. No network registration should be attempted solely because this runtime smoke succeeded.
