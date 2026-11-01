# Phase 2U — Real context-transfer LoRA trained; no generalization improvement

**Verified 1 November 2026. Research-only.** FALSUM has executed another genuine official Telegraph V2 ModernBERT LoRA training run, and compared it against the original checkpoint on three newly pinned, previously unused source projects.

**Outcome: negative for our actual goal.** The new model passed the official trainer's small GHSA evaluation gate (6/6) but DID NOT improve its ability to reverse an answer ranking when the deployment preconditions changed. This is why a single successful training job does not make a competitive security reviewer.

## One new real trained model, not a claimed released evaluator

[Official V2 training run 41283929744](https://github.com/Iniwura/falsum/actions/runs/41283929744) completed successfully.

- Actual upstream kit: commit 5fa5d68bbcf76aaa2093c5d0578f53462bc0e36e, using the same ModernBERT model architecture and Task/Answer render as real Telegraph evaluator scoring.
- Real CPU training: 1 epoch, ModernBERT LoRA Bradley-Terry pair ranking, 60 candidate training comparisons.
- Training material: 52 prior GHSA research comparisons plus 8 AI-authored hypothetical deployment contexts from Starlette, urllib3, Django and Express. These four source projects were **already inspected** in Phase 2T; this is a controlled research intervention, NOT new independent expert-approved data.
- Strict Git-pinned source and test verification: 8 exact source/test file transitions for the training projects, plus 8 for the original four excluded inspected projects.
- Every one of 16 new complete model training renders fits the official 512 token node limit; observed maximum **497**.
- Official data shortcut gate **PASS**: all negatives unique, top negative share 1.67%, length shortcut accuracy 50%, prompt-hidden surface probe accuracy 41.11%, measured duplicate-negative leakage 0.
- Model training loss **0.6950**, validation pair accuracy **66.67%**, validation loss **0.6918**.
- Official trainer's draft GHSA test verdict **PASS: 6/6 paired preferences**. This is NOT accepted Anjoman evaluation data, not a large heldout study, not independent human security correctness, and not a network registration.
- Actual newly trained adapter artifact SHA-256 research manifest: **a20bdc0ffdc9ee776877e60b5c19c225d9279467d005916a6978db1650482d33**. This is an archive-of-files digest via the repository's adapter integrity function, not a weight-binary digest.
- Original model adapter SHA-256 research manifest: **1f1c59642936235c73eb94eb44a5f9b95e8899635d997e2e3d2546b567948f1d**.

The official training results are preserved in [actual training artifact 13074383795](https://github.com/Iniwura/falsum/actions/runs/41283929744/artifacts/13074383795), including the official result.json, real LoRA checkpoint, gate logs, and independent non-release manifest. Artifact retention is seven days; source-level summaries remain in git.

## Original four-project inspected diagnostic

After training, the new checkpoint was scored on the original four projects excluded from these eight new context examples:

| Diagnostic | Frozen original LoRA | Newly trained LoRA |
| --- | ---: | ---: |
| Agreement with eight AI-proposed context judgments | 4/8 | **4/8** |
| Distinct projects with both opposite-context AI judgments ranked correctly | 0/4 | **0/4** |

This is an already inspected development comparison. Two of these historical GHSA advisories (Jinja2, Axios) appeared in the earlier 52-pair training source; it is NOT a sealed unseen model accuracy test. The new model made small numerical score changes but never reversed its relative favorite essay on these projects.

## Three new, verified, source-separated project probes

To avoid measuring only the same inspected examples, three additional authentic upstream repair commits were reserved OUTSIDE the training curriculum:

| New project | Actual code fix | Applicability requires | When not to claim an exploit |
| --- | --- | --- | --- |
| [Tornado](https://github.com/tornadoweb/tornado/commit/ab4953f1262636343bcc1875117f7a8c93d10509) | Reject non-integer Set-Cookie max_age values that could inject attributes | App passes untrusted max_age text to set_cookie | A literal numeric max_age from trusted code does not demonstrate injection |
| [Undici](https://github.com/nodejs/undici/commit/6d583124e7cf60b640097d64144ed633cc450584) | Reject chunked responses that exceed dump interceptor maxSize; propagate terminal errors | The affected dump interceptor actually processes oversized streamed responses | A bounded local response below maxSize is not evidence of oversized-body mishandling |
| [Python websockets](https://github.com/python-websockets/websockets/commit/b6a25ceb3555d0ba69e5961b8d7616e4c1aecb2b) | Bound permessage-deflate decompressed output and reject oversize payloads | Attacker-controlled compressed frames reach a negotiated decompression extension | Compression is disabled and the deflate decoder is never used |

The [three-project source generator](../src/falsum/phase2u_fresh_transfer.py) verifies the exact upstream commit SHA, parent SHA, published modified source/test file Git blob SHA-1 IDs, then applies the authentic GitHub unified diff to the exact historical file bytes and checks the resulting complete file equals the published post-fix bytes. It chooses a bounded pre-fix source excerpt and excludes remediation/test snippets and advisory identifiers from model prompts.

[Successful three-source verification 41284227213](https://github.com/Iniwura/falsum/actions/runs/41284227213) passed 8 offline adversarial tests, 6/6 exact source/test file replays, and 12/12 full ModernBERT tokenizer checks. Maximum full input length **450/512 tokens**.

The fictional deployment facts and AI preferred responses are published in [the new transfer casebook](../data/phase2u-fresh-transfer-cases.json); the model-facing packet and AI answer key were archived separately. This is source-separated **but NOT a sealed test set or expert-verified labels**.

## Genuine same-case old-versus-new model comparison

[Direct two-checkpoint scoring run 41284380222](https://github.com/Iniwura/falsum/actions/runs/41284380222) downloaded both exact model artifacts, checked previous adapter provenance and that the new source projects were excluded from the training inventory, then scored both actual ModernBERT LoRA checkpoints on all six novel A/B contexts plus answer-only controls.

| Metric | Frozen original | New 1-epoch LoRA |
| --- | ---: | ---: |
| Agreement with 6 AI-proposed choices | **3/6** | **3/6** |
| Source families where both deployment contexts change rank correctly | **0/3** | **0/3** |
| Independent expert-validated judgments | 0 | 0 |
| Network acceptance/registration | No | No |

The pattern was unchanged:

- Tornado: preferred the finding essay even when max_age was described as a literal trusted integer.
- Undici: preferred the cautious essay even when an untrusted oversized chunked response was described.
- Python websockets: preferred the finding essay even when compressed frames were disabled.

The new adapter changed numerical margins slightly but did not change any proposed winner.

[Machine-readable actual model scores and real dependencies](https://github.com/Iniwura/falsum/actions/runs/41284380222/artifacts/13074830234).

Permanent evidence including the original result SHA-256, two adapter manifest hashes, exact project identities, actual training gate metrics, and all observed changes: [evidence/phase2u-2026-11-01.json](../evidence/phase2u-2026-11-01.json).

## What this rules out, what it does NOT prove

We can rule out the following narrow claim: **adding eight previously inspected AI-authored context comparisons to a 52-pair GHSA research dataset and training a new ModernBERT LoRA for one epoch produced an improvement in these seven inspected source-project context-reversal diagnostics**. We observed none.

We cannot conclude that ModernBERT is incapable of learning context, that all security reviews will fail, or that the synthetic hypothetical preferences are external ground truth. The training sample is small, the context examples make up only 8 of 60 pairs, and the comparison evaluates only three new projects and the four publicly inspected older projects. The 6/6 official training evaluation is also a small synthetic advisory ranking metric, not proof of deployment-sensitive AppSec quality.

**Do not** repeat the same one-epoch/52+8 recipe and report the same six GHSA heldout score as progress. **Do not** register either real WASM/LoRA model on the strength of these results. No human-approved ground truth, Anjoman-eligible rows, or authenticated network publication exists.

## Phase 2V experiment proposal

A materially different model needs *evidence-conditioned* training, not just eight more advisory narratives. Build a task-specific applicability curriculum with many independently separated examples for each missing precondition, comparable credible answers and balanced answer length and wording. Train with explicit paired-context consistency so that the preferred answer demonstrably changes when the prerequisite changes, then measure against **newly sourced, untouched projects**, not the Phase 2S/2T/2U cases already inspected.

Before spending time packaging another 601 MB WASM, demand improvements in full two-context source-family reversal performance and verify the trainer's style-only/length-only checks. Seek independent expert review for consequential labels when possible; identify final network acceptance only through actual Anjoman eligible job rows.

FALSUM remains research-only. No prize or bounty funding is inferred from these experiments.
