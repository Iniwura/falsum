# Phase 3K — Real context-sensitive LoRA training experiment (quarantined)

## Why this phase exists

Phase 3D and [Phase 3J](PHASE3J.md) measured the genuine original ModernBERT LoRA on eight pairs of security contexts. Both phases showed **0/2 complete expected ranking reversals**, despite authentic official Foundation inference. Phase 3H and Phase 3I proved two historical library-behavior boundaries at runtime. The next step is no longer just reproducing source facts: **change the model's training data to force context-sensitive rankings, and measure how it changes on different public projects.**

## Intervention

[Source-anchored training builder](../src/falsum/phase3k_intervention.py) reconstructs the previous **52 research-only training rows** from pinned public advisory data and adds **8 new balanced preference pairs** from the two **already-studied** real-runtime families:

- Starlette 0.26.1 vs 0.27.0, where a same-prefix sibling path was observed as exposed vs blocked in a harmless in-process fixture.
- Requests 2.30.0 vs 2.31.0, where in-memory credentialed HTTPS proxy header reconstruction was observed as present vs absent.

For each family, each writing variation contains two opposite deployment contexts. **The same candidate answer strings appear verbatim in both contexts, with chosen/rejected roles swapped.** This makes a purely answer-only or length-only shortcut inconsistent across the pair. The same neutral suffix is attached to both candidate answers. The original Phase 3J prompts remain known and are *not a clean holdout* after this intervention. The additions originate from FALSUM-generated provisional preferences, **not independent expert labels**.

The [GitHub Actions experiment](../.github/workflows/phase3k-context-research-training.yml) uses the real pinned Telegraph Foundation-V2 ModernBERT trainer, installs actual CPU Torch and dependencies, verifies all 16 new full Task+Answer strings fit the network's 512-token cap without truncation, runs the official dataset/shortcut gate, and performs **one epoch** of genuine research LoRA training. A failing training-quality score is retained as an experiment failure rather than relabeled as success. The model weights are quarantined in a short-retention Actions artifact, **not registered to Telegraph**.

## Actual before/after transfer assessment

The comparison stage verifies and replays historical upstream source/test commits for three *different* projects: **Tornado, Undici and websockets**. Each has two opposite hypothetical application contexts and the same two candidate answers. The code loads the prior **actual trained** Phase 2U LoRA checkpoint and the newly trained Phase 3K LoRA under the real HuggingFace/PyTorch ModernBERT architecture, using the original Telegraph task/answer render template and tokenizer conformance checks. It scores both on six research contexts and records:

- Old vs new number of provisional context matches (out of six).
- Old vs new number of families with correct reversals in both contexts (out of three).
- Per-case actual score margins, answer-only ablation, actual checkpoint fingerprints and dependencies.
- Explicit source-project disjointness relative to new training interventions.

**Critical limitation:** These three comparison projects were previously inspected, scored and published in earlier FALSUM phases. They were not used in this intervention's training rows, but they are **NOT untouched, sealed, hidden, independently expert-adjudicated evaluation**. A positive comparison cannot establish network accuracy. Neither checkpoint is being evaluated through the official Foundation ONNX/WASI runtime in this training-phase comparison; those are separate future steps for any candidate passing basic diagnostics.

## Reproduce

```bash
PYTHONPATH=src:tests python -m unittest discover -s tests -p test_phase3k_research_intervention.py -v
```

All heavyweight steps, full dependency pins, source replay, model training and comparison are in [the Phase 3K workflow](../.github/workflows/phase3k-context-research-training.yml). The private AI-provisional comparison key is generated only inside ephemeral CI storage and is not added to training examples. The model is still *not eligible for submission*.

## Hard release gate

**0 independent expert-approved labels. 0 accepted Anjoman rows. 0 confirmed qualifying evaluator registrations.** Original LoRA remains blocked, and Phase 3K's candidate is a quarantined research model with no right to replace it until independent validation, clean project-disjoint prospective evaluation, official 2026 Foundation export/inference and network checks pass. Even if this training experiment improves all three observed families, those requirements are unchanged.

Next decision: compare the actual numerical and reversal results. If new performance fails or merely overfits seen projects, redesign training conditions and seek genuinely external AppSec review rather than promoting a working model to a winning claim.
