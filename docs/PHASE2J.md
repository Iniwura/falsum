# Phase 2j: genuine ModernBERT scorer measurement (model required)

**Implementation verified with offline controlled scorers. No actual checkpoint has been trained or evaluated in this phase.** This harness measures an existing trained **ModernBERT LoRA** adapter on the 12 source-linked, fictional PR examples in `data/draft-pr-benchmark.json`. It is not a replacement for the Telegraph V2 ONNX/WASM path.

## Why this gate matters

A scorer that reads only candidate answers can look excellent on an ordinary preference dataset. The counterfactual PR benchmark deliberately pairs **identical two candidate answers** with contradictory deployment evidence, flipping which one is correct. A context-blind scorer will score one side of each pair in its favor, but cannot win **both contexts**. This harness tests contextual correctness separately from answer-only ablation. It also groups results by split and rule family; a 1-of-2 holdout is **not** a meaningful confidence claim.

All 12 cases are fictional and unreviewed, so these results are *diagnostic only*. They must not be used to represent official scorer, Anjoman, or Telegraph network performance.

## Usage with a real model

Use the official adapter toolkit at immutable commit `5fa5d68bbcf76aaa2093c5d0578f53462bc0e36e`. Install its documented Python dependencies, ensure the official kit is importable on `PYTHONPATH`, and make sure you already have a trained local LoRA reward adapter directory containing `adapter_config.json` and `adapter_model.safetensors`.

```bash
PYTHONPATH="src:/path/to/telegraph-wasm-baseline" \
python -m falsum.model_eval \
  --benchmark data/draft-pr-benchmark.json \
  --casebook data/draft-scenarios.json \
  --adapter /path/to/trained/adapter \
  --report /tmp/falsum-model-score-report.json
```

The runner loads `answerdotai/ModernBERT-base` with its own LoRA sequence-classification head. It verifies the official node tokenizer conformance vectors; refuses any prompt-answer input exceeding 512 tokens instead of silently truncating security evidence; checks finite, scalar FP32 scores; and reports both full-context and no-prompt score margins. It computes SHA-256 of the **actual adapter files**, not merely the adapter's filesystem path. This records file integrity, **not** training provenance or model correctness.

## Offline tests and official render contract

```bash
PYTHONPATH=src python -m unittest discover -s tests -p test_model_eval.py -v
```

CI separately imports the official pinned `wide_runtime.train_adapter.render` and verifies that FALSUM constructs the same render string. This is a compatibility check only, not model inference. The score runner needs the official kit and model weights at execution time; CI never fabricates an adapter. No external account or wallet is needed for the offline compatibility checks.

## Release blockers

- **0 independently reviewed training cases**. The source-pinned draft comparisons pass *shortcut* checks, not a domain review. Do not silently train and present them as gold labels.
- **No trained ModernBERT adapter** exists in this repository yet. The `--adapter` argument is deliberately required, not replaced with a random model.
- **Only 2 counterfactual holdout PRs**, with one rule family. This is a proof of test methodology and does not give robust confidence about generalization.
- **No ONNX, WASM, registered evaluator, or Telegraph network accuracy** has been measured or claimed.
- **The independent-contributor evaluation pool** is an external dependency.

### What would make the next stage useful

Obtain independent AppSec reviewers, promote independently verified source-grounded cases into a clean, leak-free training corpus, run the official V2 data quality gate, then train ModernBERT on that corpus. Evaluate using this harness and a substantially larger real-project holdout before exporting to ONNX/WASM. Never use the PR holdout as training data.
