# Phase 3D: real model counterfactual security-context test

**1 November 2026. Actual Telegraph shared-Foundation inference. The reward model failed the contextual reversal diagnostic.**

## Decision

**BLOCK MODEL RELEASE AND REGISTRATION PENDING QUALITY REMEDIATION.** The already trained and structurally compatible `SECURITY_REVIEW` hybrid LoRA runs correctly, but it preferred the *same answer in both contexts* of each of two controlled deployment-fact reversals. It matched only two of four provisional, source-fact-based expectations. This is not a claim of a 50% general security accuracy rate: four authored scenarios are not a statistically representative, expert-reviewed or blind holdout.

[Successful real inference workflow 41308317723](https://github.com/Iniwura/falsum/actions/runs/41308317723), [bounded score artifacts](https://github.com/Iniwura/falsum/actions/runs/41308317723/artifacts/13084072990), [permanent exact score evidence](../evidence/phase3d-2026-11-01.json).

## Experiment: same answers, changing only the decisive fact

For each family, we froze two answer strings byte-for-byte, then changed only the task's stated deployment context. Source anchoring is historical aiohttp GHSA-5h86-8mv2-jq9f / CVE-2024-23334, fixed in aiohttp 3.9.2. An affected version and `follow_symlinks=True` are relevant prerequisites, **not** sufficient proof of exploitability. The expected answers are explicitly provisional rule-derived diagnostics, **not approved expert labels**.

- **Installed-version reversal:** both prompts specify a publicly registered `follow_symlinks=True` static route; installed aiohttp changes from **3.9.1** (before the fix) to **3.10.11** (patched). The same two answers say respectively "outside historical affected version range" and "potentially affected; verify exposure before asserting exploit."
- **Symlink-setting reversal:** both prompts specify aiohttp **3.9.1**; only the registered public route's `follow_symlinks` changes from **False** to **True**. The same two answers respectively say that the flagged precondition is absent or present but requires further verification.

All inputs were rendered as the node's Task/Answer format and encoded with the official SHA256-pinned Foundation tokenizer. No source file from an external project was executed, no historic vulnerable application was tested and no exploit was attempted.

## Actual score table

Higher numerical score means preferred. Each float32 score was produced **twice**, and the official node runtime verified the two scores' exact bits.

| Family | Context | First answer score | Second answer score | Model preferred | Provisional fact-based expected | Match? |
| --- | --- | ---: | ---: | --- | --- | --- |
| Installed version | 3.9.1, True | -0.65710080 (not affected) | -0.68222433 (potentially affected) | **Not affected** | Potentially affected | **No** |
| Installed version | 3.10.11, True | -0.63938838 (not affected) | -0.66479129 (potentially affected) | Not affected | Not affected | Yes |
| Symlink flag | 3.9.1, False | -0.66434538 (flag not met) | -0.75680423 (flag met) | Flag not met | Flag not met | Yes |
| Symlink flag | 3.9.1, True | -0.62327796 (flag not met) | -0.71390796 (flag met) | **Flag not met** | Flag met | **No** |

Observed first-minus-second margins:

- Version, before fix: **+0.02512354**; after fix: **+0.02540290**.
- Flag disabled: **+0.09245884**; enabled: **+0.09062999**.

The margin remained *positive and roughly unchanged* across both context reversals. That is direct evidence of answer-preference bias on these tests, not a successful interpretation of the changed deployment facts.

**Result: 0/2 complete context-reversal families; 0/2 families correctly matching both provisional interpretations; 2/4 individual contexts agree.**

## Real model and testing provenance

The model came from the original real Phase 2U training and successful Phase 3B conversion, without retraining or synthetic weights. The [Phase 3D workflow](../.github/workflows/phase3d-real-counterfactuals.yml) loads the exact SHA-verified `SECURITY_REVIEW.safetensors` (SHA256 `3d269cc080538b6a13ae8e5fbb8526921ffe9689c1a6f62f9a6161a9d4680fbc`), official 599 MB Foundation ONNX model, WASI engine and canonical tokenizer using the pinned official Go builder commit `1ed063e2f0066cfaf0e124d66ec6a17b7a6121fd`.

The official Go runtime loaded the Foundation for **8 distinct model inputs**, scoring each twice for **16 actual inference calls**. All 8 Stage 1 structural validations, all 8 loaded-model checks and all repeatability checks succeeded; the failures were in **model preference quality**, not the inference infrastructure.

[Counterfactual source generator](../src/falsum/phase3d_counterfactual_inputs.py) and [score auditor](../src/falsum/phase3d_counterfactual_report.py) refuse malformed tokenizer inputs, changed answer hashes, missing real Foundation load evidence, nonfinite scores, wrong model hashes and forged expert labels. Tests verify that an upside-down or static-bias model is reported as a failure rather than passed as an evaluator.

The [automatic release veto](../src/falsum/phase3d_quality_gate.py) also blocks registration **even if** this small provisional research diagnostic had passed: independent human adjudication, project-separated validation, accepted data and endpoint reliability remain missing. This means structural and runtime compatibility cannot be accidentally presented as network readiness.

## What we do next

**Do not ship the current checkpoint.** We should improve context reasoning against the actual failure mode rather than train repeatedly on the same eight provisional examples.

The next step should acquire independently human-reviewed security pairs grounded in authentic source and installed-version facts, create a balanced training curriculum where identical answers change preference with genuinely different contexts, and reserve an entirely separate project- and version-disjoint test set. Re-score candidate models with the same genuine Foundation runtime. Only then evaluate the runnable executor, accepted Anjoman data rows and registration.

No confirmed live exploit, no independent security accuracy estimate, no accepted evaluation rows and no registered evaluator are claimed.
