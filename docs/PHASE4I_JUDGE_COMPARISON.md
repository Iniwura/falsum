# Phase 4I — judge comparison and reproducible evaluation value

**Telegraph Season II · Evaluators · SECURITY_REVIEW_GENERAL · November 14, 2026**

## Why this matters for the first-place goal

A security evaluator must change its conclusion when the code and evidence change. The Phase 4H experiment demonstrates a specific measurable failure in the original Telegraph Foundation LoRA, but previously required judges to read long technical reports. Phase 4I makes that comparison available in a **standalone interactive, zero-credential source-revision exhibit** while keeping every negative result and limitation intact.

### Three judge routes

- **/ — Review challenge:** three *fictional* before/after PR scenarios with real local Python execution and legitimate controls
- **/proof/ — Version-sensitive model evidence:** six original real recorded GHSA/version conditions; original LoRA scores **3/6**, with **0/3** complete version reversals
- **/compare/ — Source-sensitive model evidence:** eight different parent/fix source conditions, four real upstream project families; same **unchanged original LoRA** scores **5/8** according to provisional researcher source interpretations, with **1/4** complete source reversals

The app is static: no live inference, no hidden evaluation pool, no wallet, no paid APIs or third-party mission actions.

## Fair controls and honest results

The [frozen four-project source selection](../data/phase4h-frozen-four-new-source-projects.json) was committed before actual Foundation inference, with exact parent/fix commits, source file paths, advisory URLs, questions, and the same A/B answer texts across each revision pair.

| Approach | Matching 8 provisional researcher source conditions | Complete A-to-B paired reversals | Interpretation |
| --- | ---: | ---: | --- |
| Constant A | 4/8 | 0/4 | A simple, invariant answer-only control |
| Constant B | 4/8 | 0/4 | Same |
| Original unchanged LoRA | **5/8** | **1/4** | Real official Foundation ONNX/WASI scoring; limited context sensitivity |
| Source-aware author answer key | 8/8 | 4/4 | **Correct by construction. NOT an ML model or independently evaluated scorer** |

Because the candidate A and B answer texts stay identical across the parent/fix revisions of each project while the researcher-supplied expected answer changes A to B, **any completely source-context-invariant answer-only method can match at most four of the eight conditions**. This is a controlled property of these *author-selected* questions, not a general theorem about all code-review evaluation tasks or a scientifically demonstrated improvement by FALSUM.

The original model actually changes its choice correctly for **PyJWT**. It stays with B across both revisions for **Werkzeug**, **MCP Python SDK**, and **Pillow**, missing the desired source-driven reversal. This is a negative finding, not a newly trained better model.

### Evidence and limits

The [real official Foundation inference run](https://github.com/Iniwura/falsum/actions/runs/43530363990) executed 16 authentic float32 scoring inputs with 32 repeat-verified inferences. Its [post-merge replay](https://github.com/Iniwura/falsum/actions/runs/43532118459) succeeded. All exact source revisions and genuine score values are [permanently preserved](../evidence/phase4h-2026-11-14-actual-original-model-source-8-conditions.json).

The new page is built by [a small source-bound report generator](../src/falsum/phase4i_evidence_comparison.py), which refuses altered frozen-source bytes, altered model-score bits, invented expert labels, model registration and false training claims. Four project tabs, before/after buttons, actual source/test/advisory links, recorded score bits, margins, and case-specific findings are shown without any remote assets.

The original four public projects are new relative to FALSUM's earlier scored source projects, **not guaranteed unseen in model pretraining**. The expected source facts are researcher-authored, **not independent expert security gold labels**. Two selected regression-test files (Werkzeug and Pillow) were unchanged by the specific pinned fixes; source verification is not a substitute for running the complete upstream test suite. There are no new eligible Anjoman rows, registered evaluator, external customer mission deployment or accepted bounty implied by this page.

## 75-second walkthrough for a professional judge

1. Open /compare/. Read **5/8 recorded LoRA**, **1/4 complete reversals**, **4/8 constant-choice baseline**. Do not mistake the score for independent AppSec accuracy.
2. Select **PyJWT**, switch before to after, see the original model change from A to B in line with the source change. Click the exact commit source and regression test.
3. Select **MCP Python SDK**, then select its fixed commit. The relevant origin-redirect behavior changes, but the model still selects B on both revisions. Show the exact real score bits and current source.
4. Open the bottom public proof links, inspect the archived original model run and the frozen manifest. The LoRA remains unregistered. The source-aware key is plainly flagged as correct by construction, not a new trained winner.

## Reproduce without credentials or spending

Clone the public repository. With Python 3.11–3.13 and the project root as working directory, execute the existing build command:

    PYTHONPATH=src python -m falsum.phase4c_release --out-dir local-judge

Open local-judge/index.html, local-judge/proof/index.html and local-judge/compare/index.html.

For offline source/score authenticity checks:

    PYTHONPATH=src:tests python -m unittest discover -s tests -p test_phase4i_evidence_comparison.py -v
    PYTHONPATH=src python -m falsum.phase4h_recorded_evidence --ledger evidence/phase4h-2026-11-14-actual-original-model-source-8-conditions.json

CI reruns the static build on Python 3.11, 3.12, and 3.13; Chromium QA checks real keyboard, 1440px desktop, 390px and 320px touch viewports, source/test URL binding, no horizontal overflow and no external API calls. The old root and /proof/ pages remain covered by their original tests.

## What Phase 4I DOES NOT accomplish

It does **not** establish a statistically meaningful improvement in trained evaluator accuracy, independent expert validation, a truly sealed and independently adjudicated holdout, or a newly registered Telegraph scoring model. It contributes an independently reproducible **diagnostic of the evaluation failure mode** supported by actual upstream source facts and official recorded model scores. The original model is still quarantined.

Before first-place-ready signoff, verify the separate 20-pair Anjoman contribution and bounty status, publish authentic technical updates, finish a publicly playable professional 2–5 minute demo, confirm account registration/star requirements and submit via the actual official hackathon form by December 1, 2026 at 23:59 UTC.
