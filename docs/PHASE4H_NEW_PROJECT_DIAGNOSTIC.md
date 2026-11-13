# Phase 4H — precommitted source-revision scoring across four new repositories

**Telegraph Season II · Evaluators · SECURITY_REVIEW_GENERAL · 14 November 2026**

## Independent question

On four public security patches not used in FALSUM's earlier scored source-case campaigns, will the **same, unchanged, original and quarantined Foundation LoRA** prefer different answers when a key line of the actual source code changes between the exact parent and security-fix commits?

This phase is a **fresh-to-this-project research diagnostic**, not a sealed blind holdout, an independently expert-labeled AppSec benchmark, a trained improvement or network-compatible evaluator. Public repositories and source code may have appeared in model pretraining.

## Pre-score freeze and real provenance

The complete selection, two questions and fixed A/B answer texts for each project were committed **BEFORE** attempting real model inference, at commit [1f872f3796f6a255ac2456b76172381296e9da8e](https://github.com/Iniwura/falsum/commit/1f872f3796f6a255ac2456b76172381296e9da8e). The frozen manifest is [data/phase4h-frozen-four-new-source-projects.json](../data/phase4h-frozen-four-new-source-projects.json), Git blob **9fc67edec49c33d3efdb4a6128bd7c6c6b7766e2**. The CLI rejects any later edit to those bytes.

The independent [source verifier](../src/falsum/phase4h_frozen_source.py) re-fetches each exact public GitHub **parent and fixed commit**, verifies that parent and fixed are directly adjacent, checks the source and selected test Git blob SHA-1 identity at **both** revisions (16 file blobs total), and requires source anchors that demonstrate the actual changed branch.

| Previously unused source project | Historical patch | Research question | Selected test file changed by patch? |
| --- | --- | --- | --- |
| PyJWT | [Real fix](https://github.com/jpadilla/pyjwt/commit/5fde08a6cf906aa7698de2d6391d88b73006b17b) · [Advisory](https://github.com/advisories/GHSA-42vr-xj54-vc7v) | Deeply nested unsigned JWT payload: uncaught RecursionError vs converted DecodeError | **Yes**, regression names nested payload |
| Werkzeug | [Real fix](https://github.com/pallets/werkzeug/commit/b1916c0c083e0be1c9d887ee2f3d696922bfc5c1) · [Advisory](https://github.com/advisories/GHSA-hrfv-mqp8-q5rw) | Long newline-free multipart tail: retained pending buffer vs bounded-tail flush | **No** in this fix; **not** presented as a new regression test |
| MCP Python SDK | [Real fix](https://github.com/modelcontextprotocol/python-sdk/commit/c6762e821c527925f0b617db216d00fbd1d0bf99) · [Advisory](https://github.com/advisories/GHSA-5h93-6whr-6q8j) | Cross-origin 307 redirect from configured MCP transport: follow vs refuse target | **Yes**, explicit out-of-origin redirect tests |
| Pillow | [Real fix](https://github.com/python-pillow/Pillow/commit/3cb854e8b2bab43f40e342e665f9340d861aa628) · [Advisory](https://github.com/advisories/GHSA-whj4-6x5x-4v2j) | Compressed FITS read: inflate full gzip stream vs bound the decompressed read to declared pixel byte count | **No** in this fix; **not** presented as a new regression test |

All source conditions are about the **specific branch behavior only**. They are NOT statements that a particular live app is exploitable or that a patch guarantees universal safety. The two unchanged selected test files are an important documented limitation, not a failure of source authenticity.

## Binary counterfactual design

There are **four pairs** of questions, one for the parent and one for the exact fix source. Within each pair the **two candidate answers are byte-identical**. A changed source fact should change the preferred answer from **A (parent)** to **B (fixed)**.

- **8** predeclared source-revision conditions.
- **16** official Foundation score input requests, 2 answers per condition.
- **32** genuine Foundation inferences with repeat verification if the real scoring workflow succeeds.
- Constant-A and constant-B baselines both agree with **4/8** of the researcher-provisional source expectations.
- Any answer-only rule that ignores the *question's changed source context* chooses the same candidate within a pair and can agree with at most **4/8** author expectations; evaluating answer position alone is insufficient.

The expectations are derived from inspection of the exact public source patch and source/test evidence. They are **researcher-authored interpretations, not independent human gold labels**. There are no new submitted or accepted Anjoman contributor rows. No training data is fed back to the quarantined model.

## How actual model inference is authenticated

The [Phase 4H real CI workflow](../.github/workflows/phase4h-new-source-model-evidence.yml) first performs the real source verification and retains its proof. Only if source verification and adversarial parser tests pass does it download:

- Original unregistered SECURITY_REVIEW LoRA SHA256 **3d269cc080538b6a13ae8e5fbb8526921ffe9689c1a6f62f9a6161a9d4680fbc**, from original Foundation research workflow 41304788714.
- Original Telegraph reference Go/WASI adapter code, exactly at commit **1ed063e2f0066cfaf0e124d66ec6a17b7a6121fd**.
- Checksum-pinned official Foundation ONNX, WASI engine, manifest and tokenizer, using the same exact model hashes as Phase 4A.

The [real model evidence checker](../src/falsum/phase4h_real_model_probe.py) refuses changed source-selection blobs, altered source/test digests, missing real model packets, invalid official score manifests, changed task/answer text, invalid tokenizer framing, truncation above 256 tokens, duplicate inputs, non-finite scores and accidental registration. Every genuine output preserves exact float32 score bits, scores, margins, real source/lock hashes, expected source revision, actual model preference, complete paired reversals, and both constant-choice baselines.

**Passing code CI only establishes source/provenance/inference integrity. It does not mean the model is good.** Negative scores and failures remain the primary finding if the original checkpoint fails.

## Reproduce

~~~bash
PYTHONPATH=src:tests python -m unittest discover \
  -s tests -p test_phase4h_frozen_sources_and_scoring.py -v

# Requires GitHub public source and API access.
PYTHONPATH=src python -m falsum.phase4h_frozen_source \
  --lock data/phase4h-frozen-four-new-source-projects.json \
  --out /tmp/falsum-phase4h-four-real-source-proof.json
~~~

For genuine scoring, run or inspect the official [Phase 4H GitHub Actions workflow](../.github/workflows/phase4h-new-source-model-evidence.yml), which fetches the previously quarantined original model, exact Foundation and official tokenizer and retains all real score packets. The offline tests deliberately use mock source metadata and **fake** score packets as *adversarial parser fixtures*, never as proof of inference.

## Current truth boundaries

- Source project selection is repository-disjoint **relative to earlier FALSUM scored source projects**, not proven disjoint from the original model's pretraining.
- The questions and source-preference rules were precommitted but researcher-authored. **0 independently verified expert labels** are claimed.
- All code and fixes are historical, publicly documented and from different projects; no private unannounced vulnerability or actual production exploit is claimed.
- Source/test Git blob verification does **not** execute those upstream packages or all their historical tests.
- No new accepted network material, model training, improved evaluator, registered adapter, external customer, or official H2 submission comes from this experiment.
- Only a new, externally adjudicated and truly sealed test set could justify calling an improved model winning-ready. Do not register the prior failed LoRA by observing its behavior here.

## Actual measured results

The authentic runner's observed counts, source and score manifest will be appended **only after** a successful official inference audit, with links to the exact GitHub Actions run and retained artifacts. No synthetic or predicted scores should be substituted if the model job fails.
