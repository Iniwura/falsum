# Phase 5O — published-model diagnostic across four source projects

**Telegraph Season II · Evaluators · SECURITY_REVIEW_GENERAL · 21 November 2026**

## Scope and previous negative result

Phase 5N's genuine three-question Qwen2.5-0.5B-Instruct CPU run returned **ABSTAIN on all three**: 1/3 public researcher-reference matches, no correct code-present facts, no correct parent/fix reversal. [Original successful real-inference run](https://github.com/Iniwura/falsum/actions/runs/44739535866). This remains negative evidence, not proof of model quality.

Phase 5O tests the same independently published open-weight model on **four other source-verified projects**: PyJWT (nested parser errors), Werkzeug (multipart buffering), MCP Python SDK (cross-origin redirects) and Pillow (compressed FITS reads). Historical source identities and original revision pairs come from [the previously frozen Phase 4H four-project selection](../data/phase4h-frozen-four-new-source-projects.json).

**Important boundary:** These are previously examined public historical fixes. The model sees **researcher-written source-behavior summaries, not actual raw code files**. The source summaries intentionally include clues relevant to the correct answer. Do not describe this as unseen code review, independent expert validation, blind model accuracy or new security-case discovery.

## Freeze completed before inference

The [Phase 5O locked study protocol](../data/phase5o-four-project-frozen-model-protocol.json) was committed in advance at [415363f](https://github.com/Iniwura/falsum/commit/415363fc2b016dcfe3753e8da776c1e54a7f5a85), before runner implementation and CPU inference. Protocol Git blob SHA-1: 07d41d2f12c7b9ececac299c72785faae0ef85ea. Original upstream selection Git blob SHA-1: 9fc67edec49c33d3efdb4a6128bd7c6c6b7766e2.

- **Model:** Qwen/Qwen2.5-0.5B-Instruct at its exact previously recorded immutable published revision 7ae557604adf67be50417f59c2c2f167def9a775. Model safetensors SHA-256: fdf756fa7fcbe7404d5c60e26bff1a0c8b8aa1f72ced49e7dd0210fe288fb7fe.
- **Inputs:** Four historical projects × (parent summary, fixed summary, intentionally omitted source) = 12 balanced prompts. Reference classes: 4 A, 4 B, 4 ABSTAIN.
- **Anti-shortcut:** The source-version role words are removed, and A/B options are reversed in two of four projects. This reduces a naive universal answer-role shortcut but cannot remove leakage from the published original text or source material.
- **Decoding:** Greedy CPU-only transformer generation, maximum 1,024 input tokens, 12 output tokens, exact A/B/ABSTAIN parser. Other outputs are INVALID and incorrect. No prompt tuning or original Telegraph LoRA substitution.
- **Declared non-model controls:** Always A, always B and always ABSTAIN each obtain 4/12. A shortcut assuming every parent=A and fixed=B, and abstaining on omitted source, obtains **8/12**. Therefore raw scores below or even equal to 8/12 should not be advertised as useful semantic reasoning.

Each report must retain source-omitted abstentions, per-class recall, invalid completions, incorrect confident choices, exact source-summary matches and **complete correct parent/fixed reversals across all four projects**.

## Reproduce

[The Phase 5O GitHub Actions workflow](../.github/workflows/phase5o-four-project-published-model.yml) verifies source locks, unit tests and forged input rejections under Python 3.11–3.13. A separate CPU job installs pinned inference libraries, downloads the immutable published model, runs all 12 exact prompts and archives the raw completions and final source diagnostic.

For local execution with the same pinned PyTorch CPU/transformers/Hugging Face packages from the workflow:

~~~bash
python -m pip install --no-deps -e .
PYTHONPATH=src python -m falsum.phase5o_four_project_published_model prepare --out frozen-questions.json
PYTHONPATH=src python -m falsum.phase5o_four_project_published_model execute --inputs frozen-questions.json --out original-outputs.json
PYTHONPATH=src python -m falsum.phase5o_four_project_published_model audit --inputs frozen-questions.json --actual original-outputs.json --out score.json
~~~

Running the tests or the prepare command **never performs inference**. The Python scorer checks original protocol and prediction formatting, but a self-asserted JSON model-run envelope is not cryptographic proof. Check the actual successful public CPU job and its archived original outputs before citing a score.

## What this does not establish

No qualified independent AppSec gold, no third-party developer-adopted evaluator, no hidden model holdout or pretraining disjointness, no general security review accuracy, no trained model improvement, no new Anjoman Eligible scores, no Telegraph scorer registration and no H2 final submission. Preserve negative results. Do not change the frozen prompt to make the observed model look better.

Next substantial gap: independently submitted developer predictions and source-first adjudication on genuinely fresh materials. The demo and official submission remain untouched by this Phase 5O change.
