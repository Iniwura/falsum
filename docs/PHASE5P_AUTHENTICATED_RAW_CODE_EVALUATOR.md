# Phase 5P — Authenticated raw upstream source-code evaluation

**Telegraph Season II · Evaluators · SECURITY_REVIEW_GENERAL · 21 November 2026**

## Why Phase 5P exists

Phase 5O used researcher-authored behavior summaries; its genuine Qwen2.5-0.5B-Instruct model returned ABSTAIN on all twelve items: 4/12 public author-reference matches and 0/4 complete parent/fix reversals. The model was not reading actual code.

Phase 5P uses **original upstream code** from both historical source revisions across PyJWT, Werkzeug, MCP Python SDK and Pillow. The [pre-inference protocol](../data/phase5p-raw-code-preinference-protocol.json) was frozen before code or model inference at Git blob SHA-1 a4eae5fd74be73e99f255d8f45da319c928aea48. Its [preexisting historical upstream selection](../data/phase4h-frozen-four-new-source-projects.json) has Git blob SHA-1 9fc67edec49c33d3efdb4a6128bd7c6c6b7766e2.

For eight source-present tasks, the full file is fetched from the immutable upstream Git commit and its Git blob SHA-1 is recalculated and compared to the preexisting original reference before extracting the code excerpt. Four no-source controls include no implementation. Every project uses one **neutral question** across both versions and the omitted-code control; answers are counterbalanced 4 A, 4 B, 4 ABSTAIN.

**Important:** These are previously studied publicly known fixes, and questions/reference answers are derived by FALSUM, not qualified independent expert gold. Source links are visible. This is open-book evaluator material, not a blind holdout, unseen-model generalization, new independent security finding or a proof of deployed exploitability.

## Reproduce

Python 3.11+, public GitHub source access, no payment, token or API key for export and scoring.

~~~bash
git clone https://github.com/Iniwura/falsum.git
cd falsum
python -m pip install --no-deps -e .

falsum score-raw-code export \
  --questions-out raw-code-questions.json \
  --template-out candidate-predictions.json

# Supply 12 actual independent model or human decisions A, B, ABSTAIN,
# in the previously generated candidate-predictions.json.

falsum score-raw-code score \
  --questions raw-code-questions.json \
  --predictions candidate-predictions.json \
  --out candidate-report.json
~~~

The source archive generator rejects file identity drift. The response scorer rejects mismatched hashes, reordered/unknown IDs, missing predictions, unknown labels and extra authoritative fields. Every result separately shows class agreement, complete source revision reversals, unnecessary code-present abstentions, unsupported confidence without source, and invalid replies.

Three constant baselines obtain 4/12 each. A shortcut choosing the same answer for every code-present task and ABSTAIN when no code is supplied obtains **8/12** but **0/4 complete reversals**. These are synthetic baselines, not measured inference.

## Real published model run

The [GitHub Actions workflow](../.github/workflows/phase5p-authenticated-raw-source-model.yml) runs offline adversarial tests on Python 3.11–3.13, authenticates eight actual pinned source files, then performs genuine greedy CPU model forward passes on all 12 prompts. The model is the unchanged original published Qwen/Qwen2.5-0.5B-Instruct checkpoint revision 7ae557604adf67be50417f59c2c2f167def9a775 (original model.safetensors SHA-256 fdf756fa7fcbe7404d5c60e26bff1a0c8b8aa1f72ced49e7dd0210fe288fb7fe).

Archive every original raw completion; INVALID counts wrong, not ABSTAIN. Do not cite a model score unless the successful real CPU run and artifact have been checked. Passing synthetic unit tests does not prove inference.

## Honest limits

The source facts are authentic, but the narrow behavioral questions and answer references remain **researcher-authored**. Previously public case selection and complete answer-generation code can leak shortcut information. The tool does **not** claim expert-certified gold labels, real external developer adoption, trained FALSUM model improvement, registered Telegraph evaluator, official Anjoman quality, hidden private holdout, or an official H2 entry.

Do not claim this source excerpt workflow re-executes upstream regression tests. Earlier historical runs provide separate source/test execution witnesses.

## Next release gate

After authentic source-and-model CI, obtain genuine outside reproduction and independently scrutinize the evaluator claim. Improve the judge's one-command path, external developer onboarding and submission evidence. Do not count any self-run model or owner-written review request as an outside developer.
