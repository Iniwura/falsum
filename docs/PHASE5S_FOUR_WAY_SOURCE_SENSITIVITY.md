# Phase 5S — Source evidence must change the model answer

**FALSUM / Telegraph Season II Evaluators / SECURITY_REVIEW_GENERAL / 21 November 2026**

## Why this benchmark is harder

Our earlier 80-item source-test scorecard had a **perfect 80/80 metadata-only shortcut**, and the revised 30-question set still allowed 22/30 without reading source. Phase 5P upgraded the input to eight **actual authenticated original Git code excerpts** across four previously researched public projects, but the published small Qwen model returned ABSTAIN on all 12 prompts. A raw accuracy percentage can mask the problem: correct no-source abstention is easier than correct source reasoning.

**Phase 5S makes correct changes of answer under both source-code changes and displayed answer-order swaps the primary endpoint.** It reuses exactly the already authenticated four historical upstream projects, and does **not** pretend they are new, blind, independently labelled or model-pretraining-disjoint.

## Frozen pre-inference design

The exact policy was [committed separately before implementation or model forward passes](../data/phase5s-preinference-four-way-source-reversal.json): commit `87998536dde9021f418cbd6fcb80a66d37706599`, Git blob SHA-1 `5d7dff79205c24d465d71d45d4457b0ff992b67d`.

Every one of the four projects receives:
- Original vulnerable source, original A/B answer order.
- Original vulnerable source, swapped B/A answer order.
- Original fixed source, original A/B order.
- Original fixed source, swapped B/A order.
- Missing source, original A/B order.
- Missing source, swapped B/A order.

Total: **24 authenticated source-prompt conditions** across four public projects, reference labels balanced **8 A / 8 B / 8 ABSTAIN**, with **16 source-present** and **8 source-omitted** questions.

The reference answers are **researcher-derived from published historical code and original upstream facts**, not qualified independently reviewed AppSec ground truth. The evaluator input contains only neutral question and actual source code excerpt with the two options. No Git commit hash, source URL, parent/fix name or condition type appears as an extra model message. The original public repository is still open, so a model or developer with external lookup can cheat; the formal bound below applies **only to the prompt-only source-masked attacker**.

## The source-blind bound is mathematically meaningful

Under the specified prompt-only source-masked setting, the candidate sees the exact same question and option order for *both* historical source revisions. Yet the correct answer flips A↔B. The source-blind candidate cannot be correct on both.

For each project, there are four code-present tasks. Any source-masked response can score at most two correct. Across four projects, that is **8/16** source-present. Even correctly abstaining on all eight deliberately no-source tasks yields at most **16/24 overall**.

More importantly, a source-blind candidate gets **0/4 complete four-way source AND option-position reversals**, even if it scores 16/24 overall. This metric cannot be gamed by always selecting a particular answer slot or always abstaining. It is a *discrimination criterion*, **not proof the source-derived gold is independently correct**.

## Genuine frozen published model comparison

The workflow compares two published original Qwen model checkpoints without tuning prompts after inference:

- `Qwen/Qwen2.5-0.5B-Instruct`, immutable publisher revision `7ae557604adf67be50417f59c2c2f167def9a775`, original previously verified safetensors SHA256 `fdf756fa7fcbe7404d5c60e26bff1a0c8b8aa1f72ced49e7dd0210fe288fb7fe`.
- `Qwen/Qwen2.5-1.5B-Instruct`, immutable publisher revision `989aa7980e4cf806f80c7fef2b1adb7bc71aa306`. Its exact original publisher safetensors SHA256 is checked from the immutable downloaded file before any score claims.

The same 24 prompts, same source code, greedy generation and no few-shot examples are used for both. The Python 3.11–3.13 contract suite checks question balance, option-swaps, exact reference mapping, absence of source role in model messages, write-once output and forged metadata rejection. The actual model jobs must load publisher safetensors, execute all 24 CPU forwards, and archive the full original completions and scores.

**Results:** Only report the genuine model scores from successful live Actions jobs after the immutable outputs have been inspected. A green unit-test matrix does not count as a model measurement. Failed model downloads or runtime limitations are failures, not outcomes to guess.

## Run locally / as an outside developer

~~~bash
git clone https://github.com/Iniwura/falsum.git
cd falsum
python -m pip install --no-deps -e .

falsum score-counterbalanced-source export \
  --questions-out counterbalanced-24.json \
  --template-out decisions.json

# Fill the exact 24 A/B/ABSTAIN decisions from a genuine external method,
# then compare with publicly disclosed researcher references.
falsum score-counterbalanced-source score \
  --questions counterbalanced-24.json \
  --predictions decisions.json \
  --out score.json

# Disclosed synthetic prompt-only source-blind baseline, never a model:
falsum score-counterbalanced-source baseline --out baseline.json
~~~

Export requires public access to original immutable upstream Git code files, which are hash-checked. All reports are write-once. The results separate **total matches**, **source-present matches**, **no-source abstention**, **correct full four-way reversals**, invalid output and confidence without source.

## Judge interpretation

A model exceeding the source-blind upper bound or completing correct source/option counterfactuals would demonstrate greater sensitivity to source context on these four **known historical public cases**. It would *not* prove a new trained evaluator, generalizable AppSec expertise, leaderboard-rank improvement, independent human gold, network registration or outside adoption. The four-project sample is too small for broad accuracy claims.

**The practical contribution is the falsifiable benchmark and provenance discipline, not a promised high model score.** Cross-check the separate [real canonical external Telegraph task-insensitivity failure](PHASE5R_CANONICAL_TELEGRAPH_TASK_INSENSITIVITY.md), which shows why output relevance matters beyond code-history puzzles.
