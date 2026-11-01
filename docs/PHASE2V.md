# Phase 2V — Paired-context loss experiment (research-only)

**Purpose:** Address the repeated failure of the original and Phase 2U ModernBERT models to change answer rankings when an application’s deployment preconditions change. This is a real new gradient-training experiment with independently measured model execution, but the judgments in these tasks are **AI-authored hypothetical AppSec labels, not independent human ground truth**.

## Why a new objective?

The earlier official Bradley-Terry research LoRA scored 52 synthetic advisory comparisons plus eight deployment-context contrasts with the usual independent pairwise loss. It passed the official trainer’s small synthetic GHSA test, yet switched correctly for **zero** two-context project families on four previously inspected projects and on three separately sourced projects.

Independent per-answer ranking encourages a shortcut: consistently preferring either “report vulnerability” or “insufficient evidence.” The code source does not change between a case’s exposure and missing-precondition question. The correct AI-proposed answer preference reverses based on concrete deployment facts.

## Real coupled loss

For the same source family, with two candidate essays F (report finding) and C (conditional assessment):

- \`d_exposed = score(exposed_prompt, F) - score(exposed_prompt, C)\`
- \`d_missing = score(missing_prompt, F) - score(missing_prompt, C)\`
- \`d_answer_only = score(empty_prompt, F) - score(empty_prompt, C)\`

A research-only custom trainable PEFT model minimizes:

\`softplus(t - d_exposed) + softplus(t + d_missing) + w * softplus(2*t - (d_exposed - d_missing)) + n * (d_answer_only ** 2)\`

Default research hyperparameters: margin target \`t=0.25\`, cross-context weight \`w=0.6\`, answer-only neutrality \`n=0.1\`; 16 gradient steps, learning rate 0.00012, seed 23. A test checks that the gradient on the first margin is negative (increasing exposure finding preference), the second positive (decreasing finding preference when exposure is absent), and the answer-only gradient penalizes the sign of its shortcut.

The implementation reuses the official V2 ModernBERT architecture, tokenizer conformance check, Task/Answer rendering, 512-token cap, and actual trainable PEFT adapter. **It is NOT the upstream official training procedure**. The custom objective is deliberately labeled as an experiment and cannot be represented as an official Telegraph-certified model.

## Train/evaluate isolation

The four training source families are historical Starlette, urllib3, Django and Express fixes from [Phase 2T](PHASE2T.md). They were previously inspected and already influenced the Phase 2U checkpoint. Thus apparent in-sample gains are not evidence of new security intelligence.

The separate diagnostic group is three historically authentic source/test-replayed projects: Tornado, Undici and Python websockets. These were **not used as Phase 2V training cases**, but their questions and earlier model outcomes were already inspected in Phase 2U, and their AI-proposed answers are not verified by independent experts. **Do not call them blind, sealed, independently accurate, or Anjoman accepted**.

The input Phase 2U actual adapter has its immutable file-manifest SHA-256 pinned. Training source questions and provisional proposed answers must match the previous Phase 2U provenance manifest exactly. Changed questions, missing context pairs, duplicate source projects, false expert labels, release-status promotion, non-finite model outputs, and mismatched hashes are refused.

The Phase 2V training workflow is [phase2v-coupled-research.yml](../.github/workflows/phase2v-coupled-research.yml). It replays the four original upstream fix/test files, downloads the exact trained predecessor checkpoint, runs 16 real gradient steps, records initial and final **in-sample** margins, then compares actual Phase 2U and Phase 2V LoRA on the same three source-separated tasks with answer-only ablation. It saves actual adapter and scored evidence, without network registration.

- [Training objective and provenance implementation](../src/falsum/phase2v_coupled.py)
- [Gradient direction, project split and fake-review regression tests](../tests/test_phase2v_coupled.py)
- [Real checkpoint source-separated comparison](../src/falsum/phase2v_transfer_eval.py)
- [Machine research runs](https://github.com/Iniwura/falsum/actions/workflows/phase2v-coupled-research.yml)

## Release policy

A positive in-sample margin change means the optimizer can learn **these four already seen AI proposals**; it does not prove useful generalization. Any improvement on the three other projects would be a promising research observation at best, because the benchmark is small, public and AI-labeled. An unchanged result is a failed transfer attempt and must be reported directly.

**No expert ground truth, official Anjoman accepted evaluation records, registered evaluator, or funding is claimed.** The older official ABI-v2 WASM execution proof still shows *technical runtime compatibility*, not model judgment reliability.
