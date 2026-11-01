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

## Verified executed result — 1 November 2026

[Real 16-step gradient training, three-project transfer and evidence archive](https://github.com/Iniwura/falsum/actions/runs/41285552033) **completed SUCCESS**. The official-v2-consistent ModernBERT and PEFT adapter ran actual backpropagation using the custom Phase 2V objective. Nine offline gradient, provenance and label-integrity tests passed before and after real PyTorch installation; pinned source/test file replay and the real tokenizer limit passed. Output was saved locally in the GitHub Actions artifact, **never registered**.

**Real source-authenticated training, but synthetic preference labels.** Its train adapter started from actual Phase 2U file-manifest hash \`a20bdc0ffdc9ee776877e60b5c19c225d9279467d005916a6978db1650482d33\` and created a different adapter with hash \`ac0aa02a7554eb263547041eb099ccc62657c382bc3438baf70314f327ab8dba\`. Training consisted of 16 gradient steps (lr 0.00012, target 0.25, contrastive weight 0.6, answer-only penalty 0.1, seed 23). There were 24 full model-render input variants and the largest consumed **466 / 512 tokens**. First sampled objective: **2.26461**; final sampled objective: **2.13346**. These are losses on different shuffled example steps, so the raw numbers alone do not establish convergence. The pre/post exact same four-source in-sample score below is more informative.

| Development diagnostic against AI-authored proposals | Phase 2U input checkpoint | Phase 2V after 16 steps |
| --- | ---: | ---: |
| Four *already trained/inspected* source families: proposed judgments matched | 4/8 | **6/8** |
| Four *already trained/inspected* families: BOTH source-context judgments matched | 1/4 | **2/4** |
| Three separate untrained source projects: proposed judgments matched | 3/6 | **3/6** |
| Three separate projects: BOTH opposite contexts matched | 0/3 | **0/3** |

The four in-sample families were Starlette, urllib3, Django and Express, so **6/8 and 2/4 are not generalization metrics**. Django and urllib3 matched both AI proposals after training; Express and Starlette still failed to reverse their relative answer preference in the missing-precondition context.

The transfer test used the three actual original+repair source/test-replayed projects Tornado, Undici and Python websockets, none included in the Phase 2V research training curriculum. All six context tasks had exactly the same source and fictional environment facts for both models. Both checkpoints made **3/6** preferred judgments agree with AI proposals and **0/3** full family reversals. The numerical answer scores changed, but **no transfer-family preference crossed the necessary decision boundary**.

**Result: the objective is capable of changing this model's in-sample margin behavior but has not shown useful cross-project transfer.** This is a well-grounded negative result and not a successful new evaluator.

[Permanent machine-readable evidence](../evidence/phase2v-2026-11-01.json) pins training and comparison report SHA-256, model manifest hashes, source identities and exact research metrics. The GitHub Actions result artifact ID is **13075226722** and will expire per its seven-day retention policy.

## Release policy

A positive in-sample margin change means the optimizer can learn **these four already seen AI proposals**; it does not prove useful generalization. Any improvement on the three other projects would be a promising research observation at best, because the benchmark is small, public and AI-labeled. An unchanged result is a failed transfer attempt and must be reported directly.

**No expert ground truth, official Anjoman accepted evaluation records, registered evaluator, or funding is claimed.** The older official ABI-v2 WASM execution proof still shows *technical runtime compatibility*, not model judgment reliability.
