# Phase 2T — Four new authentic security-fix projects, frozen-model generalization check

**Verified on 31 October 2026. Research-only.** The frozen original ModernBERT LoRA checkpoint was NOT retrained, promoted, uploaded, or registered.

## Why this phase matters

Phase 2S identified a strong failure to reverse model preference when the correct provisional security conclusion changes with deployment conditions: 0 of 4 families flipped, 4 of 8 AI-draft preferences agreed with.

Simply training on those already-inspected cases would risk memorizing the answers. Phase 2T introduced FOUR ADDITIONAL PUBLIC REPOSITORIES, verified their source and regression tests and built eight new research comparison challenges. All four original projects and their fixed advisory issues are kept in a separate, publicly inspected research pool.

The new source file is called a TRAIN CANDIDATE pool ONLY because it could support later training *after new independently adjudicated labels exist*. It has not been trained on in Phase 2T. **Now that we have also scored and inspected its eight AI challenges, it is NOT a pristine future holdout**. Any later study that trains on these examples cannot claim generalization to them.

## Independently reproducible upstream facts — not human-verified AppSec conclusions

| New project | Published issue and actual source revision | Main precondition | What the regression test addresses |
| --- | --- | --- | --- |
| [Starlette](https://github.com/Kludex/starlette/commit/1797de464124b090f10cf570441e8292936d63e3) | [GHSA-v5gw-mw7f-84px](https://github.com/Kludex/starlette/security/advisories/GHSA-v5gw-mw7f-84px) / CVE-2023-29159. An unsafe lexical path comparison was replaced by component-aware commonpath. | StaticFiles can receive traversal-style paths targeting readable siblings whose names begin with the static-root prefix | Added requests for a same-prefix sibling file and directory must be denied |
| [urllib3](https://github.com/urllib3/urllib3/commit/adb358f8e06865406d1f05e581a16cbea2136fbc) | [GHSA-gwvm-45gx-3cf8](https://github.com/advisories/GHSA-gwvm-45gx-3cf8) / CVE-2018-25091. Redirect header removal compared differently cased header names incorrectly. | A caller supplies sensitive headers in the affected casing and follows a cross-host redirect | New dummy-server tests check the lower-case authorization header is removed from cross-host redirected traffic |
| [Django](https://github.com/django/django/commit/55519d6cf8998fe4c8f5c8abffc2b10a7c3d14e9) | [GHSA-xxj9-f6rv-m3x4](https://github.com/advisories/GHSA-xxj9-f6rv-m3x4) / CVE-2024-24680. Recursive intcomma processing was replaced with non-recursive grouping. | Extremely long user-controlled numbers can reach the template filter without an effective length limit | Expanded template-filter formatting tests cover changed number rendering behavior; these tests do not by themselves prove every unbounded production path |
| [Express](https://github.com/expressjs/express/commit/0b746953c4bd8e377123527db11f9cd866e39f94) | [GHSA-rv95-896h-c2vc](https://github.com/expressjs/express/security/advisories/GHSA-rv95-896h-c2vc) / CVE-2024-29041. This is the improved 4.19.2 malformed redirect URL fix, not the earlier interim patch. | An application accepts user-controlled redirect destinations and validates host/allowlist before calling res.location or redirect | Expanded malformed Location/encoding tests; no universal claim about each application's allowlist safety |

The [new source-only queue](../data/real-fix-train-candidates.json) lists one immutable Git parent and patch SHA, exact source/test file paths, and the post-fix Git blob IDs for each. Its [source-validation CI](https://github.com/Iniwura/falsum/actions/runs/41232688735) passed:

- Four authentic single-parent fix commits, source and regression-test patches and Git blobs.
- **8 / 8 exact upstream parent-to-fix source/test file transitions** recreated and verified against real Git object hashes.
- Four distinct projects separate from the four prior inspected code-review projects; no repeated commit, advisory, parent SHA or selected source/test Git blob across the pools.
- Offline tests covering source tampering, project leakage and misrepresented network readiness.
- Two separate evidence artifacts: [source replay and project isolation](https://github.com/Iniwura/falsum/actions/runs/41232688735/artifacts/13054316310).

### The model's OLD data actually included two earlier diagnostic advisories

The prior research-model's pinned [advisory queue](../data/advisory-queue.json) contains **32 advisory records**. Its TRAIN portion includes the exact published **Jinja2 GHSA-cpwx-vrp4-4pq7** and **Axios GHSA-jr5f-v2jv-69x6** examples previously inspected in Phase 2S. The earlier four-case diagnostic was therefore **not cleanly unseen to that original model**.

The [prior-exposure auditor](../src/falsum/phase2t_prior_exposure.py) confirmed:

- **0/4 new projects** had either their exact GHSA or their matching project package in that historical pinned advisory queue.
- **2/4 earlier inspected projects** reused a GHSA appearing in the historical TRAIN partition.

This check does **NOT** prove the new fixes were unknown to base ModernBERT pretraining or other Internet models. It only excludes direct reuse of those project packages and exact advisory IDs in the specific pinned prior training queue.

### AI-assisted new context-reversal packet — not expert labels

[Four new review dossiers](../data/ai-review-train-candidate-drafts.json) explicitly separate the historic source, fix and test observations from invented deployment facts and limits. Each has two opposite conditions:

- Exposure prerequisite supplied: AI provisionally prefers the answer flagging a specific conditional risk.
- Essential exposure prerequisite absent: AI provisionally prefers a cautious answer that identifies the missing evidence.

The two candidate essays for each project are **exactly identical across the two contexts**. A scorer that always likes one essay style cannot pass both. The new [model-facing packet CI](https://github.com/Iniwura/falsum/actions/runs/41232403688) passed **14 generic and 4 new-project adversarial tests**, verified all four source fixes and checked **16 / 16 full ModernBERT Task-plus-Answer inputs** using the actual tokenizer. Maximum was **466 / 512 tokens** with no silent truncation.

[Model-facing draft A/B questions](https://github.com/Iniwura/falsum/actions/runs/41232403688/artifacts/13053724612). [Separate AI-proposed answer key and source evidence](https://github.com/Iniwura/falsum/actions/runs/41232403688/artifacts/13053739540).

These are public synthetic deployment hypotheticals, not a sealed holdout, no human expert label, and NOT Anjoman-eligible evaluation data.

## Frozen real model on the four new projects

The [actual pinned LoRA scoring workflow 41232475893](https://github.com/Iniwura/falsum/actions/runs/41232475893) verified the SAME original checkpoint SHA-256 as Phase 2S, reconstructed the exact new public challenge inputs and used real ModernBERT scoring for eight context cases plus answer-only ablation: **24 actual inferences**.

| Source family | Model's essay preference in BOTH contexts | Exposure-case AI proposal | Missing-precondition AI proposal |
| --- | --- | --- | --- |
| Starlette | Report finding | Agree | Disagree |
| urllib3 | Conditional / no confirmed finding | Disagree | Agree |
| Django | Report finding | Agree | Disagree |
| Express | Conditional / no confirmed finding | Disagree | Agree |

Total: **4 / 8** agreements with AI-proposed answers and **0 / 4** two-context families matched in full. This reproduces the earlier context-reversal failure on a separate four-project set.

The numerical model scores DO react to question context; they simply did not reverse the **preferred essay** in any project family. Do not claim it ignores all question words, or that the AI-proposed judgments are professionally verified ground truth.

[Real model research artifact with all eight score margins](https://github.com/Iniwura/falsum/actions/runs/41232475893/artifacts/13053679923).

[Permanent model hash, source overlap, case-level margins and project assignments](../evidence/phase2t-2026-10-31.json). The original CI JSON report SHA-256 was recorded before this evidence summary was committed, enabling direct comparison.

## Next model experiment

**Do not retrain using the same inspected A/B packet and then count it as independent evaluation.** Obtain fresh project-separated training examples and genuinely new untouched source groups, with credible application deployment/configuration tasks and diverse negatives. Independently adjudicate important labels where possible. Evaluate whether a context-aware improvement actually flips winners on disjoint projects; check answer-only and adversarial ablation.

Technical operation is established: the earlier 601 MB official ABI-v2 WASM model runs under Wazero with near-exact PyTorch numerical parity. **The blocker is defensible model quality and official accepted evaluation-data/network status, not how to bake WASM**.

**No expert-approved pairs, no eligible Anjoman rows and no network registration are claimed in Phase 2T.**
