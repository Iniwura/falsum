# Phase 3F — Seven genuinely different public security fixes for independent review

**1 November 2026 — CI-verified reviewer material, NOT independent training labels or a repaired model.**

## Outcome

[Verified workflow 41353459211](https://github.com/Iniwura/falsum/actions/runs/41353459211) passed **28 focused tests** (12 Phase 3F tests + 3 permanent evidence checks + 13 existing real-upstream-fix-corpus checks). The new evaluator-material pipeline:

- Revalidated **8 original upstream security-fix commits**, 4 original and 4 prior train-source candidates, including the historical aiohttp source used in earlier research.
- For each checked commit, verified the **exact full 40-hex Git commit SHA**, expected single parent, **source Git blob SHA-1**, **regression-test Git blob SHA-1**, and actual modified source and regression test textual patches. Saved SHA-256 digests of source and test diffs, without archiving the complete source/test patches.
- Built **7 additional reviewer question packets** spanning **7 unique, non-aiohttp vulnerability families**. This extends the existing five real-app-code callsite questions from [Phase 3E](PHASE3E.md), for **12 prepared and unreviewed questions** across both phases.
- Matched the question's provisional security preconditions to the code-pinned 11-case Phase 2W research catalog, while marking all those conditions as AI-authored, not expert-approved.
- Left all three Phase 2U fresh source-separated diagnostic projects (**Tornado, Undici, websockets**) outside this material set. It also did **not** train on the known Phase 3D failed counterfactuals.
- Authored two possible answers per case that may differ in subtle applicability reasoning, rather than simply asserting a confirmed exploit. Their A/B polarity is mixed; it is **not** released as an approved preference label.

[Verified public artifact: seven reviewed-source candidate packets](https://github.com/Iniwura/falsum/actions/runs/41353459211/artifacts/13102585762). GitHub Actions artifacts are time-limited. The [source-generator code](../src/falsum/phase3f_multifamily_material.py) and immutable upstream queue inputs are retained in GitHub for reproduction.

## The seven different historical source fixes

| Source project and pinned security commit | Vulnerability review family | What a reviewer must establish |
| --- | --- | --- |
| [Requests](https://github.com/psf/requests/commit/74ea7cf7a6a27a4eeb2ae24e162bcc942a6706d5) | Credentialed proxy + HTTPS redirect | Whether proxy credentials and an affected redirect path actually occur |
| [Jinja](https://github.com/pallets/jinja/commit/065334d1ee5b7210e1a0a93c37238c86858f2af7) | Sandboxed attr filter | Whether untrusted parties control the *template source*, not merely variable data |
| [Axios](https://github.com/axios/axios/commit/02c3c69ced0f8fd86407c23203835892313d7fde) | Absolute URL override despite baseURL | Whether attacker-supplied absolute URLs reach the affected client with specific options |
| [Starlette](https://github.com/Kludex/starlette/commit/1797de464124b090f10cf570441e8292936d63e3) | Commonprefix versus path-aware static-root containment | Whether readable same-prefix siblings and an exposed affected route exist |
| [urllib3](https://github.com/urllib3/urllib3/commit/adb358f8e06865406d1f05e581a16cbea2136fbc) | Cross-origin Authorization header casing | Whether affected-casing credentials reach a redirect that follows to another host |
| [Django](https://github.com/django/django/commit/55519d6cf8998fe4c8f5c8abffc2b10a7c3d14e9) | Recursive numeric formatting / resource exhaustion | Whether effectively unbounded attacker-controlled numeric input reaches the historical filter |
| [Express](https://github.com/expressjs/express/commit/0b746953c4bd8e377123527db11f9cd866e39f94) | Malformed redirect URL host validation | Whether an attacker controls a target and host allowlist parsing disagrees with emitted Location |

**These fixes are genuine upstream changes, but the authored review questions are NOT seven known exploitable live applications.** The upstream patched version does not prove the affected code is present in any separate user's runtime. Real deployed versions, input flow, configuration, host exposure and attacker influence remain unknown until independently checked.

### What does an example packet contain?

Each packet has the original upstream fix commit, parent revision, source and regression test paths and blob IDs, patch-digest hashes, exact public links, CVE and GHSA, two explicit unapproved source-specific prerequisite descriptions, a focused review question, two SHA256-bound candidate answer texts, and separate source/reviewer eligibility flags.

None contains a stored approved preference. No cases are eligible for automatic training, registration or evaluation-data uploads. A reviewer can choose either candidate or **ABSTAIN**; independent evidence could show that both draft answers need correction.

## Safety, reproducibility and independent review

From the repository's root with Python 3.11+ and GitHub access:

~~~bash
PYTHONPATH=src python -m falsum.phase3f_multifamily_material \
  --old-queue data/real-fix-queue.json \
  --train-queue data/real-fix-train-candidates.json \
  --catalog data/phase2w-applicability-rules.json \
  --out /tmp/falsum-phase3f-seven-review-questions.json
~~~

The process recontacts only the pinned GitHub public commit API endpoints, verifies their exact immutable source and test Git identities, generates the research bundle and refuses an existing output. It never executes upstream application code or tests against real customer systems. It does not fetch or run untrusted code from arbitrary private repositories. GitHub's normal API availability/rate limits apply.

Independent feedback can be submitted in **[FALSUM GitHub Issue #3](https://github.com/Iniwura/falsum/issues/3)**, with packet ID, review of the real source/test and advisory, a reasoned A/B/ABSTAIN decision, explicit unresolved deployment assumptions and public evidence. No private data, exploit payloads or nonpublic security findings should be posted; use responsible disclosure in such cases.

FALSUM cannot claim expert approval merely because a GitHub account makes a comment. Human reviewer independence, actual AppSec expertise, reasoning quality and any future Anjoman eligibility require independent verification. The [Phase 3E intake](../src/falsum/phase3e_review_intake.py) currently applies to its original five source-callsite packets only; **the seven new Phase 3F packets are not falsely routed into that five-case intake**.

## Winning-oriented next work, without data contamination

To improve our chances in Telegraph's Evaluators category we must now:

1. Obtain **actual independent AppSec feedback** on the 12 prepared questions, preserving disagreements and abstentions rather than manufacturing answer keys.
2. Expand quality along a **frozen project-disjoint and version-disjoint test split**. Keep the three fresh Phase 2U projects out of training and human-reviewed training labels for now. Our known Phase 3D model score failures are public diagnostics and must not be described as hidden evaluation.
3. Build training pairs **only** after reviewer validation, try a strictly balanced counterfactual curriculum and compare new trained LoRA results against the previously failed **0/2 context reversals** using the genuine published Foundation runtime.
4. Validate which questions meet the *current* official Anjoman quality and participation rules before claiming any network-eligible row.

**Current counts:** 12 prepared source-backed review questions, 0 independently approved security labels, 0 accepted network evaluation rows, 0 confirmed live exploits and 0 registered evaluator. The existing LoRA remains quarantined because it preferred the same answer across both Phase 3D deployment-fact reversals.

The current implementation improves *source diversity and independent reviewability*. It does **not** yet repair reward-model security-context sensitivity or prove a probability of winning.
