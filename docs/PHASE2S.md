# Phase 2S — AI-assisted AppSec review and context reversal (research only)

**Status: AI-authored source review, not independent human validation.** No human expert has approved any label. No training or Anjoman submission has been authorized.

## What was built

The [research casebook](../data/ai-review-drafts.json) contains four AppSec dossiers on historical Requests, aiohttp, Jinja2 and Axios security repairs. Each distinguishes observed source code, the published patch, the actual regression test, deployment preconditions and missing evidence.

The [contrastive builder](../src/falsum/ai_review_benchmark.py) checks pinned GitHub commit and source/test blob identities, replays 8/8 pre/post file transitions byte-for-byte, then selects a meaningful original pre-fix source excerpt. It presents two invented deployment contexts per project with the **same two candidate answers**. The preferred AI-proposed candidate reverses between contexts. This design exposes models that ignore the question and simply prefer answer wording.

The model-facing packet has **no proposed preference label, GHSA/CVE ID or post-fix code**. A separate artifact stores provisional AI-proposed answers, authentic immutable source links and specific uncertainties. The model-facing packet is NOT a sealed holdout: all code and drafts are public.

[Source-backed 8-case AI draft run](https://github.com/Iniwura/falsum/actions/runs/41210477426) passed **14/14 adversarial tests**, reproduced the **8 actual source/test file revisions** across 4 repositories and checked **16/16 full question-plus-answer renderings** with the real ModernBERT tokenizer. The longest uses **440 / 512 tokens**, with no silent truncation.

- [Questions only, without proposed answers](https://github.com/Iniwura/falsum/actions/runs/41210477426/artifacts/13045887870)
- [Provisional AI answer key and actual patch/test evidence](https://github.com/Iniwura/falsum/actions/runs/41210477426/artifacts/13045927683)

## Findings and important limitations

| Project | Original source / repair finding | Positive deployment prerequisite | Missing deployment prerequisite | Strength of source test |
| --- | --- | --- | --- | --- |
| Requests | Redirect-time Proxy-Authorization attachment to an HTTPS prepared request may expose proxy URL credentials. Patch stops attaching directly on HTTPS; urllib3 handles tunnel proxy authentication | Credential-bearing proxy URL and redirected HTTPS destination | Proxy URL has no user/password | Tests HTTP vs HTTPS prepared header presence, not observed production credential exfiltration |
| aiohttp | A static-file route's follow_symlinks-true path skipped containment checking. Patch normalizes and checks before resolution | Publicly reachable static route with follow_symlinks enabled | Only relevant route has it disabled | Added raw-socket path traversal regressions, including symlink/normalization case |
| Jinja2 | The historical attr filter can bypass sandbox handling of the string format method; patch delegates through environment.getattr | Attacker controls template source compiled by the sandbox | Users only control template values, not expressions or source | New test asserts attempted sandbox escape raises SecurityError |
| Axios | Historical buildFullPath ignores baseURL for absolute URLs; v0.x patch adds opt-in allowAbsoluteUrls=false handling | Caller forwards attacker-controlled absolute URL to client with sensitive header | Call site accepts only server-chosen relative path enum | **Selected regression test covers no baseURL configured. It does not by itself verify security behavior when baseURL is configured.** The patch changes that branch, but merely upgrading does not prove safe defaults |

Primary source records:

- [Requests fix](https://github.com/psf/requests/commit/74ea7cf7a6a27a4eeb2ae24e162bcc942a6706d5) and [advisory](https://github.com/psf/requests/security/advisories/GHSA-j8r2-6x86-q33q)
- [aiohttp fix](https://github.com/aio-libs/aiohttp/commit/1c335944d6a8b1298baf179b7c0b3069f10c514b) and [advisory](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-5h86-8mv2-jq9f)
- [Jinja2 fix](https://github.com/pallets/jinja/commit/065334d1ee5b7210e1a0a93c37238c86858f2af7) and [advisory](https://github.com/pallets/jinja/security/advisories/GHSA-cpwx-vrp4-4pq7)
- [Axios 0.x fix](https://github.com/axios/axios/commit/02c3c69ced0f8fd86407c23203835892313d7fde) and [advisory](https://github.com/axios/axios/security/advisories/GHSA-jr5f-v2jv-69x6)

**Important Axios conclusion:** The original selected test asserts an absolute URL with undefined baseURL and allowAbsoluteUrls=false stays absolute. It does not directly assert that a configured baseURL constrains an absolute URL. That is a test-scope weakness, not proof the patched library fails; evaluate the actual source branch and additional tests separately. The guard is opt-in, so application configuration still matters.

## Quality and scope rules

- Original code snapshots and upstream security patches are real. **Deployment facts and preferred answers are fictional AI-assisted scenarios**, not observations of live customers.
- The deliberately repeated good/bad candidate essays across paired contexts are useful for model diagnostics but violate the spirit of official uniqueness/style-diversity expectations if passed off as final eligible training data.
- No independent human reviewer verified these verdicts. A validated GitHub source only verifies source identity, not whether the AI's technical explanation is complete.
- No "AI panel", multiple personas or repeated LLM calls count as independent reviewers.
- Nothing in this phase creates eligible Anjoman rows, a sealed holdout, actual model-quality certification or a live evaluator registration.

## Real model diagnostic

The [AI-reviewed model probe](../src/falsum/ai_review_model_probe.py) and [Actions workflow](../.github/workflows/ai-review-model-probe.yml) use the **actual previously trained frozen ModernBERT LoRA checkpoint**, verify its archived SHA-256, and score all eight provisional cases plus an answer-only control. The metric is agreement with AI proposals, **not independently observed security accuracy**. The answer-only control cannot pass both opposed contexts from the same source family.

## Next

Inspect actual model and case-level results; then improve source-grounded evidence and real task diversity without training on repeatedly inspected provisional diagnostic pairs. Build separately authored and reviewed believable answer comparisons that can meet the official Anjoman checks; submit or register only after real acceptance. The current official bounty is **unfunded** and requires eligible material and a registered evaluator, so building more hypothetical research tests does not finish it.

**At this checkpoint: 0 independent AppSec approvals; 0 accepted Anjoman evaluation rows; no live registration.**
