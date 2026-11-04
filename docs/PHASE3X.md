# FALSUM Phase 3X: source-executed counterfactual diagnostics

**Internal research only.** No new Anjoman rows, independently approved labels, model training, registered evaluator, or live UI changes.

## Why

The previous seven public A/B cases relied on strong wording cues. Our internal AI-assisted review also found two upstream test coverage gaps:

- **Axios:** the cited buildFullPath.spec.js did not exercise an **actual configured baseURL**, an **absolute off-origin requested URL** and **allowAbsoluteUrls=false** together.
- **Django:** the cited humanize intcomma tests primarily cover normal formatting, not very long digit strings or their execution behavior.

These findings do not, by themselves, prove a production vulnerability.

## The new exact-source experiments

GitHub Actions checks out only required files from four full, immutable upstream revisions with sparse checkout. Every executed file is verified against its pinned Git blob SHA-1 before running.

| Library | Parent revision | Fixed revision | Scope |
| --- | --- | --- | --- |
| Axios | 8603e677c09fb81bd106999c194308dd230bc596 | 02c3c69ced0f8fd86407c23203835892313d7fde | Actual buildFullPath.js helper and both helpers; **no HTTP request sent** |
| Django | 9cefdfc43f0bae696b56fa5a0bf22346f85affff | 55519d6cf8998fe4c8f5c8abffc2b10a7c3d14e9 | Actual intcomma function extracted from pinned source AST; **no complete Django app or server** |

[Axios probe](../tests/phase3x_axios_source_probe.cjs) covers six URL construction conditions before and after the patch, checking resulting origins rather than extrapolating to SSRF or a deployed caller.

[Django probe](../tests/phase3x_django_source_probe.py) bounds digit input to 13, 12 or 3601 characters, executes the function in an isolated subprocess, normalizes recursion depth to 1000 and has a hard timeout. These are strings with localization deliberately disabled. The 3601-digit case tests whether the historical recursive grouping fails and the patched function returns. No actual web traffic is generated.

### A separate formatting observation worth testing

An initial local source-function inspection suggests the exact pinned patched Django formatter may produce an **extra leading comma for a 12-digit ASCII string** when localization is disabled. This is separate from the long-input recursion issue. The CI probe independently checks string grouping and first-character outcomes before accepting the observation.

That would be an **isolated function behavior** in this specific pinned source revision, not a confirmed production Django bug, application downtime, security vulnerability or general statement about currently released Django.

## Harder technical decisions

[Research diagnostic builder](../src/falsum/phase3x_hard_cases.py) consumes the two real test reports, checks source provenance and creates **18 internal research comparisons**: eight Axios destination-origin decisions, six Django return/recursion outcomes, two Django first-character formatting outcomes, and two ABSTAIN questions for deployment claims the source-only probes cannot prove.

Both A/B answers are concrete and similarly phrased. Some supported answers **reverse** when the source revision or configuration changes. There are no invented model outputs or success claims.

Every case explicitly has no approved expert label and is disallowed from training. The builder exports no eligible Anjoman rows. This material is **known and not a blind holdout**; it cannot validate a trained evaluator or establish accuracy.

## Reproduce

1. Use the precise immutable source checkouts in [Phase 3X CI](../.github/workflows/phase3x-targeted-source-probes.yml).
2. Execute the Node.js Axios probe with AXIOS_BEFORE_DIR, AXIOS_AFTER_DIR and PHASE3X_AXIOS_OUT pointing to the checkouts and a fresh output file.
3. Execute the Python Django probe with --before, --after and --out pointing to the two pinned files and a fresh output JSON.
4. Run the source-derived diagnostic builder with --axios, --django and --out.
5. Verify the artifact from the successful GitHub Actions workflow; any SHA drift, unexpected result or falsified provenance fails the run.

Python's AST extraction removes only the Django registration decorator so the exact function can run without its framework. This does **not** test the whole installed Django system. No external script dependencies or model download are needed for the probes.

## Next release gate

Obtain **real external human security review**, freeze new project-disjoint examples *before* tuning, then run actual FALSUM scorer inference and a baseline using the **same sealed evaluation set**. Report all passes and failures. Existing candidate models remain quarantined. The separately eligible 20 Anjoman preference pairs and the production interface are unchanged.
