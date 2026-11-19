# Phase 5A — Actual public reviewer intake for four executed source witnesses

**Telegraph Season II · Evaluators · SECURITY_REVIEW_GENERAL · November 19, 2026**

## The gap

The earlier [public review intake](../src/falsum/independent_review_intake.py) scans an old, separate four-case research queue in data/real-fix-queue.json. The newer [Phase 4X source-first review form](../.github/ISSUE_TEMPLATE/independent-executed-source-review.yml) covers **Koa, Hono and two LangChain repairs**, whose source/test bytes and original upstream test executions are authenticated by the [Phase 4U receipt index](../evidence/phase4u-2026-11-18-permanent-four-executed-source-witness-index.json). The older scanner cannot accept the newer review form.

Phase 5A adds a **real public GitHub API census for exactly this newer form**. Its role is to receive external criticism transparently and make a follow-up adjudication possible, not to create fabricated expert scores.

[Source checker](../src/falsum/phase5a_executed_review_census.py) · [Live GitHub Actions workflow](../.github/workflows/phase5a-executed-source-review-census.yml) · [Adversarial test suite](../tests/test_phase5a_executed_review_census.py) · [External-review request](https://github.com/Iniwura/falsum/issues/25).

## Source/evidence contract

The scanner uses read-only GitHub API pages and validates the original Phase 4P source lock and Phase 4U four-stage authenticated execution index **before** it considers any public reviewer issue.

For a GitHub-authored issue using the exact "[FALSUM independent executed-source review]" form, it checks:

1. GitHub issue's canonical URL, issue number and timestamp metadata; non-owner and non-bot GitHub *account* fields. This authenticates neither a human behind the account nor actual expertise.
2. Exact official review-form headings, case/stage identity, the reviewer's stated source conclusion (supported with limits / contradicted or incomplete / ABSTAIN), original analysis, applicability conditions, counterexamples, conflicts and tooling disclosure fields.
3. Immutable **parent source AND fixed source** Git SHA/line permalinks, plus **fixed upstream test** Git SHA/line permalink, matching the already authenticated exact stage. This is *format and identity checking*, not proof that the cited lines justify the reviewer's conclusions.
4. All three review-integrity declarations checked. An account that self-declares "independent" is still unverified; a GitHub issue title, citations or matching reviews are never enough to establish human authorship, independent qualification or security correctness.
5. Uniqueness of GitHub issues and per-case account logins. Multiple issues from one account count as one stated reviewer for the same stage; conflicting opinions and ABSTAIN are preserved instead of averaged away. Incomplete forms are explicitly rejected for intake-format purposes, without declaring the reviewer incorrect.

Issue bodies are not copied into the public artifact. The report retains only the issue URL, GitHub login, exact stated decision, timestamps, body SHA256 and explicit **unverified** review metadata. A public issue may itself contain sensitive content: the request warns against sharing any private code, credentials, exploit payloads or customer data.

The workflow runs on relevant pushes/PRs, every public issue opening/edit/reopening/closure, and manual dispatch. GitHub Actions logs and artifacts preserve the **live issue count**, accepted/rejected *format* counts and **0 independently adjudicated human expert labels**. An unreachable GitHub API does not become a false report of zero reviews: the workflow fails and produces no proof.

## Reproduce locally

Test the fully synthetic adversarial cases (these tests do **not** create genuine reviewers):

~~~bash
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_phase5a_executed_review_census.py' -v
~~~

Run an actual read-only GitHub census:

~~~bash
PYTHONPATH=src python -m falsum.phase5a_executed_review_census \
  --index evidence/phase4u-2026-11-18-permanent-four-executed-source-witness-index.json \
  --source-lock data/phase4p-three-project-open-review-lock.json \
  --out phase5a-public-review-census.json
~~~

No wallet, private Anjoman evaluation material, paid API or model credentials needed. The output is write-once and cannot overwrite the source evidence files.

## Boundaries and acceptance criteria

**The real review census can detect participation and quality of citation formatting, not quality of judgment.** In particular:

| Metric | Permitted interpretation |
| --- | --- |
| Format-valid external GitHub claim | An account posted the correct form and exact source/test links; human/expertise/conflicts still unverified |
| Two agreeing claims | Possible corroboration, but **not** independent verified expert labels without separate checks |
| Disagreement or ABSTAIN | Preserved as useful unresolved evidence, never suppressed to improve a score |
| Source-semantic accuracy | **NULL** until independent adjudication; cannot be inferred from GitHub form formatting |
| New blind holdout/model accuracy | **NULL**; this is an existing public historical four-case source pack |
| New training labels / Anjoman entries / registered scorer | **0 / 0 / false** |
| Official Season II submission | **Not completed** |

**Next required external step:** A genuine independent developer chooses one original case, reads the pinned parent/fixed source and upstream test *before* FALSUM's outputs, and submits an original assessment with evidence. A separate reviewer then checks substance and expertise, independently documents disagreement, and signs a source-specific judgment before any label is promoted. This is not a task that an assistant can truthfully complete on behalf of an independent human.

**New project reliability:** The [Flask historical source regression](PHASE4Z_FLASK_NEW_SOURCE_CASE.md) is separate, verified execution evidence but not a human-reviewed or blind semantic evaluation. The project-disjoint external case request remains [issue #54](https://github.com/Iniwura/falsum/issues/54). Do not conflate these three evidence types.

**No video or official H2 final entry is created by this phase.** The submission gate stays blocked until real owner-only steps are completed.
