# FALSUM Phase 3G — GitHub-attributed public review intake

**Goal:** connect the seven source-and-test-verified Phase 3F security-family questions to a repeatable public review intake. Phase 3E's separate five aiohttp callsite questions remain unchanged.

## Evidence boundary

Phase 3F already re-fetches and checks the original public upstream security-fix commits, source file Git blobs, regression-test Git blobs, and patches. Phase 3G requires those seven exact project/commit/blob identities, verifies both candidate answer texts against their SHA256 digests, and refuses any upstream packet claiming expert approval, training permission, production exploitation, model release or network eligibility.

For actual review collection, the CLI fetches Issue #3 comments directly from GitHub's public API over HTTPS. It checks numeric comment and account IDs, canonical comment/issue URLs and GitHub user type, and excludes project-owner comments. It accepts one bounded JSON `falsum-review-v1` block per comment bound to the *current* packet bundle SHA256, exact candidate answer hashes, and exact upstream source and test links.

Two comments from the same account on the same packet are both quarantined. Distinct reviewers' contradictory A/B preferences and ABSTAIN decisions remain visible. Their author identities may be attributed to public GitHub accounts, but neither author independence nor AppSec expertise nor underlying security judgment is verified by this program. No comments are automatically marked as expert-approved labels.

## Reproduction

Requires Python 3.11+, public GitHub HTTPS and the repository root. Optionally set `GITHUB_TOKEN` to avoid anonymous rate limits. Don't commit tokens.

```bash
PYTHONPATH=src python -m falsum.phase3f_multifamily_material \
  --old-queue data/real-fix-queue.json \
  --train-queue data/real-fix-train-candidates.json \
  --catalog data/phase2w-applicability-rules.json \
  --out /tmp/falsum-phase3g-seven.json

PYTHONPATH=src python -m falsum.phase3g_public_review \
  --packets /tmp/falsum-phase3g-seven.json \
  --out /tmp/falsum-phase3g-unapproved-comments.json \
  --templates-out /tmp/falsum-phase3g-reviewer-templates.json

PYTHONPATH=src python -m unittest discover -s tests -p test_phase3g_public_review.py -v
```

The tool refuses to overwrite pre-existing report or template files. Packet hashes use canonical sorted-key JSON with a trailing newline, consistent with the prior evidence contract. Regenerate the reviewer templates whenever the packet bundle changes.

A dedicated [Phase 3G GitHub Actions workflow](../.github/workflows/phase3g-public-review-intake.yml) runs adversarial unit tests, re-verifies the upstream patches, fetches live Issue #3 comments and uploads reviewer templates plus an explicit **unapproved claims** report. A successful green online run, not local fixture tests alone, establishes that public comment attribution works.

## How to review one case

1. Visit [Issue #3](https://github.com/Iniwura/falsum/issues/3). Choose any security family. Open the matching source diff, real regression test and advisory.
2. From the latest successful Phase 3G Actions artifact, copy the `github_comment_markdown` value for your packet into an Issue #3 comment. Preserve the `falsum-review-v1` code fence and exact bundle/answer/source/test hashes and URLs.
3. Replace *both* `REPLACE WITH` placeholders with your own evidence-based reasoning and unresolved deployment facts. Choose A, B or ABSTAIN. Don't assume either authored candidate answer is correct.
4. Name unknowns: actually installed release, route registration and reachability, attacker control, environmental boundary, and observed exposure. A historical patch is not proof a separate live application is exploitable.

Do not post private application code, credentials, exploit payloads, nonpublic security findings or deployment secrets in a public comment. Use responsible disclosure for sensitive findings.

## What is still blocked

- **Independent reviewer approvals: 0.** A GitHub account is not evidence of security competence or independence.
- **Approved training pairs: 0.** No Phase 3G comments are permitted to train the reward model automatically.
- **Accepted Telegraph evaluation rows: 0.** A source-backed question and public comment do not establish current network eligibility.
- **Model readiness:** the historical Phase 3D model failed both context-reversal families. The release veto remains.
- **Blind measurement:** seven reviewed-source projects and previously published failures are not blind holdout material. Keep the fresh Phase 2U Tornado, Undici and websockets sources out of training; future project/version-disjoint tests require independent selection.

**Next priority:** obtain real source-grounded external reviews, verify expertise and semantics outside this automated intake, then use approved material to train and evaluate against truly separate cases. Do not claim security accuracy or a win probability from these workflow improvements alone.
