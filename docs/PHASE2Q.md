# Phase 2Q — Read-only independent AppSec review intake

**Verified on 30 October 2026:** real GitHub public review submissions = **0**. FALSUM has no human-reviewed labels and no network-ready scorer.

## Why

[Telegraph's SECURITY_REVIEW bounty #96](https://github.com/telegraphprotocol/bounties/issues/96) requires eligible evaluation question pairs AND a working WASM evaluator registered on the SECURITY_REVIEW family. The specific bounty is marked **unfunded**; separate Hackathon Season II awards or protocol rewards are not paid by this issue.

A GitHub issue, checked attestation, or apparent agreement between two accounts does not establish source truth, expert independence, human authorship, or pairwise preference eligibility. This gate intentionally treats every public issue as an **unverified claim**.

## Implemented

1. Reviewers can use the [structured AppSec issue template](../.github/ISSUE_TEMPLATE/appsec-independent-review.yml) to examine one of the [four verified public security fixes](PHASE2O.md).
2. The [read-only intake workflow](../.github/workflows/appsec-review-intake.yml) triggers when a reviewer opens, edits, reopens or closes an issue. It also runs manually or when its source changes. It uses only read-only GitHub permissions.
3. The [intake verifier](../src/falsum/independent_review_intake.py) reads public GitHub issues at the exact FALSUM repository, validates the authenticated GitHub issue author, excludes the repository owner and bot accounts, and rejects malformed or repeated headings.
4. It requires substantial independent security reasoning, deployment preconditions, uncertainty, a supported / unsupported / uncertain judgment, and both reviewer-attestation checkboxes.
5. It checks the citations point to **exact pinned parent-code and post-fix code/test GitHub paths and SHA revisions**, each with line anchors, plus the exact advisory URL. This verifies URL FORMAT, not the security claim or validity of those cited lines.
6. It groups claims by source case and **unique GitHub account**. One author cannot pose as two independent reviewers using multiple issues.
7. One claim needs another reviewer; conflicting or uncertain claims require adjudication. **Even two agreeing claims do not become verified answers**.
8. The workflow publishes a bounded, read-only JSON index of public claims and deliberate quarantine statuses. No candidate answer is trained, labelled or exported.

The gate's output always uses the following state:

~~~json
{
  "status": "REVIEW_CLAIMS_REQUIRE_MANUAL_ADJUDICATION",
  "accepted_independent_expert_reviews": 0,
  "accepted_training_labels": 0,
  "exportable_preference_pairs": [],
  "network_eligible": false,
  "training_authorized": false,
  "model_accuracy_measured": false
}
~~~

Future approved expert judgments need a separate independent adjudication protocol. Do NOT change this intake code to automatically promote form submissions.

## Verified testing

The [adversarial test suite](../tests/test_independent_review_intake.py) covers 16 cases: no reviewers; one claim; two matches; conflicts; uncertain findings; duplicate reviewer accounts; owner self-review; bots; unpinned parent or fix links; foreign security advisory; unchecked attestations; malformed headings; PRs; duplicate issue identities; ignored unrelated issues; and offline fixture isolation.

[GitHub Actions run 41131525786](https://github.com/Iniwura/falsum/actions/runs/41131525786) passed all 16 tests. Its live public GitHub API step found **1 repository issue, 0 valid structured review submissions, 0 accepted reviews and 0 training labels**. The [read-only artifact](https://github.com/Iniwura/falsum/actions/runs/41131525786/artifacts/13012539131) documents the result.

Run locally on Python 3.11+ with public GitHub network access:

~~~bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_independent_review_intake.py' -v
PYTHONPATH=src python -m falsum.independent_review_intake \
  --queue data/real-fix-queue.json \
  --out /tmp/falsum-review-claims.json
~~~

Optionally supply a read-only GITHUB_TOKEN environment variable for rate limits. Do not commit credentials. An offline --issues-json fixture is explicitly tagged OFFLINE_UNTRUSTED_FIXTURE and is never counted as a live review.

## Next blockers

- Obtain independent human AppSec reviewers and check their actual reasoning and evidence, not only a form or public account.
- Resolve disagreements and independently verify pinned lines and deployment configurations.
- Obtain independently authored **better and worse answer pairs**, with credible negatives and similar length, on real security-review prompts. A claim about a public fix is **not** a pairwise training preference.
- Lock project-separated train, validation and untouched holdout data. Verify actual model gains, not a 2-row accident.
- Pass Anjoman evaluation-eligibility gates separately. Export and register a true WASM evaluator only when validated; network acceptance is not automatic.
- For an active claim on bounty #96, post meaningful /progress updates at least every 72 hours.

**The review-intake milestone is working. The bounty completion criteria are not yet met.**
