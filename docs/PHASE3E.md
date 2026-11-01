# Phase 3E — Authentic external security review material and independent reviewer handoff

**Status: five real Git-pinned source-based review questions prepared; zero independently reviewed/accepted labels.** These materials are for a human validation process and should NOT be represented as five successful Telegraph evaluator contributions.

## Why Phase 3E exists

Our original ModernBERT LoRA now runs with the official shared Telegraph Foundation, but [Phase 3D](PHASE3D.md) demonstrated a measurable context-reversal problem: 0/2 correct whole-family reversals, with only 2/4 researcher-defined deployment-fact preferences matching. A working model is not yet a good evaluator. Simply retraining on the failing eight examples would contaminate our tests.

The official Telegraph Season II Evaluators track allows an **evaluation adapter, evaluation material or both**, with repeatable proof and independently verifiable measurement improvement. See [competition rules](https://hackathon.telegraphprotocol.com/rules). FALSUM is preserving two possible paths: improve the actual reward model with reliable new independent labels, and supply high-quality evidence-anchored evaluation material if reviewers validate it. No hackathon award, acceptance, or training eligibility follows merely from generating questions.

## What's working

[Phase 3E question builder](../src/falsum/phase3e_review_packets.py) re-runs the existing immutable Git-object verification against the same source files and dependency manifests in these real public projects:

| Review packet | Upstream application | Git-pinned observation | Dependency statement |
| --- | --- | --- | --- |
| perspective-external-line-47 | [Perspective aiohttp example](https://github.com/perspective-dev/perspective/blob/444865accd46bcfdeb552960ce4f63fe8286de42/examples/python-aiohttp/server.py#L47) | Explicit \`follow_symlinks=True\` | Optional \`aiohttp>=2,<4\`, *not* resolved install |
| perspective-external-line-48 | [Perspective same file](https://github.com/perspective-dev/perspective/blob/444865accd46bcfdeb552960ce4f63fe8286de42/examples/python-aiohttp/server.py#L48) | Keyword omitted | Same optional requirement profile |
| nlweb-external-line-45 | [NLWeb static handler](https://github.com/nlweb-ai/NLWeb/blob/b423f15d9aeaa023ce75993ac9deed2354597043/AskAgent/python/webserver/routes/static.py#L45) | Explicit \`False\` | AskAgent \`>=3.13.5\` and separate Azure \`==3.13.3\` profiles |
| nlweb-external-line-56 | [NLWeb same handler](https://github.com/nlweb-ai/NLWeb/blob/b423f15d9aeaa023ce75993ac9deed2354597043/AskAgent/python/webserver/routes/static.py#L56) | Explicit \`False\` | Same separate manifest profiles; do not combine them |
| maubot-external-line-112 | [Maubot server](https://github.com/maubot/maubot/blob/f20825b5e3031a89eb5b2edea7f6f7726ada9a10/maubot/server.py#L112) | Keyword omitted | \`aiohttp>=3,<4\`, *not* actual installed version |

All five are **authentic Git-pinned source observations**, not five proven vulnerabilities. Each packet has a question, two **unadjudicated** candidate answers, original commit, blob hash, whole-file SHA256, exact AST-call hash, source link, separate dependency profile links and a clear missing-runtime-evidence warning. These pre-existing public projects were researched earlier and are **not a blind holdout**.

The builder never imports outside application code; fetching a pinned source file over HTTPS and parsing Python AST is not running that app. A declared lower/upper dependency bound does not prove the release actually installed or exposed in production. An omitted keyword does not automatically prove the runtime's configured default.

## Human-review workflow

We also implemented [Phase 3E review intake](../src/falsum/phase3e_review_intake.py). It accepts a SHA-bound bundle and structured reviewer claims that reference a public GitHub issue comment. This supports visible reviewer feedback and conflict reporting, but **does not trust self-attestation as independent security expertise**. A GitHub URL, username and comment are claims until cross-checked. Every intake report has exactly **zero automatically accepted labels**, regardless of the number of self-reported reviewers.

A reviewer should:

1. Open a pinned code/source link and confirm exact commit, line and argument.
2. Inspect the corresponding dependency declaration, distinguishing optional/alternative environments from the actual installed package.
3. Say whether the installed vulnerable version, actual route invocation, attacker-controlled data flow and symlink filesystem state are proven, unknown or contradicted. Do not use a "safe"/"vulnerable" verdict beyond the available evidence.
4. Provide an explanation and choose candidate A, B or **ABSTAIN**, with a public evidence link. Disagreement with another reviewer is useful data and must not be silently resolved in training.
5. Submit a public review through the [review issue form](../.github/ISSUE_TEMPLATE/falsum-security-review.yml). **Do not disclose confidential code or security findings** publicly. Use a private disclosure process if sensitive real vulnerabilities are discovered.

For a machine-readable review input, use the blank \`BLANK-INDEPENDENT-REVIEW-CLAIMS.json\` in the Phase 3E CI artifact. A new review's \`packet_bundle_sha256\` must match the exact review packet artifact; each record includes its original call-site source Git blob and issue-comment URL. The CLI will reject an owner self-attesting as independent, duplicate reviewer records for the same packet, rewritten source hashes or malformed data. No one needs to run a security exploit to review the material.

## Replication

From this repository with Python 3.11+ and HTTPS access to the approved pinned public GitHub sources:

~~~bash
PYTHONPATH=src python -m falsum.phase3e_review_packets \
  --sources-contract data/phase3a-external-source-cases.json \
  --dependency-contract data/phase3a-dependency-manifests.json \
  --out /tmp/falsum-review-queue.json
~~~

It re-downloads and verifies the original application and manifest Git blobs **before** issuing any reviewer packets.

For an external review file matching the bundle SHA:

~~~bash
PYTHONPATH=src python -m falsum.phase3e_review_intake \
  --packets /tmp/falsum-review-queue.json \
  --reviews /tmp/review-claims.json \
  --out /tmp/falsum-review-intake-unverified.json
~~~

The intake report remains unverified and non-eligible until real independent validation occurs. This CLI does not perform remote public-comment author checks and does not authenticate expert status. **A program cannot grant independence or expertise merely from self-reported strings.**

[CI and actual evidence for Phase 3E](../.github/workflows/phase3e-independent-review.yml) include adversarial source hash, prompt identity, source-version ambiguity, duplicate-reviewer, fabricated-expert-label and network-promotion tests. The CI artifact holds the generated five-question queue, blank review input with its correct SHA and the zero-label intake report.

## Competition plan and hard boundaries

Winning is the objective, but the evidence needs to survive judge reproduction. Our next material goal is to obtain **genuine outside security reviewers** who verify the source facts and identify ambiguous cases, then expand beyond this one aiohttp vulnerability into additional source families **without using those validation cases for training**.

Model quality is still blocked: 0/2 real Phase 3D context reversals. We should collect real reviewer-adjudicated pairs for training and reserve distinct unseen repositories/versions for an independent evaluation, then rerun the same official ModernBERT Foundation scoring experiment. This prevents leakage, false-positive rates masked by easy self-authored examples, and incorrect claims about unseen generalization.

The source-review pipeline produces **zero accepted Telegraph/Anjoman evaluation rows, zero independent confirmed expert labels, zero verified application exploits and zero registered evaluators** today. The new package remains a quarantined research checkpoint. Nothing is being auto-submitted, registered, sold or represented as network-eligible.
