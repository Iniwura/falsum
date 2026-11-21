# FALSUM: five-minute judge reproduction

**Telegraph Season II / Evaluators / SECURITY_REVIEW_GENERAL / November 21, 2026**

This is an accessible text walkthrough and reproduction path, **not a claim that a required final demo video was recorded, that judges have accepted this as the video-equivalent, or that FALSUM is registered as a new network evaluator**.

## Step 1 — Try the real public verifier (about one minute)

Open https://falsum-evidence-lab.vercel.app/witness/ .

Choose any of Koa's redirect, Hono's CSRF, two LangChain path conditions, or Flask's session-cookie Vary header. Inspect the named public upstream commit and its regression test. Switch between vulnerable source and fixed source.

Make a narrow source-test claim. When the authenticated regression passed at the selected source commit, the source-witness verdict is SUPPORTED; when it failed, CONTRADICTED. Enter an incorrect execution receipt hash and the checker abstains. Claims about deployed production exploitation and universal application safety also abstain. The current workbench contains five historical upstream repair stages in four original projects; its 80 constructed verdicts are not 80 independent security audits.

## Step 2 — Reproduce the deterministic source-witness tool (about one minute)

On a computer with Python 3.11+:

~~~bash
git clone https://github.com/Iniwura/falsum.git
cd falsum
python -m pip install --no-deps -e .
falsum verify-source-review \
  --index evidence/phase4u-2026-11-18-permanent-four-executed-source-witness-index.json \
  --source-lock data/phase4p-three-project-open-review-lock.json \
  --requests examples/source-review-witness-claims.json \
  --out judge-source-review.json
~~~

Expected structured report: 2 SUPPORTED, 2 CONTRADICTED and 3 ABSTAIN for the supplied sample claims. This is an original source-identity and archived-execution claim checker, not a neural language model and not an arbitrary prompt safety guarantee.

## Step 3 — Try the original raw-code evaluator material (about one minute)

~~~bash
falsum score-raw-code export \
  --questions-out raw-code-questions.json \
  --template-out candidate-responses.json
~~~

Requires public internet for pinned Git source retrieval, no payment, model account or API key. The command downloads the **full historical source files** from four upstream projects at eight exact Git commits, checks every Git blob SHA-1 against the preregistered reference, then exports 12 A/B/ABSTAIN choices, including four cases with deliberately absent code.

Open raw-code-questions.json. The model input includes real code excerpts, the same neutral question on each pair and an explicit no-source condition. Fill every null choice in candidate-responses.json with the answer your own method actually chooses. Then run:

~~~bash
falsum score-raw-code score \
  --questions raw-code-questions.json \
  --predictions candidate-responses.json \
  --out candidate-report.json
~~~

The score measures per-class matches, complete parent/fix reversals, unsupported confidence and code-present abstention. A tampered challenge hash, extra label or incomplete response fails closed. A constant code answer with no-source ABSTAIN already gets 8/12, so high raw agreement alone is not source reasoning.

## Step 4 — Inspect authentic negative model evidence (about one minute)

Read the source-and-model original [Phase 5P GitHub Actions run](https://github.com/Iniwura/falsum/actions/runs/44852933182) and its archived original model artifact. Qwen/Qwen2.5-0.5B-Instruct ran genuine CPU inference against all twelve authenticated raw-code prompts. All outputs were ABSTAIN. That means **4/12** public author-reference matches, **0/4** correct source reversals, **4/4** correct no-code abstentions and **8/8** unnecessary code-present abstentions.

The original model source and safetensors revisions are pinned; the ZIP contents have [per-file SHA-256 evidence](../evidence/phase5p-2026-11-21-authenticated-raw-code-negative.json). The original Telegraph Foundation LoRA historical experiment was negative and its old checkpoint is unavailable. We do not describe the published external Qwen checkpoint as a new FALSUM-trained evaluator or independent developer adoption.

## Step 5 — Judge its relationship to Telegraph

FALSUM develops public reproducible **evaluation material** for the SECURITY_REVIEW_GENERAL Intent. Its historical Anjoman record showed 20/20 Eligible rows for one verified public wallet address, but final acceptance, registered scoring improvement and current rows are not asserted. The earlier [read-only wallet evidence](https://github.com/Iniwura/falsum/actions/runs/44311491808) is separate from source evidence.

The working contribution is evidence-conditioned evaluation material, a deterministic claim checker, reproducible source-change tasks and a failure-reporting pipeline. It does **not** independently prove a ranking improvement on Telegraph, licensed qualified security expert labels, outside adoption or a production exploit.

**Reviewer counterexample welcome:** Find an incorrect public researcher reference, an alternate metadata shortcut, an uncovered source ambiguity, or a genuine external evaluator whose predictions differ. Preserve original model output and input provenance, including negative results. Use the [independent review discussion](https://github.com/Iniwura/falsum/issues/25). Owner-authored comments and internal bot exercises are not independent reviews.

## Current release and entry distinction

The source workbench has its own [latest main live-HTTPS freshness gate](https://github.com/Iniwura/falsum/actions/workflows/phase5e-live-production-source-freshness.yml). Phase 5P raw-code material is a **CLI/CI contribution**, not yet a deployed browser-time scorer.

The official Season II entry remains unsubmitted. The official final deadline is December 1, 2026 at 23:59 UTC. The project still needs the mandatory bounties GitHub star ownership evidence, final judge form, showcase permissions and an approved 2–5 minute video or organizer-accepted equivalent. Do not invent these receipts.
