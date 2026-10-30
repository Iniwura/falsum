# Phase 2P — Remediation-withheld source challenges and tokenizer gate

**Scope:** Build testable, public-source security-review inputs without giving the scoring model the security-fix diff or the advisory's answer. This is an engineering proof, **not** verified human ground truth, a sealed holdout, or a network evaluator.

## Why this differs from simply showing a security patch

A model shown a public security fix, regression test and GHSA can recite the patch without understanding the vulnerable pre-fix code. That creates a shortcut and invalidates a claimed security-review result. Likewise, a post-fix file cannot be automatically treated as entirely safe.

FALSUM now generates a **separate model-facing question** from the real *parent* source revision only, and withholds the fix, regression test and advisory references from that question.

The code is PUBLIC and can be traced back to the fix using an external search or the provenance artifact; **this is NOT a secretly held-out benchmark**. No scored preferences have been added.

## What is actually verified

1. [Real source queue](../data/real-fix-queue.json) pins a complete parent and fix commit SHA and exact code + regression-test Git blob identities for Requests, aiohttp and Jinja2.
2. [Real fix evidence builder](../src/falsum/real_fix_corpus.py) retrieves upstream immutable commit metadata and code/test diff hunks. [Exact replay](../src/falsum/real_fix_replay.py) reconstructs all 6 parent-to-fix file transitions byte-for-byte, refusing unknown drift.
3. [Pre-fix challenge generator](../src/falsum/pre_fix_challenges.py) selects only existing **parent** file lines aligned with every modified source hunk, merges overlapping windows and refuses an overlong window rather than silently dropping the security-relevant lines.
4. **Model-only artifact:** The generated prompt manifest has only an opaque challenge ID plus original source excerpt. No project identity, advisory/CVE, patch diff, repaired code, source test, source URL, draft label, or preferred answer is put into the model input. It is explicitly marked unlabelled, public, unreviewed, not eligible, and not a sealed holdout.
5. **Separate provenance artifact:** The SHA-256 of the public prompt manifest binds it to source-project identities, parent SHA, post-fix revision, file blob hashes, source line ranges, advisory URL, and remediation/test patch checksums. This metadata is useful to an external reviewer, but **must not** be passed to the model as part of the question.
6. [ModernBERT token budget auditor](../src/falsum/prompt_token_budget.py) runs a real tokenizer from the same public base architecture, using the exact FALSUM V2 Task/Answer render template. The hard limit is 512 tokens. The static task allotment is **384**, keeping **124** for an answer and **4** as token-boundary safety. Over-budget tasks **fail**; they are never truncated behind the scenes. At live inference, the scorer still has to check each fully rendered question and answer.
7. CI uses **separate artifact upload paths**: only prompt questions and capacity report in the model-question artifact; security fixes, advisory links and exact-provenance report stay in a distinct source-evidence artifact.

Important nuance: Passing the task token budget is *not* proof that all future answers will fit, that official V2 tokenizer conformance vectors passed in this job, or that any scorer made accurate decisions. The original quarantined training run did verify the official 88 tokenizer vectors separately.

## Reproduce

Python 3.11+ and outbound access to publicly pinned GitHub revisions are required.

~~~bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_pre_fix_challenges.py' -v
PYTHONPATH=src python -m unittest discover -s tests -p 'test_prompt_token_budget.py' -v
PYTHONPATH=src python -m falsum.real_fix_corpus \
  --queue data/real-fix-queue.json \
  --out /tmp/falsum-sources.json \
  --reviewer-out /tmp/falsum-evidence-questions.json
PYTHONPATH=src python -m falsum.pre_fix_challenges \
  --evidence /tmp/falsum-sources.json \
  --public-out /tmp/falsum-pre-fix-prompts.json \
  --provenance-out /tmp/falsum-prompt-provenance.json
python -m pip install transformers==4.57.1
PYTHONPATH=src python -m falsum.prompt_token_budget \
  --prompts /tmp/falsum-pre-fix-prompts.json \
  --out /tmp/falsum-token-budget.json
~~~

The [research-only real-fix CI](../.github/workflows/real-fix-evidence.yml) runs all checks. Any malformed original, changed Git blob, modified hunk, unexpected answer metadata, synthetic promotion, or token-cap overflow fails the relevant stage.

## Verified run, 30 October 2026

[GitHub Actions run 41130342976](https://github.com/Iniwura/falsum/actions/runs/41130342976) completed successfully after a first real tokenizer audit correctly rejected an oversized question. The generator was tightened to omit redundant line-number prefixes and unnecessary context rather than silently truncate a candidate.

- **5 real pre-fix questions** extracted from the three source-verified projects.
- **5/5 within the static token budget**, with a maximum of **286 rendered task-template tokens** against the 384-token allowance.
- Each question reserves **124 answer tokens plus 4 tokens of boundary safety** under the 512-token cap.
- **0 human-reviewed cases, 0 approved training labels and 0 eligible/network claims**.
- The [questions-only artifact](https://github.com/Iniwura/falsum/actions/runs/41130342976/artifacts/13011519997) and [full public-source provenance artifact](https://github.com/Iniwura/falsum/actions/runs/41130342976/artifacts/13013425056) were uploaded separately. Neither should be treated as a secret evaluation holdout.

This is a capacity and provenance achievement, not evidence that the model can recognize the vulnerabilities or even that the complete answer fits before a separate full-render check.

## Still required before training or registration

- A genuine external AppSec reviewer must establish independent case-specific security truth and realistic deployment preconditions. *Zero have been accepted so far.*
- Lock multiple independent repositories and vulnerability families into disjoint training and holdout sets. Three projects are insufficient for credible generalization.
- Candidate answers must be independently written and reviewed; plausible-but-wrong negative answers cannot be fabricated as verified.
- Never reuse public, developer-tuned tasks as a sealed test.
- Measure actual context-sensitive scorer performance only on appropriate, approved material before ONNX/WASM and network validation.

**No eligibility, evaluator accuracy, independent review, bounty acceptance or network registration is implied by this phase.**
