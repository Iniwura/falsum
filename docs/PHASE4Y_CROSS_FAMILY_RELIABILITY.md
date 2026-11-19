# Phase 4Y — Cross-family replay beyond the four public source witnesses

**Telegraph Season II · Evaluators · `SECURITY_REVIEW_GENERAL` · November 19, 2026**

**Scope: actual installed-library replay of two *previously researched* security families. This is NOT a new blind holdout.**

[Executable four-matrix-job workflow](../.github/workflows/phase4y-cross-family-replay.yml) · [Strict cross-family source checker](../src/falsum/phase4y_cross_family_replay.py) · [Adversarial regression tests](../tests/test_phase4y_cross_family_replay.py) · [Four already authenticated upstream test witnesses](../evidence/phase4u-2026-11-18-permanent-four-executed-source-witness-index.json).

## What the new replay actually measures

The original FALSUM public source-witness process validates **four historical patches in three projects**: Koa, Hono, and two separate LangChain Core repair stages. That checker is intentionally *not* allowed to trust unrelated source cases without new provenance.

Phase 4Y reuses two earlier research families **outside those four cases** and executes their original historical library functions again in four separate fresh GitHub-hosted Python installations. The runtime runners existed since Phase 3H/3I; this phase puts them behind a combined fail-closed comparison and publishes one auditable proof.

| Distinct other project | Installed affected/fixed releases | In-process actual historical behavior | Unchanged controls |
| --- | --- | --- | --- |
| [Starlette](PHASE3H.md) | 0.26.1 / 0.27.0 | Same-prefix external sibling file is accessible / blocked by actual `StaticFiles.get_response` | Three expected unaffected directory/path cases |
| [Requests](PHASE3I.md) | 2.30.0 / 2.31.0 | Synthetic HTTPS proxy credentials appear / no longer appear in `Session.rebuild_proxies`'s rebuilt request headers | Four unchanged request/proxy conditions |

Both conditions are bounded synthetic test inputs. The Requests replay **does not perform an HTTP redirect or send credentials**. The Starlette replay accesses only synthetic temporary files. Neither runs customer code or proves a production exploit.

### Reproduction

The authoritative new execution is the [Phase 4Y GitHub Actions workflow](../.github/workflows/phase4y-cross-family-replay.yml), once a green run exists. Its four matrix jobs:
1. Install and check the **exact** affected/fixed package version in a separate runner job, retaining `pip freeze`.
2. Call the **actual installed upstream library method** on the small hardcoded benign fixture. Check published upstream source/test pins already verified by the Phase 3H/3I runners.
3. Upload the bounded JSON observation. A final job runs `phase4y_cross_family_replay` against the four reports, the immutable source/test queues, and the existing authentic four-stage index.
4. Fail if the expected source-bound behavioral reversal, any unchanged negative control, package identity, source hash or provenance assertion differs. Upload one combined report with SHA-256 digests of all four input reports.

You can reproduce the schema/tamper checks locally without installing historical dependencies:

```bash
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_phase3h_starlette_runtime.py' -v
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_phase3i_requests_runtime.py' -v
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_phase4y_cross_family_replay.py' -v
```

**A schema-valid manually constructed report is not proof of an installed execution.** Trust comes from the actual reproducible GitHub Actions run logs, package installs, and resulting file identities, never the JSON itself. A failing/missing final Actions job means this Phase 4Y replay has **not** been validated.

## How to describe this evidence accurately

If real CI finishes green, it validates **six distinct historical security behavior boundaries across five public projects**, **but across two different execution methods**: four upstream author-written parent-fail/fix-pass tests, plus two direct historical library-method comparisons. The latter are distinct projects yet were already examined earlier in FALSUM's development. This is **breadth of real bounded execution evidence**, not proof that a learned or semantic evaluator generalizes.

Do **not** report this as six independent reviewer gold labels, six blind evaluation cases, a six-case neural-model accuracy score, six accepted Anjoman rows, a new Telegraph adapter, or a set of six equivalent upstream security regression executions. The original source-witness checker remains limited to four exact upstream-authored regression witnesses. Its safe ABSTAIN for any unregistered case is desirable but is **not** a successful security verdict on that case.

| Evidence metric | Exact interpretation |
| --- | --- |
| Four previous source-test witnesses | Previously authenticated, untouched |
| Two additional out-of-four execution families | Starlette and Requests, both previously studied |
| Independent human AppSec assessments verified | **0** until genuine external reviewers produce checkable findings |
| Genuinely new, pre-registered unseen projects tested with current assessor | **0** |
| New source cases recognized by the existing typed witness checker | **0**, until new case admission/provenance support exists |
| Original quarantined LoRA improvement | **Not demonstrated** |
| Official Season II submission | **Not completed** |

## The next, genuinely new-case reliability experiment

A stronger Evaluators-track claim requires a preregistered **source-project-disjoint challenge**. Apply these gates before reporting any generalization rate:

1. **Freeze the evaluator and case-selection policy before seeing the challenge cases.** An unrelated reviewer supplies at least two historical security repairs from projects not in the Phase 4U source index or the previous FALSUM research corpus. Preserve the reviewer choice time and code version. Public historical code is fine; do not claim it is confidential or unknown to a pretrained model.
2. **Authenticate the actual upstream source and test.** Pin the direct affected/fixed Git commits and original test/source Git blobs. Run the real upstream regression as an unchanged original-control PASS, vulnerable-source fixed-test FAIL for the expected assertion, and fixed-source same-test PASS. Reject skipped/broken/setup failures. Preserve full CI logs and immutable receipts.
3. **Precommit the decision task, baseline and grading.** Ask the unchanged evaluator to issue source-specific supported/contradicted/abstained judgments on each new case. The current four-case gate will deliberately ABSTAIN until new trusted evidence is admitted, so report *coverage separately from correctness on attempted cases*; never turn ABSTAIN into an accuracy win. Record false-supported, false-contradicted, missing evidence, and inability to assess.
4. **Get independent source-level adjudication.** The actual reviewer reads parent/fixed upstream code and the upstream-authored test before seeing FALSUM's answer. They independently report what is supported and what remains unknown, with conflict-of-interest/tooling disclosures. Preserve disagreements and abstentions. At least one verified external expert review is meaningful evidence; a GitHub issue or self-review alone is not.

Only once those conditions are met can FALSUM publish a credible *new-case* reliability score with numerator, denominator, failures, uncertainty and proper baselines. Do not quietly repurpose Starlette or Requests as fresh holdouts: their earlier analysis is public and already shaped this project.

**Independent reviewer entry:** [choose one actually executed original upstream fix](REVIEW_FOUR_EXECUTED_CASES.md) or [critique it through the open request](https://github.com/Iniwura/falsum/issues/25). No wallet, paid API, secrets or private customer vulnerabilities required. The demo and official H2 entry are deliberately held for the operator.
