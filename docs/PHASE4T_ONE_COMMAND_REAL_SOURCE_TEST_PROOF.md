# FALSUM | Four real security-regression proofs

**Telegraph Season II · Evaluators · `SECURITY_REVIEW_GENERAL`**

FALSUM tests whether a security verdict follows **observed code behavior**, rather than a confident but unsupported explanation. These are four authentic upstream fixes across three public repositories. Unlike fictional PRs or author-preferred A/B responses, each case includes the actual upstream project's source, original tests, new security regression and a direct parent/fix counterfactual.

**Verification statement:** The original upstream tests passed. The real new security regression from the fixed revision failed on the original implementation with its expected security assertion. The identical new regression passed on the fixed implementation. This claim is scoped to the four named, historical test executions below.

## One-screen judge evidence

| Project | Security check | Historical commits | Genuine executed test |
|---|---|---|---|
| Koa | Reject protocol-relative `Referer` redirect bypass | [parent](https://github.com/koajs/koa/commit/433b20c9e5954113e8d7a23a25e9d5bb750c3034) / [fix](https://github.com/koajs/koa/commit/769fd75cc6b30d72493b370b5a3ae2332ca03c5b) | Upstream `should fix Trailing Double-Slash security issue` |
| Hono | Check cross-origin `text/ping` using CSRF middleware | [parent](https://github.com/honojs/hono/commit/d88fab372415277a9e540e895650943dd08eef4a) / [fix](https://github.com/honojs/hono/commit/bf16471913b5199212dac33f5d170f94745dd26a) | Upstream `hyperlink auditing` regression group |
| LangChain Core, initial | Default `template_path` absolute and `..` traversal validation | [parent](https://github.com/langchain-ai/langchain/commit/7563fceb40ce31165524f3f57ec65e487c02b1a7) / [fix](https://github.com/langchain-ai/langchain/commit/27add913474e01e33bededf4096151130ba0d47c) | Upstream `test_load_template_rejects_absolute_path` and `test_load_template_rejects_traversal` |
| LangChain Core, follow-up | Detect `.txt` symlink to a disallowed suffix via `resolve()` | [parent](https://github.com/langchain-ai/langchain/commit/c9f51aef85e02fbaadcd5c6c37cf4ef01a49f86e) / [fix](https://github.com/langchain-ai/langchain/commit/0b5f2c08ee256473e368372a803c5c92039c0a4e) | Upstream `test_symlink_txt_to_py_is_blocked` |

**Actual upstream CI:** [Koa + Hono](https://github.com/Iniwura/falsum/actions/runs/44352329150) · [LangChain initial + follow-up](https://github.com/Iniwura/falsum/actions/runs/44353999011). Original packages and their own test suites were executed in reproducible GitHub Actions jobs. All historical Git identities and the four source/test file SHA-1 blob values per patch stage were checked. The readable source-bound AI critique and deployment limitations are [here](PHASE4Q_AI_ADVERSARIAL_SOURCE_REVIEW.md).

## One independent source-proof index

The new [Phase 4T indexer](../src/falsum/phase4t_four_stage_evidence.py) ties the four artifacts into **one report** rather than cherry-picking a screenshot of a passed test.

- [Frozen four-artifact manifest](../data/phase4t-four-run-receipt-lock.json) fixes the exact GitHub Actions run IDs, workflow/head commit SHAs and source-stage identities.
- [Source lock](../data/phase4p-three-project-open-review-lock.json) fixes all three repo identities, four exact fixes, four direct parent SHAs, source paths and test file Git blob hashes.
- [Phase 4T GitHub Actions](../.github/workflows/phase4t-github-execution-proof.yml) retrieves the original **immutable GitHub Actions artifacts**, checks the source workflows really completed successfully on their pinned commits, verifies parent/fixed source and **the original upstream regression test identity**, confirms all four real process exit statuses and the three original process-log digests per case, and emits one small public JSON index. Tests reject forged gold labels, mismatched blobs, fabricated successes, wrong workflows and unverified source identities.
- The index lists **3 repositories, 4 distinct historical patch stages, 6 open-ended review questions**, with pointers to every original source and real test. The two LangChain patch stages are not misleadingly counted as independent projects.

The original Actions artifacts currently have 90-day retention. The permanent Git source locks and the re-runnable code remain in this repository. Re-run the original [Phase 4R workflow](../.github/workflows/phase4r-real-upstream-regression.yml) and [Phase 4S workflow](../.github/workflows/phase4s-langchain-two-stage-runtime.yml) if those historical artifacts expire; then version a **new** provenance index with the new actual run identifiers. Do not quietly replace old receipts or pretend the original run IDs remain retrievable forever.

### Reproduce the four-receipt audit

From a FALSUM clone, the self-contained synthetic attack tests require only Python:

```bash
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_phase4t_four_stage_evidence.py' -v
```

To independently validate the **real** GitHub Actions artifacts, inspect and run [Phase 4T](../.github/workflows/phase4t-github-execution-proof.yml). The workflow downloads the exact four public source-test artifacts through GitHub's authenticated read-only Actions interface (no Telegraph account, wallet or paid API), compares them with the frozen source manifest, and writes a compact standalone proof. This is what verifies *actual runtime execution*; the synthetic unit tests above do **not** substitute for that real job.

## Actual scope and remaining winning-quality gaps

**What this establishes:** genuine cross-project evaluation coverage based on real historical fixes, including four independently replayable **before/after security regression witnesses**. An evaluator can now be tested for recognizing that a particular code state supports or contradicts a specific test-based security assertion.

**What it does not establish:** a new general semantic evaluator, a trained/registered scoring adapter, improved LoRA performance, independent human AppSec gold labels, a new genuine blind model holdout, production vulnerability exploitation, independently verified adoption, or maintainer acceptance. The previous LoRA remains quarantined: genuine Foundation scoring yielded only **5/8** researcher-source matches and **1/4** complete source-sensitive reversals versus a constant-choice control of **4/8**. FALSUM does not turn four deterministic source-test outcomes into 100% ML accuracy.

The user's **20 Eligible Anjoman preference rows**, verified under the correct Privy Wallet on November 18, are a **separate real network material contribution**. The upstream execution index does not create, upload, substitute for or certify those hidden pairs. Nothing here claims an external qualified human reviewed the four source diagnoses.

**Remaining requirements before official entry:** full regression/audit and all user-facing proof links green; real independent reviewer assessments if available; official H2 registration/star and 2–5 minute authentic demo when the operator authorizes it; three authentic published progress update links if required for growth points; final hackathon entry and receipt. The hackathon’s official deadline is **December 1, 2026 at 23:59 UTC**. The internal **November 22** goal never overrides technical correctness. No video work is performed in this phase.
