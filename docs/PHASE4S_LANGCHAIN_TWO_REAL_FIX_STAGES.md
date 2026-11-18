# Phase 4S — Actual LangChain source-pinned two-stage security regression

**FALSUM · Telegraph H2 Evaluators · SECURITY_REVIEW_GENERAL · November 18, 2026**

**Scope:** Re-run the *actual upstream Python unit tests*, not just inspect the source or simulate a simplified path checker. This extends the open-ended [Phase 4P](PHASE4P_OPEN_RESPONSE_SOURCE_REVIEW.md) LangChain Core case after its [Phase 4Q AI source critique](PHASE4Q_AI_ADVERSARIAL_SOURCE_REVIEW.md).

[Executable CI](../.github/workflows/phase4s-langchain-two-stage-runtime.yml) · [Verifier](../src/falsum/phase4s_langchain_upstream_runtime.py) · [adversarial tests](../tests/test_phase4s_langchain_upstream_runtime.py)

## Two deliberately separate historical repair stages

| Stage | Vulnerable parent | Fixed commit | New upstream regression |
|---|---|---|---|
| Initial absolute/`..` path restriction | `7563fceb40ce31165524f3f57ec65e487c02b1a7` | [`27add913...`](https://github.com/langchain-ai/langchain/commit/27add913474e01e33bededf4096151130ba0d47c) | `test_load_template_rejects_absolute_path` and `test_load_template_rejects_traversal` |
| Follow-up symlink target suffix | `c9f51aef85e02fbaadcd5c6c37cf4ef01a49f86e` | [`0b5f2c08...`](https://github.com/langchain-ai/langchain/commit/0b5f2c08ee256473e368372a803c5c92039c0a4e) | `test_symlink_txt_to_py_is_blocked` |

The commits are not described as an uninterrupted adjacent two-commit history. The Phase 4P source-lock separately pins each fixed commit's direct parent and verifies that the relevant source and test files entering the later stage retain the prior stage's fixed blob values.

## Executable counterfactual method

Each stage gets a fresh **sparse Git checkout of the exact historical SHA** (not moving `main` or latest installed package) for the parent and fixed revision. Pytest imports the corresponding local `libs/core/langchain_core` source. The parent and fixed source and test files are checked against the Phase 4P immutable Git blob hashes.

1. Run the original upstream `test_loading_from_yaml` on the vulnerable parent, verifying legitimate file loading still works.
2. Copy the exact upstream regression **test file**, not its new source implementation, from the fixed revision to the parent; the parent keeps its original source Git blob.
3. Execute the new upstream security tests on the parent. Accept a failure only if the named upstream test makes it as far as **a missing expected `ValueError`**, not because a dependency is missing or the runner crashes.
4. Execute the same immutable test file and targeted security tests against the fixed source and require **PASS**.
5. Record all exact Git parent/commit, source/test blob hashes, process exit statuses and raw test-log SHA-256 digests. Missing, changed, skipped, inconclusive or false failures veto the result.

The CI intentionally selects `test_symlink_txt_to_py_is_blocked` for the follow-up. It does **not** run the separate Jinja demonstration that executes a payload. The safe `.py`-suffix target test establishes the path-resolution branch sufficiently for this bounded review question.

## The technical claim we can and cannot make

An independently rerunnable real upstream regression shows the intended path-validation behavior changed between historical source revisions. It does not establish that every symlink escape is closed, that a real application loads hostile prompt configurations, that attackers can write symlinks, that an untrusted user can obtain a local secret, or that the full LangChain upstream test suite was executed. The original patch's explicit `allow_dangerous_paths=True` opt-in remains a trust-dependent override.

A passing runtime test is **not** independent AppSec expert review, a hidden secure benchmark label, a trained evaluator accuracy gain, a Telegraph registered scoring adapter, a new Anjoman Eligible pair, a real deployment exploit or formal bounty acceptance. The original 20 Eligible contributor rows are unaffected.

A real counterfactual should strengthen the **source-level auditability** of FALSUM's evaluation material and help downstream developers verify relevant fix branches without needing the vulnerable project deployed in production. It cannot substitute for a reviewer independently assessing applicability and impact.

**Outcome field intentionally left unasserted until real CI completes.** If the upstream tests cannot run under a pinned environment, the workflow is red and this case remains provenance-only. Do not manufacture a success record.

No video, public new data submission, signature or private user action is required for this experiment.
