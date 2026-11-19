# Phase 5C — Fifth independently replayable source-test witness

**FALSUM · Telegraph Season II · Evaluators · SECURITY_REVIEW_GENERAL · November 19, 2026**

## Problem addressed

FALSUM's original Phase 4U source claim checker was deliberately frozen to four authenticated upstream security regressions in Koa, Hono and two LangChain repair stages. Phase 4Z subsequently reproduced a genuine Flask session-cookie Vary regression against original upstream source, but the public checker did not admit it. Claiming that source replays prove new-case evaluator behavior without actually sending a new case through the checker would be misleading.

Phase 5C adds **one strictly provenance-locked new case** to a separate five-witness checker, without modifying the existing four-case source index, existing CLI, recorded LoRA or source material. Flask was chosen by the researcher after the earlier work; it is **not** a blind model holdout, independently supplied human gold label, or arbitrary-prose review.

## Original upstream proof recovered and pinned

The Flask evidence comes from the **actual** [successful Phase 4Z GitHub Actions run](https://github.com/Iniwura/falsum/actions/runs/44524997174), artifact ID **14529512891**, on the previously published upstream source-test workflow. The original ZIP archive was downloaded through GitHub, independently hashed, and checked against GitHub's artifact digest.

| Original proof identity | Fixed value |
| --- | --- |
| Original Actions run | [44524997174](https://github.com/Iniwura/falsum/actions/runs/44524997174) |
| Original artifact | 14529512891, original Phase 4Z Flask source-test proof |
| Verified original ZIP SHA-256 | d2bd64dd1d893bc2367ef5664e119bb484a2db1898c643936a57933c5d3431ef |
| Inside the ZIP, exact original JSON SHA-256 | 65150bc4d196d715386bd758d37ad0b41dc8b2f242bd8628825b3158da15efb5 |
| Original fixed source SHA | 8705dd39c4fa563ea0fe0bf84c85da8fcc98b88d |
| Original direct parent SHA | 9532cba45d2339e90ebf04f178b1e4f2064e7328 |
| Executed security regression | tests/test_basic.py::test_session_refresh_vary |
| Real observed test exits | Original parent baseline 0; new test on parent 1 (expected assertion); new test on fix 0 |

The original ZIP has been preserved byte-for-byte, base64-encoded into [a portable text evidence file](../evidence/phase5c-original-phase4z-github-artifact.zip.b64). Decoding it and recomputing its SHA-256 reproduces GitHub's digest; the precise JSON payload and source/test SHA identities are validated again on every fifth-case check. This is **not** a newly simulated or invented upstream result. A caller cannot substitute their own plausible-looking JSON: the zip hash must match the originally downloaded artifact and the original selection must match Phase 4Z's hard-pinned security fix.

## Developer reproduction

The new checker works **fully offline** with Python 3.11+ and the four existing source receipts:

~~~bash
PYTHONPATH=src python -m falsum.phase5c_fifth_source_witness \
  --index evidence/phase4u-2026-11-18-permanent-four-executed-source-witness-index.json \
  --source-lock data/phase4p-three-project-open-review-lock.json \
  --flask-lock data/phase4z-flask-new-source-lock.json \
  --flask-proof-b64 evidence/phase5c-original-phase4z-github-artifact.zip.b64 \
  --out five-original-source-witness-results.json
~~~

The original four-case command continues to work unchanged. The new command verifies **5 historical source-test repair stages in 4 distinct upstream projects**. Its 40 source-derived constructed controls test: 10 supported claims, 10 contradicted claims, and 20 abstentions for unsupported production/global-security assertions.

For caller-chosen structured review claims, pass --requests PATH (a JSON array using Phase 4U's schema). Both genuine Flask revisions can now be evaluated. But any external "expected" verdict remains an **unverified caller assertion**, not an internally generated reference label. Arbitrary unknown projects, wrong Git revisions, incorrect test blob SHA, forged evidence receipt, or unsupported production claims do not receive source-supported verdicts.

[Implementation](../src/falsum/phase5c_fifth_source_witness.py) · [Adversarial tests](../tests/test_phase5c_fifth_source_witness.py) · [Three-Python CI](../.github/workflows/phase5c-authenticated-fifth-source-witness.yml) · [Original Flask execution process](PHASE4Z_FLASK_NEW_SOURCE_CASE.md).

## Skeptical evaluation, not performance inflation

| What this phase demonstrates | What it does **not** demonstrate |
| --- | --- |
| The original source and regression evidence can admit a fifth original project without rewriting the four previous receipts | An unseen trained-model generalization score |
| The same typed checker accepts true, false and abstain source-test claims for Flask | General natural-language reviewer competence |
| Forged source/test Git blobs and other proof archives cannot be promoted | An independent human AppSec evaluation or expert-certified labels |
| Offline source consistency can be reproduced from exact original GitHub ZIP SHA and source locks | A newly registered Telegraph scorer, new Anjoman Eligible rows or commercial adoption |
| 40 internal regression controls exercise the enlarged source facts | A 100% semantic or ML accuracy claim |

**Current human expert gold: zero. Original LoRA negative evaluation: unchanged. Official H2 entry: not yet filed.** The source project itself was selected by FALSUM's researcher, not external reviewers, and its historical upstream vulnerability does not prove an exposed production Flask application or compromised cache.

The next substantive technical goal remains unfamiliar-case quality measurement against externally adjudicated evidence or new pre-registered counterfactuals with transparent provenance. Preserve the distinction between **a tested historical source fact** and **a general-purpose security evaluator that is measurably better than controls**. No demo or submission was created.
