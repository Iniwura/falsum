# Phase 3Q — Executable Mission Evidence Lab

**Purpose:** An independently runnable, attractive **public-safe** demonstration of why evidence-aware security evaluation matters for realistic pull requests across three *fictional* business workflows. It adds a genuine code execution result, not just another simulated "claim" catalog or an unsupported AI-model quality statistic.

## Run the demo

Only Python 3.11+ and the checked-out FALSUM repository are required:

```bash
git clone https://github.com/Iniwura/falsum
cd falsum
PYTHONPATH=src python -m falsum.phase3q_mission_lab --out-dir phase3q-demo
```

Open `phase3q-demo/index.html` in any local browser. This is a **self-contained, responsive, dark-mode evidence browser** with three selectable mission scenarios, a before/after result, reproduced state, intact legitimate control, source function SHA256 identity and an explicit unknown-evidence outcome.

For the exact machine-readable results, open `phase3q-demo/ACTUAL-SYNTHETIC-RUNTIME-PROOF.json`. The CLI will refuse to overwrite a previous output directory. To rerun, choose a fresh output directory. The [Phase 3Q GitHub Action](../.github/workflows/phase3q-mission-evidence-lab.yml) reruns everything on Python 3.11, 3.12 and 3.13 and saves the generated real-output HTML/JSON as a downloadable CI artifact.

## What the Python interpreter actually executes

| Fictional mission scenario | Pre-fix local behavior | Patched local behavior | Legitimate control |
| --- | --- | --- | --- |
| **Exchange** — withdrawal gateway / caller identity | Actor B can decrement actor A's integer account balance without matching the owner parameter | The mismatched actor is refused; balance stays unchanged | Authenticated actor A can debit A's own fictional balance in both |
| **Model Economy** — task completion callback | The in-memory completion webhook accepts a synthetic payload even with a deliberately wrong HMAC | The HMAC must match the exact bytes before event processing | A correctly signed synthetic callback is accepted in both |
| **Web3 Native & DeFi** — off-chain event relayer | Delivering the same synthetic event ID twice credits a fictional ledger twice | A second delivery of that event is ignored | Two distinct event IDs are accepted and credited in both |

The actual functions are in [`src/falsum/phase3q_mission_lab.py`](../src/falsum/phase3q_mission_lab.py). Each is run with a fresh in-memory fixture. The module **fails closed** if its real Python output deviates from expected conditions, before generating the report.

**Observed synthetic outcomes:** 3 unwanted actions reproduced before, 3 blocked after, 3 legitimate positive controls preserved. Three missing-evidence hypotheticals are explicitly reported **INSUFFICIENT_EVIDENCE**, never silently "safe". Actual source fingerprints are computed from `inspect.getsource` for before/after code. Every on-screen outcome is generated from real execution, not hardcoded front-end animations.

## Security and competition boundaries

- **No actual Exchange, Model Economy or DeFi third-party mission app was run, integrated or verified.** These are functional fictional examples inspired by possible workflows.
- **No deployed service, real customer, funds, signing key, third-party endpoint or blockchain is touched.** The webhook uses a disposable, clearly synthetic in-process HMAC secret. The DeFi fixture represents an off-chain relayer, not real smart contract or chain evidence.
- The before/after assertions are intentionally simple and controlled. They do **not** demonstrate new LoRA accuracy, released model quality, independent AppSec adjudication, production exploitability, or previously unseen benchmark generalization.
- No actual hidden Anjoman evaluation questions/answers, wallet identity, row hashes or signed payloads are included. **Public evidence is independent of the 20 eligible private contribution rows.**
- The HTML has no external fonts, images, libraries, network calls or analytics. It is keyboard-accessible, responsive, respects reduced motion and uses a restrictive Content Security Policy.

## Judges: reproduce the negative case too

Run the targeted suite:

```bash
PYTHONPATH=src:tests python -m unittest discover -s tests -p test_phase3q_mission_lab.py -v
```

It verifies all three actual before/after side effects (including safe controls), invalid replay/input variants and strict no-overclaim invariants. A test also injects a mutated fixture that falsely claims to be patched; the report must **raise an error** rather than publish a positive result.

This is an **evidence-collection and source-boundary test**, not a validated evaluator adapter.

## What this changes for the winning strategy

Judges can now open a concrete offline product, select one of three mission-inspired scenarios, inspect the exact measured before/after outcomes and reproduce them via one CLI command. That is materially stronger than a screenshot of a README. The real FALSUM network contribution remains the 20 `SECURITY_REVIEW_GENERAL` **eligible rows** verified through the contributor UI and [bounty claim](https://github.com/telegraphprotocol/bounties/issues/96#issuecomment-6588168396); the maintainer's decision is still separate.

This lab does **not** establish independent real-world mission adoption. To compete strongly in H2, follow with external developer use on genuine public PRs, expert case adjudication, real independent mission workflow checks, an honest video and the **separate final hackathon submission**. Do not promote either quarantined LoRA.
