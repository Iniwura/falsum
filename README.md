# FALSUM

**Every claim stands trial.**

**Current research checkpoint (1 November 2026):** The Phase 2Z pipeline verified three allowlisted example applications against **real pinned aiohttp 3.10.11**, including static-to-runtime route checks and six localhost HTTP requests; 55 focused tests passed. This is evidence-plumbing proof, not CVE exploitation or independently validated real-application vulnerability accuracy. No approved security labels, eligible Anjoman evaluations or live evaluator registrations. See [Phase 2Z](docs/PHASE2Z.md) and the [reward-model generalization postmortem](docs/PHASE2V.md).

An evidence-grounded security evaluation research project for [Telegraph Season II](https://hackathon.telegraphprotocol.com/). FALSUM targets the `SECURITY_REVIEW_GENERAL` child Intent and the `SECURITY_REVIEW` evaluator family, as described by [bounty #96](https://github.com/telegraphprotocol/bounties/issues/96).

**Independent validation:** [FALSUM issue #1](https://github.com/Iniwura/falsum/issues/1) requests genuine AppSec review. A [label-blinded PR reviewer packet](docs/PHASE2N.md) can now be generated with proposed answers stored separately; a [public-question-only Actions artifact](https://github.com/Iniwura/falsum/actions/runs/41127352499) is also available. No independent reviewer approval or network eligibility is implied.

## Phase 2Z: actual patched Python framework runtime evidence

FALSUM's evidence engine now has a real **pinned aiohttp 3.10.11 runtime integration**, not just synthetic Python AST tests. It checks exact tracked source Git blob hashes **before executing** three controlled application fixtures, compares Phase 2Y static call syntax against the actual registered \`aiohttp.web_urldispatcher.StaticResource\` flag, and exercises six ordinary HTTP requests over localhost. Two literal values matched runtime; a variable-controlled value remained appropriately **UNDETERMINED** statically while actual runtime resolved it.

[Actual Phase 2Z run](https://github.com/Iniwura/falsum/actions/runs/41289904581) passed **55/55 focused tests** and all six loopback requests. The historical aiohttp traversal advisory was fixed in 3.9.2; this pilot uses a later **patched** version. There is **no reproduction of that CVE**, no independently sourced external application, no security accuracy score and no confirmed exploit.

[Phase 2Z technical report and local reproduction](docs/PHASE2Z.md) · [Permanent exact execution evidence](evidence/phase2z-2026-11-01.json).

**FALSUM is research-only:** zero independently reviewed AppSec labels, zero accepted Anjoman network rows, and no registered evaluator. The next task is an independently reviewable, consented outside application with a pinned source revision and isolated runtime checks.

## Phase 2Y: framework import bindings and guarded claim reconciliation

The security evidence pipeline now distinguishes **simple framework-backed Python import declarations** from unrelated code that merely shares a vulnerable-looking method name. The [Phase 2Y static binder](src/falsum/phase2y_bindings.py) checks narrow aiohttp Application constructor chains, explicitly imported websockets server call aliases and Tornado RequestHandler subclasses, with SHA-verified source and conservative module/function call-path classification. Shadowed imports, dynamic rebinding, eval/exec, conditional or uninvoked functions abstain instead of pretending actual framework execution is known.

The [binding-aware claim guard](src/falsum/phase2y_claim_guard.py) **recomputes the original application source evidence** before flagging contradictions. In real GitHub Actions tests, an imported aiohttp call with a literal False and opposing developer claim was flagged for review, while a visually identical fake dummy.router.add_static call was **correctly left unresolved**. [Verified Phase 2Y CI](https://github.com/Iniwura/falsum/actions/runs/41289002820) passed **89/89 tests** across new import/call guarding and previous evidence plumbing.

**Static import declarations do not prove actual runtime callee identity or code execution, and no true security-vulnerability accuracy is established.** Zero independent human-reviewed labels, zero accepted Anjoman rows and no registered evaluator. [Complete Phase 2Y technical report](docs/PHASE2Y.md) · [Permanent execution evidence](evidence/phase2y-2026-11-01.json).

## Phase 2X: independently parsed source facts, rather than trusting every claim

FALSUM now has a **Python AST evidence checker** for three narrowly scoped vulnerability preconditions: aiohttp static-route follow_symlinks literals, Tornado set_cookie max_age integer literals and Python websockets explicit compression arguments. The checker validates the **full original application file SHA-256, exact call-site line range and AST node hash**, then re-parses the local source rather than trusting a claimed machine-verification JSON report.

The [new AST reconciler](src/falsum/phase2x_reconcile.py) cross-checks a submitter's unreviewed application evidence **only if it cites the very same hashed file, prerequisite and overlapping call line**. If an excerpt claims follow_symlinks enabled but the actual AST parses follow_symlinks=False, it flags the contradiction for human review. For dynamic values, unresolved aliasing, unknown reachability and other source areas, it **abstains** rather than making up a safe or vulnerable conclusion.

[Phase 2X CI run](https://github.com/Iniwura/falsum/actions/runs/41288248962) passed **49 tests** and proved the contradictory-literal scenario end to end using both actual CLIs. This is valuable syntactic cross-checking, **not verified runtime binding, application-level safety, or exploit accuracy**. Zero independent expert labels, zero accepted network evaluation rows, and no registered evaluator.

[Phase 2X technical documentation and CLI examples](docs/PHASE2X.md) · [Permanent exact experiment evidence](evidence/phase2x-2026-11-01.json)

## Phase 2W: evidence-first, source-bound application precondition checks

The previous LoRA checkpoints failed to generalize security-context judgments, so we built an **application evidence integrity + applicability gate**, rather than repeating the same reward-model training. The new [Phase 2W rulebook](data/phase2w-applicability-rules.json) names **22 explicit required conditions across 11 real Git-pinned upstream security fixes**. A [file-hash and citation verifier](src/falsum/phase2w_proof_gate.py) accepts source-bound app evidence and returns one of four abstention-friendly states: **conditional candidate / contradicted precondition / insufficient evidence / conflicting claims**.

A [real local application capture command](src/falsum/phase2w_capture.py) extracts SHA-256, actual file quotes and exact line ranges from developer-specified code without modifying the app. It rejects altered files, symlinks, escaping paths, forged quotes and unknown conditions. **Matching code bytes is not independent semantic validation**, and the gate does not report confirmed exploits or eligible training labels.

[Successful Phase 2W CI](https://github.com/Iniwura/falsum/actions/runs/41286462954) passed 46 adversarial/isolation/source tests, a 44-case synthetic decision study (11 of each four statuses), a working CLI capture of application file evidence, and reverified 16 authentic Git pre/post source/test transitions; the other three source projects were already checked in [Phase 2U](https://github.com/Iniwura/falsum/actions/runs/41284227213). No real customer application was security-audited.

[Phase 2W methodology and exact CLI usage](docs/PHASE2W.md). **0 human-reviewed findings, 0 real-world exploit confirmations, 0 accepted Anjoman rows and 0 live evaluator registrations.** Next: cautiously derive *machine-observed* facts for narrowly scoped source patterns, rather than trusting an asserted fact because its quote has a valid SHA.

## Phase 2V: custom context-coupled gradient training, no transfer yet

We implemented and ran an **actually different, differentiable training objective** on the real ModernBERT LoRA model. Instead of independently preferring a fixed security answer, the model trains on *both* conflicting deployment contexts for the same original source, plus a contrastive margin and an answer-only penalty. Real PyTorch gradient tests, pinned input adapter, original source/patch replay and complete token limit all passed. [Actual Phase 2V run](https://github.com/Iniwura/falsum/actions/runs/41285552033).

In-sample AI draft agreement changed **4/8 → 6/8** and families matching BOTH contexts **1/4 → 2/4**. **But on three other source-separated projects, transfer stayed 3/6 AI draft choices and 0/3 full-context families**, unchanged from the Phase 2U checkpoint. The experiment learned some already inspected pairs, but no improvement in the diagnostic that matters most. We must not describe this as a successful generalizable security reviewer or an accepted network evaluator.

[Complete Phase 2V report](docs/PHASE2V.md) · [Immutable real model and source evidence summary](evidence/phase2v-2026-11-01.json).

**FALSUM is still research-only: zero independently validated labels, zero accepted Anjoman evaluation rows, no registered live evaluator.** Next work should address label quality and broader independent project diversity before another expensive training run. Neither pretrained checkpoint nor new coupled adapter should be registered based on the present findings.

## Phase 2U: authentic second LoRA trained, but NO security-context transfer

We ran a genuinely **new official Telegraph V2 ModernBERT LoRA** training experiment using 52 pinned GHSA research pairs plus eight AI-authored deployment-context comparisons from four source-verified projects. The upstream data shortcut gate passed (100% unique negatives, 50% length-only accuracy, 41.1% answer-only surface probe). The actual one-epoch trained checkpoint got a **PASS on the trainer's six small synthetic GHSA test pairs**. [Real training CI](https://github.com/Iniwura/falsum/actions/runs/41283929744).

**That did not improve FALSUM's deployment-sensitive reviewing.** On four already inspected, separately sourced PR-review examples the new and original checkpoints both agreed with AI draft preferences 4/8 and reversed the preferred essay correctly across 0/4 opposite-context source families.

To test actual cross-project transfer we acquired **three further untouched-by-training public projects**: Tornado cookie-attribute handling, Undici oversized streaming dump handling and Python websockets decompression limits. Six exact original-to-repair source/test transitions replayed, and all 12 full model inputs fit the real 512-token limit. [New source audit](https://github.com/Iniwura/falsum/actions/runs/41284227213). Both actual LoRA models were then scored, with no new training: original **3/6 provisional choices and 0/3 context families**; new **3/6 and 0/3**. [Real two-checkpoint test](https://github.com/Iniwura/falsum/actions/runs/41284380222).

These are **AI-authored hypothetical judgments, NOT independently reviewed AppSec accuracy**, and are **not** eligible Anjoman pairs, a sealed holdout, or an approved network evaluator. We should NOT repeat the ineffective 52+8 one-epoch recipe or represent the trainer's six-pair PASS as proof that security context is understood.

[Full Phase 2U methodology and limitations](docs/PHASE2U.md) · [Permanent verified score and model hashes](evidence/phase2u-2026-11-01.json)

## Phase 2T: eight real projects, reproducible generalization failure, historical leakage disclosed

Four more independently maintained public fixes from **Starlette, urllib3, Django and Express** have been pinned and cryptographically replayed against their actual source and modified regression-test files. This yields **eight distinct source projects** across separate research pools, with no cross-pool repository, commit, advisory or selected blob reuse. [Successful real-source CI](https://github.com/Iniwura/falsum/actions/runs/41232688735) · [Complete technical evidence](docs/PHASE2T.md).

Their **eight new AI-provisional context-reversal questions** passed all full-token 512-cap checks (**maximum 466**) and source authenticity gates. [Source-grounded new question build](https://github.com/Iniwura/falsum/actions/runs/41232403688).

We tested the **same frozen research ModernBERT LoRA checkpoint**, with no additional model training, on all eight new cases. It matched AI-proposed answers **4/8** and switched correctly across **0/4** opposite-context source families again. Four original project families also showed **0/4**, making **0/8 inspected families** with both context judgments matching the AI proposals. [Verified actual model experiment](https://github.com/Iniwura/falsum/actions/runs/41232475893) · [Permanent model and source evidence](evidence/phase2t-2026-10-31.json).

**Important correction:** The old research training queue included the EXACT Jinja2 and Axios advisories later used as Phase 2S diagnostics, so those earlier cases were **not unseen**. The four newly sourced projects showed **zero exact GHSA and package overlap with that specific prior advisory queue**, but this does **not** establish an untouched, sealed evaluation set or exclude wider pretraining exposure.

All added judgments remain AI-authored, speculative deployment scenarios. **No human-validated labels, eligible preference data, registered evaluator or winning accuracy claim.** The current model should NOT be registered on the basis of this research.

## Phase 2S: real-source AI AppSec research exposes model's context weakness

FALSUM now has **four AI-authored AppSec review dossiers** tied to real, immutable Requests, aiohttp, Jinja2 and Axios security fixes and tests. Each has two hypothetical deployment contexts with **identical competing answers** but opposite AI-proposed preferred answers. The source verification CI produced **8/8 authentic source/test replay transitions**, **8 research A/B cases**, and **16/16 full Task/Answer renders within ModernBERT's 512-token limit** (maximum **440**). [Corpus build](https://github.com/Iniwura/falsum/actions/runs/41210477426) · [Technical methodology and evidence](docs/PHASE2S.md).

We ran our **actual existing, quarantined ModernBERT LoRA model** on all eight cases. It agreed with the AI research proposals **4/8** but correctly reversed its preferred answer across **0/4** opposing project-context families. It favored the same answer in both scenarios for each project. This is **not independently verified accuracy**, but clearly exposes a problem in the context discrimination we want. [Real model CI](https://github.com/Iniwura/falsum/actions/runs/41211098910) · [Exact case-level scores](evidence/ai-review-frozen-model-case-scores-2026-10-31.json).

We also **executed actual original and fixed Axios URL-building code** from Git-pinned source (6/6 assertions). The new 0.x allowAbsoluteUrls guard is **opt-in**: by default, even the patched helper still lets an absolute URL override a configured baseURL. The selected upstream regression test's no-baseURL case does not by itself prove configured-baseURL protection. No outgoing HTTP was sent, and **we do not claim a deployed SSRF exploit**. [Actual source-behavior test](https://github.com/Iniwura/falsum/actions/runs/41211349379).

All Phase 2S judgments remain **AI-authored research drafts**. They are NOT independent human reviews, a sealed holdout, eligible Anjoman evaluation rows or approved model training labels. We should not register this model based on these results.

## Phase 2R: genuine ABI-v2 hybrid WASM build from actual trained model

FALSUM has now **successfully exported its real quarantined ModernBERT LoRA checkpoint to 599 MB ONNX FP32, baked it into a WASI model and packaged a 601 MB WebAssembly module through the exact official Telegraph V2 toolchain**. The packager classified `SECURITY_REVIEW_GENERAL` as **hybrid**, wrote ABI v2 metadata, passed structural checks and produced **two byte-identical builds**.

[Successful full build](https://github.com/Iniwura/falsum/actions/runs/41132003351) · [Download time-limited research-only WASM](https://github.com/Iniwura/falsum/actions/runs/41132003351/artifacts/13013677262) · [Detailed artifact hashes, provenance and limitations](docs/PHASE2R.md).

The [real WASI execution smoke test](https://github.com/Iniwura/falsum/actions/runs/41132583676) also **passed**: Wazero ran the actual official-format packaged module and obtained **−0.4765051305** versus the PyTorch exporter's **−0.4765053391**, an absolute difference of **2.09 × 10⁻⁷** on one fixed input. This demonstrates single-input runtime fidelity only, not security-review correctness or live Telegraph node acceptance. [Source, build and smoke proof](docs/PHASE2R.md). [Permanent hash-linked research evidence](evidence/research-wasm-runtime-2026-10-30.json) remains available after the large binary expires.

**The WASM is not eligible for registration.** The underlying model still scored only **1/4 (25%)** on fictional PR validation, has **zero independent AppSec-reviewed preference labels**, and has not passed the network's own node-side acceptance, a real project-separated holdout or Anjoman acceptance. The separate [real WASI execution experiment](.github/workflows/research-wasi-smoke.yml) verified single-input PyTorch/WASI score fidelity without claiming security-review correctness.

## Phase 2Q: independent AppSec review intake, always unverified until adjudicated

FALSUM now runs a **read-only GitHub issue intake** whenever someone submits or edits the [structured AppSec review form](https://github.com/Iniwura/falsum/issues/new?template=appsec-independent-review.yml). It verifies the public issue author's GitHub identity, excludes the maintainer and bots, requires pinned pre/post code citations and the exact advisory, checks deployment reasoning and disagreement, and deduplicates claims by source case and GitHub account. Two agreeing GitHub accounts still **do not** become expert-reviewed labels automatically.

[Verified intake workflow](https://github.com/Iniwura/falsum/actions/runs/41131525786): **16/16** offline adversarial tests passed, and a live public GitHub API read found **zero review submissions, zero independently validated labels and zero training-ready question pairs**. [Implementation, threat model and next gates](docs/PHASE2Q.md).

**Bounty truth:** [Telegraph #96](https://github.com/telegraphprotocol/bounties/issues/96) requires eligible preference question pairs AND a registered working WASM evaluator. Its own reward is listed as **unfunded**; Season II prizes and protocol evaluator rewards are separate.

## Phase 2P: code questions from real pre-fix revisions

FALSUM has now produced **6 remediation-withheld, real pre-fix source challenges** from four verified open-source Python/JavaScript projects. The questions-only artifact contains code from the historical parent revision without a supplied fix, GHSA/CVE, regression-test patch or answer. A **separate provenance artifact** links each task to immutable source and repair evidence; these public examples are NOT a sealed holdout.

The [actual ModernBERT tokenizer gate](https://github.com/Iniwura/falsum/actions/runs/41130722345) checked **6/6 prompts within the 384-token task allowance** (maximum 286), reserving another 124 tokens for an answer and 4 for boundary safety under the 512-token limit. The original first attempt correctly failed when one question exceeded this allowance; CI now rejects overflow instead of truncating code. All examples remain **unlabelled and unreviewed**. See [Phase 2P documentation](docs/PHASE2P.md).

## Phase 2O: genuine public security-fix code (not training labels)

FALSUM now verifies four **real upstream security-fix commits** in Requests, aiohttp, Jinja2, and Axios, covering proxy credential forwarding, static-file traversal, and a sandbox attribute-filter bypass. It checks full commit and parent identities, exact source and regression-test Git blob IDs, then **replays the code and test diff against the actual upstream parent revision**. Eight file transitions must reconstruct byte-for-byte or CI fails.

- [Real source queue](data/real-fix-queue.json)
- [Source provenance, replay and independent-review boundary](docs/PHASE2O.md)
- [Automated verified evidence workflow](.github/workflows/real-fix-evidence.yml)

**Important:** These are real public patches, not independent security-review answer labels. Their real-world deployment prerequisites must still be reviewed by AppSec experts. This four-project corpus has **zero human-reviewed answers**, is **not** fed into the quarantined ModernBERT pilots, and is **not** an eligible Telegraph evaluation set.

## Phase 1 + Phase 2a: foundation and source snapshots

This repository starts with an **offline, fail-closed data quality gate** for security evaluation material. It catches malformed provenance, unreviewed evidence, duplicated negatives, easy length shortcuts, near-duplicate prompts, and advisory leakage across train/validation/holdout splits. It exports the exact `prompt` / `chosen` / `rejected` JSONL format used by the official training kit.

**Phase 2a can now fetch immutable OSV advisory snapshots and check supported version ranges. It does not prove exploitability, independently review advisories, train a model, provide a network scorer, or claim accepted Telegraph evaluation material.** A reviewer and source snapshot must establish ground truth independently. All examples in unit tests are invented and must not be submitted.

## Run locally (Python 3.11+)

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m falsum validate path/to/ledger.json
PYTHONPATH=src python -m falsum export path/to/ledger.json --split train --out path/to/train.jsonl
PYTHONPATH=src python -m falsum fetch-osv GHSA-jr5f-v2jv-69x6 --directory data/snapshots
PYTHONPATH=src python -m falsum check-osv data/snapshots/GHSA-jr5f-v2jv-69x6.json --advisory GHSA-jr5f-v2jv-69x6 --ecosystem npm --package axios --version 1.8.2 --expect unaffected
```

`pip install -e .` is optional for the `falsum` console command.

See [Evidence format and quality guarantees](docs/EVIDENCE.md), [Source snapshots and trust boundaries](docs/SOURCES.md), and [Architecture and build gates](docs/ARCHITECTURE.md).

## Official V2 compatibility

The [current Telegraph scoring-adapter kit](https://github.com/telegraphprotocol/telegraph-wasm-baseline) uses a **ModernBERT LoRA reward model → ONNX FP32 → WASI WASM** pipeline with ABI v2 and a 512-token model cap. The adapter runs offline and cannot retrieve new CVE facts during scoring. FALSUM's evidence ledger is a training and evaluation preparation system, not an alternative adapter runtime. The Phase 2k pilot **did** perform official tokenizer conformance, actual LoRA training and real model scoring. Phase 2R **has now verified ONNX export and deterministic ABI-v2 WASM packaging**; **Telegraph registration, full node-side acceptance and dependable answer-ranking accuracy are still unverified**, although one independent Wazero WASI execution smoke now passes.

## Trust model

- `review_status: reviewed` records *human attestation*, not automated confirmation of advisory authenticity.
- A `source_sha256` records an external source snapshot checksum. The Phase 2a snapshot audit can now verify the digest against a local OSV archive; the base ledger gate alone validates only its form.
- Cite primary advisories, pin the version and affected conditions, and keep the original evidence snapshot in a reproducible archive before material submission.
- No synthetic identities, false network claims, real credentials, or private vulnerability disclosures in public datasets.
- Keep training data separate from independent test cases. No evaluation submissions before the evidence is source-verified.

## Status

Phase 2L: official CPU training completed and produced a quarantined LoRA adapter; independent security-review evaluation failed on five of six paired counterfactual families. **No active scoring adapter, network registration or judge acceptance is claimed.**

## Phase 2b — public-advisory draft corpus (not submitted)

The repository includes pinned OSV-format snapshots from GitHub's reviewed
advisory database for Axios and two different Jinja2 CVEs. Version-boundary
checks include the important OSV `ECOSYSTEM` format for stable npm and PyPI
versions. Unsupported version syntax returns `unknown`, not an unsafe clean
result. **All real-source cases remain `draft`, not independently human-reviewed.**

```bash
PYTHONPATH=src python -m falsum validate data/draft-ledger.json
PYTHONPATH=src python -m falsum audit-snapshots data/draft-ledger.json --directory data/snapshots --include-drafts
PYTHONPATH=src python -m unittest discover -s tests -v
```

Read [corpus provenance and review boundary](docs/CORPUS.md). This is evidence
preparation, not model training, a scorer, or eligible Telegraph pool material.

## Phase 2c — security-review application scenarios (draft only)

Twelve additional **hypothetical, non-submitted** cases test configuration,
secret-handling, SSRF, Actions token privileges, and TLS certificate-validation
preconditions. Cases are partitioned by rule family and source across training,
validation, and holdout. All linked guidance is **unpinned** and every case
remains `draft`, with no human review or network-eligibility claim.

```bash
PYTHONPATH=src python -m falsum check-scenarios data/draft-scenarios.json
# This export intentionally refuses unreviewed/unpinned material:
PYTHONPATH=src python -m falsum export-scenarios data/draft-scenarios.json --split train --out train.jsonl
```

Read [Phase 2c casebook, provenance and promotion gates](docs/SCENARIOS.md).
The program does **not** analyze real repositories, detect real secrets, or
replace human review. It must not be represented as a deployed security scanner
or an accepted Telegraph scoring adapter.

## Phase 2d — pinned application-security guidance

Four upstream documentation revisions have been pinned, with curated SHA-256 verified excerpt manifests. Run `PYTHONPATH=src python -m falsum audit-scenarios data/draft-scenarios.json`. See [Phase 2d provenance](docs/PHASE2D.md). All scenario cases are still drafts; no independent human review, eligible Telegraph rows, model or scorer is claimed.

## Phase 2e — official dataset-gate diagnostic

A [pinned upstream Telegraph training-kit check](docs/PHASE2E.md) now runs in CI on quarantined **draft-only** rows. The official check is currently expected to **fail** because the training partition contains six pairs and the upstream 2% single-negative rule requires at least 50 unique rows. This is deliberate transparency, not a passing data gate, not a trained model, and not network eligibility.

## Phase 2f: pinned GitHub advisory research queue

The [32-advisory research queue](data/advisory-queue.json) provides a reproducible **draft-only** pipeline for synthetic affected/fixed-version tasks (potentially 52 training, 6 validation, 6 holdout comparisons). Use `PYTHONPATH=src python -m falsum.advisory_corpus data/advisory-queue.json --out build/phase2f-quarantined` with outbound GitHub access. The workflow never marks rows reviewed, trains a model, or claims Telegraph eligibility. See [Phase 2f notes](docs/PHASE2F.md).

## Evidence-present security judgment benchmark (Phase 2h)

Our initial GHSA-ID prompts did not give the model the affected-version boundary it would need for reasoning. We now build a **second, draft-only evidence-grounded benchmark** from pinned source events, plus missing-evidence controls designed to catch confident guessing. Run `PYTHONPATH=src python -m falsum.grounded_eval data/advisory-queue.json /path/to/DRAFT-ONLY-corpus.json --out /tmp/falsum-grounded`. See [evidence availability and scoring protocol](docs/PHASE2H.md). These are not independently reviewed cases, model scores or accepted Telegraph evaluation material.

## Phase 2i — PR counterfactual challenge (research-only)

The [12-case fictional PR benchmark](docs/PHASE2I.md) tests security judgments about deployment configurations, SSRF, signing keys, GitHub Actions permissions, logging, and TLS. A source-blind answer-only baseline ranked **6/6** original validation/holdout answers correctly without reading a question or diff, exposing a serious shortcut. We replaced those easy comparisons with six paired context reversals. On the paired benchmark, that same baseline scored **50%** on validation and holdout.

Run the provenance and shortcut audit:

```bash
PYTHONPATH=src python -m falsum.pr_benchmark data/draft-pr-benchmark.json --source-casebook data/draft-scenarios.json
```

The 12 cases remain hypothetical and **unreviewed**. They intentionally reuse the same candidate text under opposite conditions, so they are *diagnostic-only*, not a valid training dataset under Telegraph's negative-uniqueness gate. This isolated benchmark does not train a new adapter or claim a network score. The [dedicated CI workflow](.github/workflows/pr-review-benchmark.yml) verifies these constraints on Python 3.11–3.13.
