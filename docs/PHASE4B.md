# Phase 4B — evidence-grounded reference checking for security-review evaluation

**November 12, 2026 · Real upstream evidence · Offline reference tool · Not a registered Telegraph evaluator adapter**

## The problem we are actually solving

FALSUM's authentic official Foundation LoRA failed repeated changed-fact tests: Phase 3Y **4/8 provisional source matches, 0/4 complete context reversals**; Phase 4A **3/6 public GHSA source-fact matches, 0/3 complete version reversals**, with the LoRA choosing A for all six cases. Our earlier genuine Phase 3K training also produced **no demonstrated context-sensitive transfer improvement**. Continuing to report trainer success as better evaluator quality would be misleading.

Instead, this phase builds a **strict reference checker for auditable factual claims**. When a security-review claim says that a specific package version falls inside or outside **one named GitHub-reviewed advisory**, the tool checks its exact source provenance. When a claim asserts deployment exploitation or total application safety, or source evidence is missing or altered, the tool **abstains** instead of inventing certainty.

This reference is useful for generating and checking candidate evaluation material. It does **not** parse arbitrary natural-language AppSec reviews, score all kinds of vulnerabilities, work as a semantic ML evaluator, or meet the network's shared-Foundation LoRA registration contract.

## Scope and provenance

All checks are pinned to **the exact Phase 3Z real source report**, SHA-256:

82347910cb443f2b1cbde565107dbbd280f40e884ca45f2abfd501a8a5d108a8

That report was produced after fetching [the pinned public GitHub-reviewed advisory catalogue and real published PyPI release data](PHASE3Z.md). The source was originally verified in [run #43286926731](https://github.com/Iniwura/falsum/actions/runs/43286926731), and its exact bytes are checked before every CLI execution. It has **three projects, six published release conditions**, and one source-specific affected/patched change per package:

| Project | Named advisory | Within named range | Outside named range |
| --- | --- | --- | --- |
| docling-core | GHSA-vqxf-v2gg-x3hc | 2.48.3 | 2.48.4 |
| hydra-core | GHSA-wf6j-7hvr-gr93 | 1.3.7 | 1.3.8 |
| python-multipart | GHSA-mj87-hwqh-73pj | 0.0.25 | 0.0.26 |

Versions outside these six specifically verified release records **abstain**. This is intentional; a fix for one GHSA does not prove universal safety, nor is an affected version proof that an application exposes the vulnerability.

## Real reproducible measurements

[Phase 4B GitHub Actions](../.github/workflows/phase4b-reference-judge.yml) checks source SHA-256, historical actual model evidence, then evaluates 36 distinct **source-derived** claims:

| Review condition | Cases | Reference verdict |
| --- | ---: | --- |
| Evidence-correct claim about named GHSA range | 6 | SUPPORTED |
| Factually contradicted claim about named GHSA range | 6 | CONTRADICTED |
| Unsupported production-exploit claim | 6 | ABSTAIN |
| Unsupported guaranteed-application-safe claim | 6 | ABSTAIN |
| Tampered or missing primary provenance | 6 | ABSTAIN |
| Unverified package release version | 6 | ABSTAIN |

The intended result is **36/36 matches against the tool's own source-derived scenarios**. This is *by construction*, not independently measured model security accuracy or a statistically valid blind holdout.

The untouched **real old LoRA** scored only **3/6** on the six comparable binary source facts and made **0/3 correct version reversals**. The two experiments do NOT measure the same task on all 36 conditions, and **36/36 must never be misrepresented as a measured improvement in a trained model or network win rate**.

All public-source conditions were designed and inspected by the project. There are **zero independent expert labels**, zero new Anjoman-eligible rows, and no registered evaluator from this phase.

## Try five real sample inputs

1. Open the successful [Phase 3Z source-verification run](https://github.com/Iniwura/falsum/actions/runs/43286926731) and download its artifact named **FALSUM-PHASE3Z-THREE-REAL-ADVISORY-PACKAGES-SIX-VERSION-CASES-NOT-LABELS**.
2. Extract the archive to obtain **PHASE3Z-REAL-SOURCE-CATALOGUE-VERSION-REVERSALS-UNREVIEWED.json**.
3. From the FALSUM repository root, run Python 3.11 or later:

~~~bash
PYTHONPATH=src python -m unittest discover -s tests -p test_phase4b_reference_judge.py -v

PYTHONPATH=src python -m falsum.phase4b_reference_judge \
  --source ./PHASE3Z-REAL-SOURCE-CATALOGUE-VERSION-REVERSALS-UNREVIEWED.json \
  --claims examples/phase4b-evidence-check-requests.json \
  --out /tmp/falsum-phase4b-developer-report.json
~~~

The example claims use real, fixed published advisory and PyPI metadata hashes. They produce **SUPPORTED, CONTRADICTED, ABSTAIN, ABSTAIN, ABSTAIN**. They do not contain private data, protected network evaluation pool material or credentials. The output contains precise, machine-readable reason codes and refuses output overwrites.

To inspect the stress experiment and the honest old-model comparison (not learned improvement):

~~~bash
PYTHONPATH=src python -m falsum.phase4b_reference_judge \
  --source ./PHASE3Z-REAL-SOURCE-CATALOGUE-VERSION-REVERSALS-UNREVIEWED.json \
  --old-model-ledger evidence/phase4a-2026-11-12-real-original-model-failure.json \
  --out /tmp/falsum-phase4b-36-test-report.json
~~~

To try new supported inputs, copy an object from the [five sample inputs](../examples/phase4b-evidence-check-requests.json), keep the exact evidence hashes, edit only the supported claim type, and run --claims with your own JSON array. New version IDs that were not authenticated in Phase 3Z deliberately get ABSTAIN; to cover them, extend the source verifier with new independently pinned source records first. There is no background network access in the checker itself.

## Trust boundaries and remaining work

- The approved source is checked against the exact digest of the original verified CI artifact. An arbitrary JSON with substituted outcomes is rejected.
- Each claim checks its **exact GHSA, package, published version, advisory digest, release metadata digest and official PyPI URL** before making any version-range verdict.
- False certainty is not silently rewarded: missing evidence, unverified versions, and claims of actual exploitation or universal application safety return **ABSTAIN**.
- No freeform text understanding, claim of deployed vulnerabilities, security certification, independent expert accreditation, model registration or confidential network label leakage.
- The validator is an **offline reference and evaluation-material aid**, **not** a network-compatible evaluator adapter for Telegraph judgment/hybrid Intents. The prior trained and original LoRAs stay quarantined.
- The external [Phase 3Z review issue](https://github.com/Iniwura/falsum/issues/25) remains open. A review will count only if genuinely received and independently vetted; none is fabricated.

**Next gate:** obtain external source adjudication, evaluate a genuinely new candidate against a protected project-disjoint test set, and prepare a judge-readable demonstration of the actual source checking + failed LoRA baseline. The official Season II rules allow evaluation material, an adapter, or both; this reference tool supports evaluation material and does not substitute for network registration or independently accepted material.
