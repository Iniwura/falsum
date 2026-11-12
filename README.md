# FALSUM

**Evidence-grounded security-review evaluation for Telegraph.**

A good security review must change its conclusion when important facts change. FALSUM tests that requirement against real public software fixes and publishes the outcome, including failed model results.

[**Try the review challenge**](https://falsum-evidence-lab.vercel.app/) · [**Inspect actual recorded model scores**](https://falsum-evidence-lab.vercel.app/proof/) · [**Run locally**](#reproduce-it) · [**Review the evidence**](https://github.com/Iniwura/falsum/issues/25)

**Track:** Telegraph Season II / Evaluators. **Intent:** SECURITY_REVIEW_GENERAL.

## What FALSUM actually delivers

| Component | What works | What it does not claim |
| --- | --- | --- |
| [Review challenge](https://falsum-evidence-lab.vercel.app/) | Interactive A/B reviews backed by genuinely executed before/after Python code across three **fictional** PRs | Live model inference or real partner application testing |
| [Real model proof](https://falsum-evidence-lab.vercel.app/proof/) | Inspect the original LoRA's **recorded official Foundation float32 scores** while switching affected vs fixed library releases | A registered evaluator, newly generated model answers or general security accuracy |
| [Reference checker](docs/PHASE4B.md) | Offline verified GHSA/PyPI version facts, contradiction detection and safe ABSTAIN outcomes | A trained semantic security model or Telegraph network-compatible scoring adapter |
| [Seven-family real patch review pack](docs/PHASE4E_FIRST_PLACE_REVIEW.md) | Reverified seven **existing** diverse upstream security-fix source/test cases, with 14 position-balanced review displays and an independent GitHub source-review form | Fourteen independent gold labels, new eligible rows, a sealed model holdout or verified exploitability |

The public source material includes three previously unstudied packages, six affected/fixed version conditions, and 36 constructed reference-check scenarios. Every source uses pinned GitHub-reviewed advisory records and published PyPI release evidence.

### The real measured result

| Experiment | Actual outcome | Inspect the proof |
| --- | --- | --- |
| Original model on earlier Axios/Django before/after facts | **4/8** provisional matches; **0/4** complete reversals | [Phase 3Y report](docs/PHASE3Y.md) · [Official real inference CI](https://github.com/Iniwura/falsum/actions/runs/42145294551) |
| Same unchanged model on six new public GHSA version conditions | **3/6** narrow source-fact matches; **0/3** complete affected-to-fixed reversals; always preferred A | [Phase 4A report](docs/PHASE4A.md) · [Official real inference CI](https://github.com/Iniwura/falsum/actions/runs/43291803205) · [Exact score evidence](evidence/phase4a-2026-11-12-real-original-model-failure.json) |
| Constant-A and constant-B baselines on those six balanced source cases | **3/6** each | [Score audit](docs/PHASE4A.md) |
| Offline source-grounded reference tool | **6 supported, 6 contradicted, 24 abstained**; 36/36 on its **own source-derived fixtures by construction** | [Phase 4B report](docs/PHASE4B.md) · [Source CI](https://github.com/Iniwura/falsum/actions/runs/43297345188) |

The reference checker's 36/36 and the model's 3/6 are **different tasks**. This is *not* a 100% AI improvement. There are **zero externally adjudicated expert labels** in this public reference set, no sealed benchmark, and no demonstrated improved trained LoRA. We keep the failing research checkpoints quarantined.

## The Telegraph contribution

FALSUM's target is the **SECURITY_REVIEW_GENERAL** Intent (adapter family **SECURITY_REVIEW**). The contributor reported **20 source-referenced, explicitly AI-assisted preference pairs marked Eligible** in their actual Anjoman account after rollover.

[Privacy-safe account-status evidence](evidence/phase3o-2026-11-02-20-eligible.json) · [Public bounty #96 /submit comment](https://github.com/telegraphprotocol/bounties/issues/96#issuecomment-6588168396)

**Important:** the bounty submission exists, but final maintainer acceptance is **not verified**. It is separate from the Season II competition entry. Hidden evaluation prompts, selected answers, row hashes and private account data remain out of the public site and repository. The current public checker is **not registered on the Telegraph network** and there is no independently verified external customer or H2 mission-app use.

### Why it matters

Security-review intelligence should differentiate a published affected dependency version from a *reachable production exploit*, and should not certify an application safe merely because one dependency was patched. That is useful evaluation coverage for possible Exchange, Model Economy and Web3 software workflows, though **none of those separate mission integrations is verified yet**.

## Reproduce it

**Prerequisites:** Python 3.11–3.13 and Git. After cloning, the basic static build runs without credentials, wallet, model downloads, external API requests or spending.

~~~bash
git clone https://github.com/Iniwura/falsum.git
cd falsum

# Execute fictional PR fixtures and build the recorded real-model proof
PYTHONPATH=src python3 -m falsum.phase4c_release --out-dir local-judge

# Open local-judge/index.html (three-case synthetic challenge)
# Open local-judge/proof/index.html (authentic previous model scores)

# Fail-closed data integrity and source checking tests
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_phase4c_judge_release.py' -v
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_phase4b_reference_judge.py' -v
~~~

**Expected:** three real Python-executed before/after fictional scenarios, plus six source-verified package-version conditions and the old model's **3/6** fact matches and **0/3** complete reversals. Invalid scores or source receipt identities fail the build. To rebuild, use a new output directory; existing evidence outputs cannot be overwritten.

To try the reference checker with **five real public example inputs**, download the successful [Phase 3Z verified-source artifact](https://github.com/Iniwura/falsum/actions/runs/43286926731), extract its single verified JSON, and run:

~~~bash
PYTHONPATH=src python3 -m falsum.phase4b_reference_judge \
  --source ./PHASE3Z-REAL-SOURCE-CATALOGUE-VERSION-REVERSALS-UNREVIEWED.json \
  --claims examples/phase4b-evidence-check-requests.json \
  --out /tmp/falsum-checked-claims.json
~~~

Expected sequence: **SUPPORTED, CONTRADICTED, ABSTAIN, ABSTAIN, ABSTAIN**. Unknown versions, changed digests, missing evidence, blanket safety claims or unsupported deployment exploit assertions get ABSTAIN. [Reference-checker documentation](docs/PHASE4B.md) explains input format, limitations, failures and how to add new independently verified source records.

On Windows PowerShell, set the PYTHONPATH environment variable to src before using python -m. No token spending occurs in the public demo.

## Verify the evidence independently

1. [New GHSA/PyPI source cases](docs/PHASE3Z.md) and [permanent SHA-bound receipt](evidence/phase3z-2026-11-12-pinned-real-advisory-receipt.json). Real upstream source verification: [CI](https://github.com/Iniwura/falsum/actions/runs/43287674960).
2. [Official original-model ONNX/WASI scores](docs/PHASE4A.md) and [permanent 12-score-bit failure record](evidence/phase4a-2026-11-12-real-original-model-failure.json). Real post-merge scoring: [CI](https://github.com/Iniwura/falsum/actions/runs/43291803205).
3. [Offline deterministic source reference](docs/PHASE4B.md): genuine data checks for 36 deliberately constructed claims. [CI](https://github.com/Iniwura/falsum/actions/runs/43297345188).
4. [Source-executed local Python examples](docs/PHASE3Q.md) and [hosted synthetic fixture proof](https://falsum-evidence-lab.vercel.app/ACTUAL-SYNTHETIC-RUNTIME-PROOF.json).
5. [Independent reproduction and criticism invitation](https://github.com/Iniwura/falsum/issues/25). **No external AppSec review has been verified as completed.**

The actual Phase 4A model artifact has extended retention through February 2027. The public site replays **recorded scores** and never pretends a model is computing them in the user's browser. Our tests explicitly block false model-release claims, tampered evidence, and misleading source assertions.

### Trust boundaries

Public case source records are known and not independently demonstrated to be absent from pretraining. Version-range inclusion does not prove deployment reachability, exploitability or broad application safety. The public three-case challenge tests only **fictional local code**. The online site is static and makes no live scoring or paid Telegraph request. Real Anjoman contribution status is separate, and the two research checkpoints are unregistered.

FALSUM's original implementation includes source material and runtime tooling built with pinned official [Telegraph WASI/scoring code](https://github.com/telegraphprotocol/telegraph-wasm-baseline), the shared ModernBERT Foundation, public advisories and PyPI metadata. Third-party licenses remain applicable. No private network test questions are copied here.

## For judges and developers

[**90-second judge walkthrough**](docs/H2_EVALUATORS_JUDGE_PACK.md) · [**3-minute real demo recording plan**](docs/H2_EVALUATORS_DEMO_STORYBOARD.md) · [**Complete form-ready H2 submission draft**](docs/H2_FINAL_ENTRY_DRAFT.md) · [**Full engineering history**](docs/DEVELOPMENT_HISTORY.md)

FALSUM is being prepared for **Telegraph Season II / Evaluators**. **Official deadline: December 1, 2026 at 23:59 UTC.** Internal quality target: **November 17**. The **official H2 website entry and 2–5 minute recording are not yet submitted or verified**; a GitHub bounty comment does not submit the hackathon entry.

Developer feedback should include a real source URL, exact version, reproducible command and the observed result. The team records genuine reviews, corrections and abstentions, including negative findings. No purchased or fabricated developer activity is counted.
