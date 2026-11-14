# FALSUM — Judge guide

**Telegraph Season II / Evaluators / SECURITY_REVIEW_GENERAL**  
**Evidence snapshot: 12 November 2026. Final H2 submission: NOT YET FILED.**

## What is FALSUM?

FALSUM contributes evaluation material for AI security-review quality. It checks a simple but important requirement: when a dependency version, authorization condition or runtime observation changes, the evidence-supported security conclusion must change too. Its public work uses real historical upstream source, exact model score records, safe synthetic PR executions and strict abstention for unsupported claims.

**Track contribution:** 20 Anjoman evaluation preference pairs previously reported Eligible by the contributor, with a [public bounty submission](https://github.com/telegraphprotocol/bounties/issues/96#issuecomment-6588168396); formal maintainer acceptance is **not verified**. This is **not** an active network scoring adapter, a confirmed independent expert benchmark, or an H2 submission receipt.

## 90-second judge walkthrough

| Time | Action | What it establishes |
| --- | --- | --- |
| 0:00–0:25 | Open [real model evidence](https://falsum-evidence-lab.vercel.app/proof/). Choose docling-core 2.48.3, then 2.48.4. | The pinned public GHSA expected answer changes A to B; the genuine original LoRA continues choosing A. |
| 0:25–0:40 | Switch to hydra-core and python-multipart. Select each fixed version. | Three separate package projects have the same model failure; these are genuine recorded f32 scores, not an animated fictional AI. |
| 0:40–1:05 | Open the [three-case review challenge](https://falsum-evidence-lab.vercel.app/), choose the weaker review on the first case, then reveal before/after results. | The local fictional code behavior is actually executed, and the legitimate control remains operational. These are *authored* review examples, not model-generated predictions. |
| 1:05–1:30 | Follow [official Foundation model CI](https://github.com/Iniwura/falsum/actions/runs/43291803205), [source verifier CI](https://github.com/Iniwura/falsum/actions/runs/43287674960) and [contributor bounty evidence](https://github.com/telegraphprotocol/bounties/issues/96#issuecomment-6588168396). | Source and score provenance, repeatable process, separately reported Anjoman contribution. Maintainer acceptance still pending. |

**One-sentence result:** The unchanged model got **3/6** public, narrow version facts right and **0/3** full affected-to-fixed reversals, no better than the constant-A or constant-B baseline (**3/6**). The source-grounded reference tool correctly handles known GHSA fact, contradiction and abstention cases **by construction**, not by improved machine learning.

## New 75-second source-revision comparison (Phase 4I)

[**Open the live four-project comparison**](https://falsum-evidence-lab.vercel.app/compare/) · [**Read the exact experiment and controls**](PHASE4I_JUDGE_COMPARISON.md) · [**View the genuine scoring CI**](https://github.com/Iniwura/falsum/actions/runs/43530363990).

- **0–15 seconds:** Read the exact result: the unchanged original LoRA matched **5/8** public source-fact interpretations, completed **1/4** proper before-to-after reversals, versus **4/8** for constant-A and constant-B controls on these *same* eight questions.
- **15–35 seconds:** Select **PyJWT** and switch its pinned parent source to the fix. The model correctly changes its preference A → B; open the actual source patch and regression test.
- **35–55 seconds:** Select **MCP Python SDK**, then **Werkzeug**. Both upstream source facts change A → B, but the original model stays with B across both revisions. The displayed float32 scores and source URLs are real, recorded and SHA-verified.
- **55–75 seconds:** Verify the permanent source manifest, original model score artifact and exact model f32 bits. Note that the source-aware **8/8** control is *correct by construction from researcher expectations*, not a trained winning evaluator.

This is a **different experiment** from the older /proof/ page's 3/6, 0/3 public GHSA version conditions. Both used the same failed research LoRA, so neither result is evidence that FALSUM trained a better model. The source-fact expected choices remain **unadjudicated by independent AppSec experts**; the original LoRA remains quarantined. The new third route is also built by the exact same zero-credential command below and produces `judge-output/compare/index.html`.

## Reproduce without an account, wallet, model or keys

Python 3.11–3.13; the clone step needs internet, but build/test does not.

~~~bash
git clone https://github.com/Iniwura/falsum.git
cd falsum
PYTHONPATH=src python3 -m falsum.phase4c_release --out-dir judge-output
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_phase4c_judge_release.py' -v
~~~

Open judge-output/index.html and judge-output/proof/index.html. The first is a static report of real executions against fictional PRs. The second replays the authentic **recorded** Foundation scores. Both reject false security certification claims; the second also binds actual float32 score bits to a source and model SHA record.

Test the independent source-bounded claim checker:

~~~bash
# First extract the JSON artifact from the Phase 3Z source-verifier CI run:
# https://github.com/Iniwura/falsum/actions/runs/43286926731

PYTHONPATH=src python3 -m falsum.phase4b_reference_judge \
  --source ./PHASE3Z-REAL-SOURCE-CATALOGUE-VERSION-REVERSALS-UNREVIEWED.json \
  --claims examples/phase4b-evidence-check-requests.json \
  --out /tmp/falsum-review-results.json
~~~

Expected five results in order: **SUPPORTED, CONTRADICTED, ABSTAIN, ABSTAIN, ABSTAIN**. A changed version outside the frozen six or a forged source digest must abstain. The checker is intentionally limited to published one-GHSA version-boundary checks; it is not an LLM or general AppSec scanner.

### Original Phase 3Q reproduction, preserved

The combined Phase 4C command above builds both public pages. To independently reproduce **only the original fictional synthetic Python challenge**, its stable historical entrypoint still works:

~~~bash
PYTHONPATH=src python -m falsum.phase3q_mission_lab --out-dir original-phase3q-only
~~~

Earlier visual releases are preserved as technical history: [Phase 3S original Firma-inspired editorial interface](PHASE3S.md) preceded the current minimal interactive Phase 3U layout. These are UI stages, not external security-review certification or additional live model capability.

## Proof directory

| Claim | Machine-checkable evidence | Limit |
| --- | --- | --- |
| Real upstream catalogue and PyPI version records | [Phase 3Z](PHASE3Z.md) · [authentic source CI](https://github.com/Iniwura/falsum/actions/runs/43287674960) · [permanent source receipt](../evidence/phase3z-2026-11-12-pinned-real-advisory-receipt.json) | Public source, no independent expert labels |
| Genuine original LoRA scoring on the new version facts | [Phase 4A](PHASE4A.md) · [real official Foundation ONNX/WASI CI](https://github.com/Iniwura/falsum/actions/runs/43291803205) · [permanent all-12 score bit ledger](../evidence/phase4a-2026-11-12-real-original-model-failure.json) | 3/6, 0/3, old model fails quality gate |
| Source-grounded reference tool | [Phase 4B](PHASE4B.md) · [successful CI](https://github.com/Iniwura/falsum/actions/runs/43297345188) · [five developer inputs](../examples/phase4b-evidence-check-requests.json) | 36 fixtures are construction checks, not trained-model accuracy |
| Real before/after Python of three fictional PRs | [Phase 3Q](PHASE3Q.md) · [public proof JSON](https://falsum-evidence-lab.vercel.app/ACTUAL-SYNTHETIC-RUNTIME-PROOF.json) | No independent H2 mission integration |
| Original researcher-trained LoRA comparison | [Phase 3K](PHASE3K.md) · [verified negative training evidence](../evidence/phase3k-2026-11-02.json) | Trained candidate made no measured source-transfer improvement |
| Anjoman material contribution status | [Privacy-safe 20 Eligible record](../evidence/phase3o-2026-11-02-20-eligible.json) · [actual /submit](https://github.com/telegraphprotocol/bounties/issues/96#issuecomment-6588168396) | Eligibility reported by contributor, not independently confirmed bounty acceptance |
| Independent-source review | [Reviewer issue #25](https://github.com/Iniwura/falsum/issues/25) · [review guide](REVIEW_ONE_CASE.md) | External review and developer activation currently unverified |

## Network and cost truth

The real Anjoman contribution used the signed contributor workflow for SECURITY_REVIEW_GENERAL. The public static website does **not** buy inference, hold wallets, submit signed transactions, access the hidden evaluation pool or register an evaluator. No live request or network earning is demonstrated by the website. All browser examples and security identities are synthetic or previously recorded from public sources.

The original and retrained checkpoints remain quarantined after authentic negative model-quality experiments. Public GHSA version-inclusion questions do not establish production exploitability or general security safety. No customer or external partner usage is claimed.

**Possible mission impact:** Security-review quality can matter for Exchange listing services, Model Economy agent tools and Web3/DeFi off-chain APIs. These are *potential* uses, not independent deployments or verified completed H2 missions.

## Risks a judge should know immediately

| Item | State | Required follow-up |
| --- | --- | --- |
| Valid source-based evaluation coverage | Verified on three new public packages | Independent expert critique and extension to more failure types |
| Registered better evaluator | **No** | New sealed, expert-reviewed test plus real validated improvement; do not present failing LoRA as released |
| Bounty acceptance | **Unconfirmed**; other contributors' claims do not invalidate this entry | Ask maintainer to review existing evidence; no fake bot acknowledgment |
| Outside AppSec reproduction or developer use | **Not verified** | Request and cite genuine feedback, including negative findings |
| Three public technical progress updates across dates | **Unverified** | Publish and preserve actual public URLs; no backdating |
| Required Telegraph bounties GitHub star | **Unverified** | Owner must verify it with the correct GitHub username |
| Official H2 registration and final entry | **Not verified/submitted** | Owner completes official H2 form; preserve real receipt |
| Real 2–5 minute screen demo | **Not yet uploaded** | Record actual website, official CI, and safe Anjoman status |

## Competition fit

Official Season II rules require working independently testable contribution, real Telegraph integration evidence, safe data handling, actual reproduction, and a star on the bounties repository. The Evaluators track may submit **evaluation material without a model adapter**. Any excellence or delivery award still requires independent judges to accept technical validity and value; neither this guide nor an Eligible badge guarantees a prize.

Official deadline: **December 1, 2026 at 23:59 UTC**. Our internal target: **Tuesday, November 17**, provided quality and actual submission gates pass. The [final form draft](H2_FINAL_ENTRY_DRAFT.md) and [real video storyboard](H2_EVALUATORS_DEMO_STORYBOARD.md) are ready for the remaining owner-controlled steps.
