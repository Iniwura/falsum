# Phase 4V — The real-source FALSUM review workbench

**Current extension:** [Phase 5D adds a verified Flask fifth case to this same workbench](PHASE5D_FIVE_CASE_PREMIUM_JUDGE_WORKBENCH.md). The original historical Phase 4V analysis below describes the original four-case launch. The present public build generates **five cases and 80 constructed outcomes** once the updated deployment is live. The original four-case permanent index remains unchanged.

**Telegraph Season II / Evaluators / `SECURITY_REVIEW_GENERAL`**  
**Recorded upstream executions:** November 18, 2026. **Mode:** static offline verification, not live scoring.

## The judge problem this solves

The previous home-page challenge used clearly labeled *fictional* Python security-review scenarios. FALSUM's strongest new security material was real, but reaching it required opening GitHub Actions artifacts and then executing the Python CLI.

**Phase 4V makes the authentic source evidence the first visible test path.** The front page now links prominently to `/witness/`. This new workbench works without GitHub login, Telegraph keys, a wallet, model endpoint, an external API, or an account. A judge can:

1. Select **Koa**, **Hono**, **LangChain Core's initial file-path fix**, or **LangChain Core's later symlink-target fix**.
2. Switch between the exact **vulnerable Git parent** and its exact **fixed commit** while keeping the **same upstream-authored security regression test**.
3. State a review claim: the test passes, the test fails, a production exploit is established, or all deployments are guaranteed safe.
4. Keep the actual pinned execution receipt or deliberately replace its SHA-256 digest.
5. Press **Verify the claim** and see **SUPPORTED**, **CONTRADICTED**, or **ABSTAIN**, with actual SHA-1 Git source/test identities and links to the original source, test and completed GitHub Actions run.

The real upstream source executions were already reproduced in [Phase 4R](https://github.com/Iniwura/falsum/actions/runs/44352329150) and [Phase 4S](https://github.com/Iniwura/falsum/actions/runs/44353999011). [Phase 4T](https://github.com/Iniwura/falsum/actions/runs/44356563508) independently validated their archived receipt identities. The [permanent public digest snapshot](../evidence/phase4u-2026-11-18-permanent-four-executed-source-witness-index.json) supports the browser's generation, so new fake data cannot replace an upstream source silently.

## Architecture and strict truth boundaries

The browser **does not implement an invented alternative scorer**. At build time, [`phase4v_real_source_witness_site.py`](../src/falsum/phase4v_real_source_witness_site.py) invokes the **exact same Python source-witness checker** used by the offline CLI. That checker first validates the original source lock, all four historical parent/fix/test Git blobs and the four archived original upstream execution receipt hashes.

The Python process precomputes all **64 case × revision × claim × receipt-integrity combinations**. It requires exactly:

| Verdict | Source-grounded constructed combinations |
| --- | ---: |
| SUPPORTED | 8 |
| CONTRADICTED | 8 |
| ABSTAIN | 48 |

The browser serializes those decisions in a single inert `application/json` block, with unsafe HTML delimiter characters escaped. The UI only selects and presents already computed Python outcomes. There are **zero API requests**, no wallet connectors, no dynamic model inference and no external analytics or fonts.

Actual evidence boundaries cannot be removed without failing the build:

- The exact upstream source, regression test and original receipt Git hashes are checked before rendering.
- A test result claimed on the wrong Git revision is **CONTRADICTED** when the original evidence proves the opposite.
- A wrong or tampered receipt digest yields **ABSTAIN**, even when the underlying test assertion would otherwise be true.
- A claim that a real application was exploited or that every possible deployment is safe yields **ABSTAIN**. Historical unit tests cannot establish either.
- The 64 outcomes are **constructed combinations**, not 64 new independent third-party findings, Telegraph evaluation submissions, expert gold labels or successful model predictions.
- **Independent qualified AppSec labels: 0.** **Improved trained-model accuracy proven: no.** **Registered Telegraph evaluator: no.** **Official H2 entry filed: no.**

## Reproduce

Build all current site routes using Python 3.11–3.13 from the repository root:

```bash
PYTHONPATH=src python -m falsum.phase4c_release --out-dir judge-release
```

Open `judge-release/witness/index.html`. The accompanying `witness/FOUR-AUTHENTIC-UPSTREAM-SOURCE-REGRESSIONS.json` contains all 64 exact precomputed results and cited public source links.

Test the same authenticated evidence and web output without network access:

```bash
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_phase4v_real_source_witness_site.py' -v
```

[The Phase 4C CI workflow](../.github/workflows/phase4c-judge-release.yml) runs Python checks on three Python versions and the [Chromium browser acceptance suite](../tests/browser/phase4v_real_source_witness.cjs) at desktop, 390px and 320px, checking every case, revision toggle, legitimate and invalid claim, receipt tampering, keyboard, touch, zero horizontal overflow and zero outbound requests.

### 75-second real-case walkthrough (not a video)

Start in [`/witness/`](https://falsum-evidence-lab.vercel.app/witness/):

- Choose Koa's redirect case, leave **Vulnerable parent** selected and claim **The security regression passes**. The result is **CONTRADICTED**, because the real new test fails on the old code.
- Switch to **Fixed commit**, keeping the exact same claim. The result changes to **SUPPORTED** and source/test Git identities update.
- Select **Wrong receipt** and verify again. The result becomes **ABSTAIN**, not a fabricated result from corrupted source evidence.
- Restore the authentic receipt and claim a **production exploit**. The result remains **ABSTAIN** because the cited test says nothing about actual deployed consequences.
- Open **Hono**, then each distinct **LangChain Core** stage. Inspect the linked public original upstream source, newly authored regression test and GitHub Actions execution.
- Optionally open the unchanged [recorded actual Foundation-model comparison](https://falsum-evidence-lab.vercel.app/compare/) to see the **negative** model-quality result: 5/8 researcher-source matches and only 1/4 complete before/after reversals against 4/8 for either constant-choice baseline.

The original fictional educational review lab still exists at `/` and is **separately labeled**. The newer real upstream evidence is the recommended primary Evaluators judge experience.

**No demo video was recorded, generated or uploaded in this phase.**
