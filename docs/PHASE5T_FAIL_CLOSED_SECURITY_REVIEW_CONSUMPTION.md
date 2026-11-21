# Phase 5T — An application cannot trust a paid response without evidence

**FALSUM | Telegraph Season II Evaluators | SECURITY_REVIEW_GENERAL | November 21, 2026**

## What changed

FALSUM now has a **real, executable application-consumption decision policy**, not only a benchmark report. Given a canonical-Intent-shaped security-review request and response, the offline reference application **allows** only a precisely source-supported, narrowly scoped claim. It **denies** off-target intelligence, disproved assertions, unknown revisions and tampered source/test/receipt evidence.

The policy composes two previously verified inputs:

1. **Original executed upstream regression proof.** Four original real-source Koa, Hono and LangChain historical regression stages from [the permanent authenticated source-witness index](../evidence/phase4u-2026-11-18-permanent-four-executed-source-witness-index.json). For each original pre-fix and post-fix Git revision, the claim checker authenticates the source Git blob, exact upstream security-regression test blob and original execution receipt SHA-256. The original source selection and index are fingerprint-checked before issuing any positive result.
2. **Original actual third-party network output evidence.** The independent PR Guard builder's [two published canonical `SECURITY_REVIEW_GENERAL` HTTP 200 paid-flagged captures](PHASE5R_CANONICAL_TELEGRAPH_TASK_INSENSITIVITY.md), from its exact original public Git revision. A code-diff security review and an npm lodash 4.17.15 review yielded the identical irrelevant 100-advisory list from the same reported miner. Every execution fetches and verifies both original public Git blobs and checks the response's actual target relevance.

**No new paid request, application contract in the Telegraph network, network evaluator registration, or external adoption is implied.** This is a reproducible public offline consumption *reference integration*. The two historical external captures are genuine public recorded paid-status outputs, but the recorded payment fields are not independently chain-settlement verified.

## Precommitted protocol and measured dimensions

Original source-consumption protocol committed **before Phase 5T evaluator code or CI** as [Phase 5T frozen contract](../data/phase5t-preimplementation-source-consumption-lock.json), commit `566deb1de916bb1316469bf92eb78c4e57b0d867`, Git blob SHA-1 `8383f599f8abf60278008fbbf284081882daa62e`. This is a design preregistration, not a blind source-case selection: all four upstream projects and both PR Guard outputs were already known.

| Group | Cases | Origin | Expected action |
| --- | ---: | --- | --- |
| True, correctly bound original regression result | 8 | Author-constructed from four genuinely executed upstream source-regression stages × pre/post fix | ALLOW |
| False reversal of that same narrow source fact | 8 | Author-constructed counterfactuals against original execution | DENY |
| Correct narrow fact, corrupted execution-receipt hash | 8 | Author-constructed tampered evidence | DENY |
| Off-target paid-status original external Telecom reports | 2 | Actual immutable independently published PR Guard captures, same reported Miner | DENY |
| **Total** | **26** | **24 constructed and 2 real historical outputs** | **8 ALLOW, 18 DENY** |

The gate can also assess local caller-supplied canonical-shaped requests and responses, without contacting the network. **Its positive output means narrowly verified regression truth, not vulnerability exploitability, production safety, semantic AppSec gold or general accuracy.**

### Failure mode a real app faces

A 200 status and paid-response flag tell the calling application that it got a response, **not** that the intelligence pertains to the requested source. A third party's unrelated 100-GHSA-feed answer should not drive an automated security signoff.

Similarly, a response containing familiar security vocabulary or a plausible-looking Git commit is not a verified source-test result. The app refuses to act unless the **request identity, upstream source, test and receipt agree**.

## Reproduction

Python 3.11–3.13; public GitHub access for the original third-party captures; no authentication, wallet, API key, payment or private evaluation material needed.

~~~bash
git clone https://github.com/Iniwura/falsum.git
cd falsum
python -m pip install --no-deps -e .

# Run the 26-case study, actually retrieving the original two external captures
# and separately validating the original four executed-source historical receipts.
falsum audit-telegraph-consumption --out phase5t-original-decisions.json

# Test your own local canonical-shaped case, never sending it to Telegraph.
falsum audit-telegraph-consumption \
  --request-json canonical-request.json \
  --response-json canonical-response.json \
  --out local-safe-action.json

# Run the independent technical-contract unit tests.
PYTHONPATH=src python -m unittest discover \
  -s tests -p 'test_phase5t_application_consumption.py' -v
~~~

Every resulting report is written only to a fresh path and never includes complete original third-party response bodies, source-code snippets or hidden prompts. The live GitHub Actions workflow verifies original external Git bytes, the original regression proof and all 26 anticipated source/application outcomes. It also exposes three deliberately weak comparison policies:

| Baseline policy | Why it fails |
| --- | --- |
| Allow when HTTP 200 and paid flag are present | The two actual external paid-status records still carry irrelevant answers; synthetic local controls do too |
| Deny everything | Prevents a real task failure from becoming an unsafe action, but also prevents **eight supported narrowly verified facts** from being used |
| Trust any structured review claim | Author-looking source claims can be wrong, stolen from another revision or have altered execution receipts |

The 26-item comparison is **a contract self-consistency test** with expected actions that are mostly constructed from the same existing original source witness. If it passes 26/26, **do not report 100% model accuracy or 100% external benchmark accuracy**. Only **2/26** are original real external output captures, and both are failures from one reported miner. The baseline's local "paid" flags for the 24 constructed cases are explicitly simulated for the transport-only control.

## Threat model and safety

The application denies wrong Intent, incorrect request envelope, unrecognized task shape, oversized input, arbitrary full-text security claims, unsupported Git revisions, swapped claims from other projects, altered source/test/receipt hashes, discredited historical regression claims, missing source and meaningless advisory feeds. A user cannot turn a negative outcome into an accepted one simply by adding an overriding field to the JSON.

Only source claims with original narrow `UPSTREAM_REGRESSION_PASSES` or `UPSTREAM_REGRESSION_FAILS` semantics can pass. Deployment exploitation and universal safety remain untested and fail closed. A source-sounding claim cannot bypass a source-independent upstream receipt.

The application consumes no private evaluation pool, hidden benchmark case, buyer credential, wallet material, payment request, or third-party response training corpus. No original paid request/response body is copied into a public artifact. A third party's publicly reported `paid=true` remains an attributed observation, not independently verified settlement.

## What is still necessary for a 90+ competitive evaluation

1. A **project-disjoint**, independently sourced new security dataset with genuine upstream reference evidence, not just perturbations of the same historical four source stages.
2. Comparable **real, permitted same-Intent, same-request** competing Miner outputs, with independent reference adjudication, to demonstrate a genuine ranking decision improvement rather than this local policy demonstration.
3. A real app/integrator or organizer reproducing and adopting the gate. External adoption and qualified independent source judgement cannot be self-certified.
4. Final official hackathon submission, applicable publicity, demo and owner-only eligibility actions.

The official [Telegraph evaluation-material guide](https://docs.telegraphprotocol.com/docs/bounties/evaluation-material) recognizes reproducible measurement processes and working integrations as contributions, but public bounty proof **does not** mean canonical network evaluator status or award acceptance.

This work does not generate the final demo or submit the H2 entry.
