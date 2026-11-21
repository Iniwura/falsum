# Phase 5AB — Original source-verified receipt Intent comparability census

**FALSUM · Telegraph Season II Evaluators · SECURITY_REVIEW_GENERAL**  
**Original source:** `anvithagowda098/pr-guard`, immutable Git commit `99d2e3c93890a8fc083947bde4f21217516b7a5f`. This project is a third-party source; its publisher has not adopted, endorsed or independently verified FALSUM.

## Why the audit matters

A security response placed in a folder named `SECURITY_REVIEW_GENERAL`, or even an HTTP 200 response reporting payment success, is not proof that the original **receipt's Intent**, **request envelope**, **provider identity** and **review target** were comparable to another Miner response. A quality benchmark that compares unlike questions or Intent schemas would mislead developers and hackathon judges.

FALSUM now tests the *underlying original captured request/receipt fields*, not the filename. Its relevant criterion for same-request **candidate** comparability is the same explicit routed `SECURITY_REVIEW_GENERAL` request object with identical canonical JSON SHA-256, successful recorded receipt with that exact Intent, and two different **reported** Miner IDs. This would still not verify independent ownership, payment settlement or accurate scores. The current frozen third-party set yields **zero** such candidates.

## Preimplementation original protocol

The list of all 12 public external captures, immutable original Git SHA-1 byte fingerprints, expected audit partitions and limitations were frozen **before** the implementation under [Phase 5AB lock](../data/phase5ab-original-receipt-comparability-lock.json). The source is downloaded from one exact Git commit and rejected if any original file's complete Git blob SHA-1 changes. The audit is not based on regenerated fake payloads or author-created responses.

### Original observations — exact scope

The 12 source files include the **ten** original records in the third-party `SECURITY_REVIEW_GENERAL` folder and **two** explicit canonical-routed `ROUTED/security-review-*` captures. The observed categories are:

| Source-verified original category | Records | What is legitimately established |
| --- | ---: | --- |
| Explicit canonical request and matching `SECURITY_REVIEW_GENERAL` receipt | 2 | Two real canonical-routed observations, **two different tasks from the same reported Miner**, not competing responses to one question |
| Direct provider request with `SECURITY_REVIEW_GENERAL` receipt | 2 | Receipt reports the canonical Intent, but the transmitted request is a provider-specific `POST /package` or `POST /review`, **not** the canonical routed request |
| HTTP 200 and recorded paid flags, but receipt Intent is different | 6 | Real published evidence of the risk of directory-label and payment-success-only comparators; the actual receipt reports `SECURITY_REVIEW`, `FACT_CHECK` or `FACT_CHECK_GENERAL` |
| Failed HTTP 500 original requests without a successful receipt | 2 | Paid flags may coexist with failed responses, which cannot be treated as successful comparable outputs |

Therefore: **10 reported-paid HTTP 200 captures**, **4 receipts whose reported Intent is `SECURITY_REVIEW_GENERAL`**, **2 matching explicit canonical request-and-receipt captures**, and **0 distinct-reported-Miner pairs on an identical explicit canonical request in the frozen material**.

The two originally published direct lodash references from Miners **190048** and **77010** are genuine source records. They are excluded from an identical-canonical-request comparison because their original requests were distinct provider-specific `GET /query` shapes and their receipts reported **`SECURITY_REVIEW`**, regardless of their directory names. This does **not** negate Phase 5Y/5Z's independent advisory version-applicability findings. It constrains what those findings can say about Telegraph network rankings.

The published `5530` direct responses include receipts for `FACT_CHECK` or `FACT_CHECK_GENERAL` despite the local request payload's `SECURITY_REVIEW` label. A request payload's intended label is not independent receipt authority, and the external publisher's claimed payment settlement is not independently onchain verified here. Likewise, Miner ID inside a response is a **reported identifier**, not verified evidence of provider-owner independence.

## Reproduction

Python 3.11+ from the public FALSUM repository root:

```bash
python -m pip install --no-deps -e .
falsum audit-receipt-comparability --out original-receipt-census.json
```

The command retrieves all **12 complete original third-party source bytes** from the single immutable Git revision, verifies every complete Git blob SHA-1, validates paid/HTTP/receipt structural claims, and produces a **write-once bounded public-safe metadata report**. It never republishes the original third-party response body, request text, answer, payment account, wallet or full receipt.

The [Phase 5AB Actions workflow](../.github/workflows/phase5ab-original-receipt-comparability.yml) runs constructed adversarial checks on Python 3.11–3.13, then an independent CI job re-downloads the original twelve outside source files, verifies the full upstream Git blobs and requires the exact previously frozen category counts. It archives the safe report as a GitHub artifact.

**To obtain a real fair multi-provider comparison:** an independent external builder would need captures for at least two meaningfully independent providers receiving the **same explicit canonical request**, with trustworthy original Intent/receipt and validated quality labels, using supported network interfaces. The current evidence cannot supply that. Synthetic duplicate inputs or FALSUM self-purchases cannot be represented as new outside observations.

## Judge-facing boundaries

**Genuine evidence:** A separately published public archive has mixed request/receipt/Intent contexts. FALSUM makes the mismatch auditable with original immutable Git source bytes and refuses to manufacture a winner from incomparable data. This is additional provenance-based evaluation material, and can prevent misleading downstream quality and network evidence.

**Not established:** A better registered scoring adapter, a new network ranking, two independently owned comparable Miners, human expert AppSec gold, a fair performance leaderboard, independently settled transactions, fresh paid calls, an accepted external FALSUM integration, new independent usage, a hidden holdout, or the final H2 entry.

This is a **negative comparability finding**, not a claim that the reported Miners are fraudulent, that the external project's directory naming is malicious, or that the responses are semantically incorrect. A valid audit may conclude no comparison is currently defensible.

**Original run link and artifact SHA:** provide only after the full original-source GitHub CI job actually succeeds.
