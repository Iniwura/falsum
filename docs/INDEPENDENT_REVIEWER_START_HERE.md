# Independently reproduce FALSUM's public evidence

**No wallet · no API key · no Telegraph payment · no model download · no hidden evaluation prompts**

This is a public, reproducible developer review task for [FALSUM](https://github.com/Iniwura/falsum), a **Telegraph Season II Evaluators hackathon entry** focused on source-grounded security-review evidence. It is not a promise of a payment, reward, credential, approved network evaluator or validated scoring improvement.

## What to test (three public-source exercises with distinct provenance)

1. **Receipt/Intent comparability.** FALSUM re-fetches 12 historical captures independently published in PR Guard's public GitHub repository, checks each complete original Git blob SHA-1, and compares the **actual request envelope** with the **reported receipt Intent**. The expected observed partition is **2** explicit canonical requests with matching receipts, **2** direct requests with canonical-reported receipts, **6** HTTP 200 captures with different reported receipt Intents, and **2** unsuccessful records lacking a successful receipt. The exact canonical request of neither routed capture was answered by a different reported Miner in this frozen sample. This is not a fair Miner leaderboard.
2. **Package/version reference filtering.** FALSUM independently authenticates six complete GitHub-reviewed GHSA source records and rechecks a **constructed local** lodash 4.17.15 response. It should display **5** version-applicable advisory references and suppress **1** version-inapplicable reference (GHSA-f23m-r3pf-42rh). The local response is deliberately constructed and **is not an independent outside Miner response**.

3. **New npm/RubyGems advisory source cases.** The one-click replay separately authenticates three complete GitHub-reviewed advisory blobs covering npm/axios and RubyGems/rack. Three **constructed** reviewer targets check an Axios version-applicable reference, an old-vs-new Rack version distinction and conservative abstention on an unsupported prerelease interval. The source corpus and original 13 precommitted assertions remain unchanged. This is not a general current vulnerability scanner or independent expert-labelled benchmark.

The distinction between original outside captures, reviewed GitHub advisory sources and constructed demonstration inputs is material. Original source records are not independent expert security gold, proof of paid onchain settlement, proof of external adoption or a registered network evaluator.

## Option A: run the public GitHub Action on your own fork

1. Fork [Iniwura/falsum](https://github.com/Iniwura/falsum).
2. In **your fork**, enable GitHub Actions if GitHub prompts you. Open **Actions → Independent Reviewer Replay - public evidence only → Run workflow** on your fork's default branch. GitHub may require the workflow file to be on the fork's default branch before manual dispatch is available.
3. Inspect the actual job's green/red steps, not merely a screenshot. Download its **falsum-public-reviewer-replay** Actions artifact. It contains `reproduction-manifest.json`, `original-12-receipt-comparability.json`, `constructed-local-display-decision.json`, `constructed-axios-source-decision.json`, `constructed-rack-source-decisions.json`, and `constructed-rack-prerelease-uncertainty.json`. Check the source count, provenance classes, distinct reported-Miner comparison count and the filtered GHSA.
4. Try to **falsify** an assumption: inspect any original pinned source link in the report and decide whether the request/receipt classification matches the published input. A failed run, a contrary finding or an unclear item is more valuable than a rubber stamp.
5. If willing, report the **actual public workflow run URL** and your specific findings in [the external reproduction issue form](https://github.com/Iniwura/falsum/issues/new?template=independent-public-reproduction.yml). Use your own GitHub account. No submission of keys, paid receipt secrets, wallets or nonpublic cases is requested.

A successful run in the author's own GitHub account **does not count as independent developer adoption**. An independent forked run is evidence of reproducibility, while the person's analysis, critique, corrections or real integration is needed to support a stronger contribution claim.

## Option B: run locally without installing dependencies

Requires Python 3.11+ and a computer able to reach public `raw.githubusercontent.com` (the pinned historical originals). The commands are read-only except for their JSON output files.

```bash
git clone https://github.com/Iniwura/falsum.git
cd falsum

# No pip install, private token, wallet or paid Telegraph request:
PYTHONPATH=src python -m unittest discover -s tests -p 'test_phase5ab_original_receipt_comparability.py' -v
PYTHONPATH=src python -m falsum.cli audit-receipt-comparability --out original-12-receipt-comparability.json

PYTHONPATH=src python -m falsum.cli bundle-reviewed-advisories --out historical-six-reviewed-sources.json
PYTHONPATH=src python -m falsum.cli filter-security-references \
  --role direct_deps_dev_ghsa \
  --request-json examples/phase5aa-constructed-request.json \
  --response-json examples/phase5aa-constructed-response.json \
  --reviewed-bundle historical-six-reviewed-sources.json \
  --out constructed-local-display-decision.json

# New reviewed Axios/Rack original-source and constructed-input exercises:
PYTHONPATH=src python -m unittest discover -s tests -p 'test_phase5ag_reviewed_reference_evaluator.py' -v
PYTHONPATH=src python -m falsum.cli review-verified-references --ecosystem npm --package axios --version 1.5.0 --reference GHSA-wf5p-g6vw-rhxx --out constructed-axios-source-decision.json
PYTHONPATH=src python -m falsum.cli review-verified-references --ecosystem RubyGems --package rack --version 3.2.5 --reference GHSA-xj5v-6v4g-jfw6 --reference GHSA-7mqq-6cf9-v2qp --out constructed-rack-source-decisions.json
PYTHONPATH=src python -m falsum.cli review-verified-references --ecosystem RubyGems --package rack --version 3.0.5 --reference GHSA-7mqq-6cf9-v2qp --out constructed-rack-prerelease-uncertainty.json
```

On Windows PowerShell, use `$env:PYTHONPATH = 'src'` in that terminal session, then remove the `PYTHONPATH=src` prefix from each Python command. If `python` is not your Python 3.11+ executable, substitute `python3` or `py -3`.

Each CLI writes a **new file only** and deliberately refuses to overwrite an existing output. Change the filename or delete the old local output before repeating. This avoids silent mutation of a reviewer result.

### Expected outcomes

| Check | Expected |
| --- | --- |
| Local Phase 5AB adversarial unit tests | Exit code 0 |
| Original receipts authenticated against fixed Git blobs | 12/12 |
| Explicit canonical request **and** matching reported receipt Intent | 2 |
| Canonical-reported receipt on a noncanonical direct request | 2 |
| Successful responses whose receipt Intent is not canonical | 6 |
| Failed records without a successful receipt | 2 |
| Identical exact canonical requests answered by different reported Miners | 0 |
| Six original reviewed GHSA Git files authenticated | 6/6 |
| Local constructed lodash 4.17.15 references displayed / suppressed | 5 / 1 |
| New and separately frozen reviewed Axios/Rack Git blob identities authenticated | 3 / 3 |
| Constructed npm Axios 1.5.0 reference | VERIFIED_APPLICABLE |
| Constructed RubyGems Rack 3.2.5 older/newer references | VERIFIED_INAPPLICABLE / VERIFIED_APPLICABLE |
| Constructed RubyGems Rack 3.0.5 prerelease range | INSUFFICIENT_EVIDENCE |
| New qualified independent source labels from these examples | 0 |
| Historical snapshot counts as current advisory completeness | No |
| Original external Miner provenance of constructed local response | No |

These are expected **historical original source/reproduction values**. They are **not** a generalization to all of Telegraph, all Miners, all dependency advisories, or arbitrary unseen responses.

## What to challenge

A useful reviewer can do any of the following: independently open one source URL from the 12 original receipts and identify a classification mistake; independently inspect the exact affected version range inside the linked GitHub-reviewed advisory and dispute the filtering decision; identify a flaw in the strict hash/Intent matching rule; reproduce the workflow on an independent fork and share a genuine failure; or integrate the public-safe metadata in a prototype and explain an unhandled case.

If the captured original request and receipt differ, **do not** interpret that as fraud by a Miner or the PR Guard publisher. The folder may reflect the intended task category rather than the receipt. FALSUM's evidence concerns **comparability**, not an accusation.

Failures: a network/TLS error during original public fetch is **not a source-validity failure**; distinguish transport failures from hash mismatches. GHSA coverage is pinned to six original historical files, not an exhaustive current vulnerability feed. No onchain settlement is independently verified. The first-party CI proves the implementation runs; it cannot replace external reviewer expertise.

## Two copy-paste falsification recipes (Phase 5AF)

These **constructed local challenges** are safe and require no account, payment, network request or file edits. They run against the actual classifier and byte-lock verifier, and intentionally do **not** count as genuine external Miner outcomes or independent reviewer adoption.

From the repository root, after setting Python's module path as in Option B, run each recipe:

```bash
python examples/reviewer_challenges.py --challenge direct-vs-routed
python examples/reviewer_challenges.py --challenge tampered-lock
```

Expected assertions:

1. `direct-vs-routed` changes **only** the constructed capture URL from `/engine/v1/ask` to `/engine/v1/ask/77003`. Even though the request body and receipt still say `SECURITY_REVIEW_GENERAL`, classification must switch from canonical routed to **direct**. Both constructed observations must keep `original_source_verified_by_git_blob=false`.
2. `tampered-lock` copies the **real locally pinned lock** into a disposable temporary directory, appends one byte to the copy and requires the frozen verification to raise `ComparabilityError`. The tracked original remains untouched.

Both commands must exit `0` and print `PASS` lines. Exit `1` or a traceback is a challenge failure worth reporting. On PowerShell, first set `$env:PYTHONPATH = 'src'` and run the same two `python` commands. These recipes are also executed on the public reviewer GitHub Action and tested automatically on the Windows CI path.

Reviewer CI now pins the exact `actions/checkout`, `actions/setup-python` and `actions/upload-artifact` commits and a specific Python patch version; its pull-request trigger covers `src/falsum/**`, all `data/**`, `examples/**`, and `tests/**`. The standalone Windows workflow separately verifies common `core.autocrlf=true` behavior. Other research workflows are not covered by this limited action-pin audit.

## How to report an independent result

Use [Independent public reproduction / challenge](https://github.com/Iniwura/falsum/issues/new?template=independent-public-reproduction.yml). Attach a **real workflow run link** or exact commands, environment and exit status; the specific source URL/lines or output field; whether the reported counts matched; any discrepancy and its practical effect. All opinions and negative outcomes are welcome. Do not publish secrets or hidden evaluation prompts. Public feedback may be reviewed and incorporated but is **never automatically promoted to independent expert gold**.

For the original source and detailed method, see [Phase 5AB external receipt audit](PHASE5AB_EXTERNAL_RECEIPT_COMPARABILITY.md), [Phase 5AA offline advisory reference validation](PHASE5AA_OFFLINE_REVIEWED_SOURCE_BUNDLE.md) and [Phase 5AG cross-ecosystem reviewed references](PHASE5AG_MULTIECOSYSTEM_REVIEWED_REFERENCE_EVALUATOR.md). The official Telegraph [evaluation material guidance](https://docs.telegraphprotocol.com/docs/bounties/evaluation-material) distinguishes public evidence from formal acceptance or canonical network ranking.

**Hackathon disclosure:** This project is competing for prizes in Telegraph Season II. Participation and feedback here should be genuine and uncompensated; no likes, stars, artificial traffic, paid testing or endorsements are requested. The official submission has not yet been filed.
