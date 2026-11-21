# Phase 5U — Four new public upstream security-fix projects

**FALSUM · Telegraph Season II / Evaluators / SECURITY_REVIEW_GENERAL · November 21, 2026**

## Purpose

FALSUM's previous source-sensitivity tests used four familiar historical projects (PyJWT, Werkzeug, MCP Python SDK and Pillow). Our 80-item and 30-item benchmarks also admitted source-blind shortcuts. This stage addresses **new-source coverage**, not a prettier score.

Four previously unused upstream repositories were selected, with immutable original Git tags and their real source and upstream test files. The original code and upstream tests are downloaded from the exact Git commits and the **full original Git blobs** verified before generating any challenge prompt.

| Project | Original vulnerable tag → patched tag | Security family | Original upstream code / test |
| --- | --- | --- | --- |
| [minimist](https://github.com/minimistjs/minimist) | 1.2.5 → 1.2.6 | Constructor-prototype argument traversal | `index.js` / `test/proto.js` |
| [JSON5](https://github.com/json5/json5) | 2.2.1 → 2.2.2 | Prototype mutation through parsed object properties | `lib/parse.js` / `test/parse.js` |
| [tough-cookie](https://github.com/salesforce/tough-cookie) | 4.1.2 → 4.1.3 | Inherited domain-map keys in cookie memory store | `lib/memstore.js` / `test/cookie_jar_test.js` |
| [follow-redirects](https://github.com/follow-redirects/follow-redirects) | 1.15.11 → 1.16.0 | Custom sensitive-header stripping across redirects | `index.js` / `test/test.js` |

Advisories: [minimist](https://github.com/advisories/GHSA-xvch-5gv4-984h), [JSON5](https://github.com/advisories/GHSA-9c47-m6qq-7p4h), [tough-cookie](https://github.com/advisories/GHSA-72xf-g2v4-qvf3) and [follow-redirects](https://github.com/advisories/GHSA-r4q5-vmmm-2653).

These are **four new historical security-fix families**, not 24 independently discovered vulnerabilities.

## Frozen before model scoring

Selection and original source SHA references were committed before implementation, then the exact prompt system and source-slice policy were frozen in commit **`1e6b3a212659739365731e3e8d452ecd96c90ffa`**, Git blob SHA-1 **`ff1e9063f0f37e0a9265db25d6f767bb56db73e8`**.

The 24 questions comprise **16 code-present** and **8 code-omitted** conditions: four projects × (affected and fixed revision) × (original and swapped A/B order), plus missing-source controls with each answer order.

A correct answer changes when the supplied authenticated source changes; it must also adapt to the placement of the possible answers. A source-blind strategy that sees the neutral question and answer statements but **not** the source file can obtain at most **16/24** reference matches, with **0/4 complete correct four-way source-and-answer swaps**. This bound is *prompt-only*: the full casebook, Git commits, repository code and references are public, so a participant with source lookup can cheat. It is neither a secret holdout nor an evaluation of model generalization.

The reference facts are researcher-authored descriptions of the **original published source behavior**. The full original upstream regression **test files are SHA-verified, not executed** by this stage; upstream tests are only cited as provenance, not passed off as new FALSUM runtime proof.

## Reproduce

Python 3.11–3.13, public internet, no model key, wallet, paid Telegraph request or private dataset:

~~~bash
git clone https://github.com/Iniwura/falsum.git
cd falsum
python -m pip install --no-deps -e .

# Reads 16 original upstream Git assets and verifies exact Git blob SHA-1.
falsum score-new-source-projects export \
  --questions-out original-24-new-code.json \
  --template-out empty-candidate-decisions.json \
  --source-proof-out immutable-source-and-test-links.json

# Publicly disclosed synthetic source-blind shortcut:
falsum score-new-source-projects baseline --out source-blind-control.json

# Use genuine predictions from an independently chosen candidate:
falsum score-new-source-projects score \
  --questions original-24-new-code.json \
  --predictions my-real-model-answers.json \
  --out candidate-score.json
~~~

The exported template requires all 24 decisions `A`, `B` or `ABSTAIN`. Inputs are bound to the exact original Git-verified challenge SHA, cannot be reordered or inflated with labels, and outputs are write-once. User-supplied responses are marked **unverified external candidates**, never independent verified expert gold.

## Authenticity and reproducibility

The original CI [Phase 5U workflow](../.github/workflows/phase5u-disjoint-upstream-source-test-provenance.yml) must pass the Python 3.11–3.13 adversarial tests and fetch all 16 original source/test revisions. The report records upstream URL, full original SHA-1 code and test blobs, shortened code-excerpt SHA-256 and original commit. An unreachable source, malformed provenance or mismatched blob **fails closed**.

### What this proves

- Four additional **previously unused project families** have original historically affected/fixed Git source and security-test material suitable for independent source-reasoning evaluations.
- Source-role and answer-position counterfactuals make constant answer strategies fail the full reversal metric.
- A public reviewer can independently download upstream code and reproduce every input.

### What this does **not** prove

- The 16 source-present prompts are not 16 separate new vulnerabilities; there are **four** distinct fixes.
- The original upstream regression tests were not executed by this stage. Do not claim new runtime pass/fail proof.
- The source choices are public and researcher-derived, not externally independently validated AppSec gold, sealed model holdout or pretraining-disjoint model validation.
- No newly improved model, registered Telegraph scorer, same-request fair network ranking, developer adoption, commercial mission activation, new paid requests or official submission is claimed.

Next meaningful proof: authentic execution of these exact upstream historical tests, and real independent model responses on these new prompts compared against baselines. The phase supplies the frozen source-and-test inputs required to do that honestly.

[Phase 5T production app-consumption policy](PHASE5T_FAIL_CLOSED_SECURITY_REVIEW_CONSUMPTION.md) remains separate: it tests **real application allow/deny decisions** against two original paid captures and previously authenticated executed source facts. Phase 5U addresses the **unseen project-source coverage gap**.
