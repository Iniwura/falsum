# Phase 4G — source-specific security reasoning without the wording shortcut

**Telegraph Season II · Evaluators · SECURITY_REVIEW_GENERAL**

## Motivation

Our [internal AI adversarial review #32](https://github.com/Iniwura/falsum/issues/32) found a serious weakness in the previous seven public A/B questions: a lexical heuristic favoring answers with fewer universal claims agreed with all **7/7 researcher-preferred answers** without reading source. Letter swapping does not remove this shortcut.

Phase 4G adds **14 newly authored code-specific conditions** across the same seven previously published source projects, with two answer choices and both A/B positions (28 displays). The cases are new author-written research questions, **not 14 new independent expert labels, new source projects, a sealed test set or accepted Anjoman rows**.

| Previously studied upstream patch | Two harder reasoning conditions |
| --- | --- |
| Requests | HTTPS prepared-request Proxy-Authorization exclusion versus HTTP inclusion |
| Jinja | Missing attribute returns undefined; existing attribute routes through environment sandbox lookup |
| Axios | Absolute URL with configured baseURL and allowAbsoluteUrls=false versus omitted flag |
| Starlette | Matching-prefix sibling path excluded by commonpath versus real child allowed |
| urllib3 | Lowercase Authorization stripping versus custom removal-list replacing defaults |
| Django | Long-input recursive risk versus historical three-digit leading-comma formatting regression |
| Express | Backslash retained in malformed authority-like prefix versus encoded in path portion |

Each question refers to a previously verified immutable Git source commit and regression-test file. It presents two plausible, similar-length answers. The generated reviewer casebook contains answer text hashes, upstream citations and original and reversed display order, **but no independently approved gold label**.

## Reproducibility

The [Phase 4G CI workflow](../.github/workflows/phase4g-source-reasoning.yml) does the following:

1. Re-verifies eight immutable, **real upstream Git commits**, source-file blobs, test-file blobs, and patch digests using the existing Phase 3F verifier.
2. Generates 14 source-specific researcher-written conditions with seven preferred A and seven preferred B answers, both presentation orders and no label promotion.
3. Executes **isolated source-derived microprobes** in Python and Node. They cover relevant Python standard-library path and regex behavior, Requests/Jinja/urllib3 branch decisions and small Axios/Express logic analogues.
4. Compares the old wording-only heuristic against author hypotheses, explicitly reporting that its agreement is **not model security accuracy** and not independent evidence of correct labels.

Microprobes **are not upstream integration tests**. We do not claim to run full published library versions, real production exploits, a Telegraph model, or an external expert security audit. The pinned upstream security-fix and regression-test *files* are verified separately from these isolated reproductions.

### Commands

Requires Python 3.11+, Node 22, and public GitHub connectivity for source verification.

~~~bash
PYTHONPATH=src:tests python -m unittest discover \
  -s tests -p test_phase4g_reasoning_puzzles.py -v
PYTHONPATH=src python -m falsum.phase4g_safe_microprobes
node tests/browser/phase4g_source_logic_microprobes.cjs

PYTHONPATH=src python -m falsum.phase3f_multifamily_material \
  --old-queue data/real-fix-queue.json \
  --train-queue data/real-fix-train-candidates.json \
  --catalog data/phase2w-applicability-rules.json \
  --out /tmp/falsum-phase4g-source.json

PYTHONPATH=src python -m falsum.phase4g_reasoning_puzzles \
  --source /tmp/falsum-phase4g-source.json \
  --out /tmp/falsum-phase4g-casebook.json \
  --diagnostic /tmp/falsum-phase4g-wording.json
~~~

All outputs are write-once; use new file paths to rerun.

## What the seven upstream tests really establish

- **Axios:** The historical added unit test does not configure baseURL, so it does not reach the central option branch. We now make that branch itself a question rather than pretending the original test demonstrated it.
- **Requests:** The pinned regression tests scheme-specific Proxy-Authorization handling, not a full HTTPS redirect and proxy-integration journey.
- **Django:** The historical recursion fix is genuine but introduced a formatting regression for some three-digit multiples; that regression was subsequently fixed. We do not claim a modern unpatched vulnerability.
- **Jinja, Starlette and urllib3:** The original regression-test files more directly exercise the relevant sandbox, sibling-directory or cross-host credential-stripping security boundary.
- **Express:** The upstream location parser has substantial malformed-URL tests, though its denied-host branch is not an independently validated application integration.

The cases are about precise **source semantics and test completeness**, not CVE lookup alone.

## Remaining first-place gates

Phase 4G is an important research-quality improvement, **not** evidence that a new model outperforms anyone. To measure actual evaluator improvement, we still need a separate genuinely project-disjoint test set, independent adjudication where possible, fixed model scoring through the real official Telegraph Foundation runtime, and honest comparisons against baseline heuristics on exactly the same gold-labeled cases.

The original LoRA failure remains 3/6 narrow source facts and 0/3 complete version reversals. There are **zero confirmed independent expert labels**, no registered improved evaluator and no new eligible Anjoman rows from Phase 4G. Actual final H2 submission remains pending, with an official deadline of December 1, 2026 at 23:59 UTC.

No code-comment label, CI pass, AI internal reviewer opinion or self-generated fixture score substitutes for independent adjudication.
