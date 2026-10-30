# Phase 2f — 32 pinned advisory families: research-only boundary challenges

This checkpoint introduces a **curated queue of 32 GitHub-reviewed security advisories** (from the immutable `github/advisory-database` commit `4af30eafd57e3bd9a0b4865dee2ced6f611de33f`). They span PyPI and npm and several issue classes. The queue does **not** imply that FALSUM, a security professional, or Anjoman has independently reviewed the downstream challenge answers. A GitHub-reviewed advisory is not a review of the downstream FALSUM pairs.

The generator retrieves the exact upstream advisory files, checks each GitHub advisory ID and ecosystem/package boundary, and attempts to derive two opposing **hypothetical dependency-version checks** from each supported affected/fixed pair. It saves the raw advisory bytes, exact SHA-256, source URL, and `draft` triplets in a diagnostic-only directory. Each hypothetical version is selected from advisory range metadata and is **not a claim that the version was actually released on a registry**.

The queue partitions by full package identity, not case or superficial wording:

| Split | Advisory families | Potential draft pairs |
| --- | ---: | ---: |
| Train | 26 | 52 |
| Validation | 3 | 6 |
| Holdout | 3 | 6 |
| **Total** | **32** | **64** |

These are *upper-bound candidate counts*, not acceptance, quality-gate or runtime success figures until the pinned snapshot fetch and exact version-status audits run. The small validation and holdout samples are inadequate for a credible accuracy claim.

## Repeatable build

```bash
PYTHONPATH=src python -m unittest discover -s tests -p test_advisory_corpus.py -v
PYTHONPATH=src python -m falsum.advisory_corpus \
  data/advisory-queue.json --out build/phase2f-quarantined
```

The build **requires outbound HTTPS** to the immutable `raw.githubusercontent.com/github/advisory-database/<commit>/...` paths; it refuses redirects and oversized/unparsable advisories. It writes no code, credentials or network submissions. All outputs live under the ignored `build/` directory and are labeled `DRAFT-ONLY-*`. No model training or Anjoman upload is performed.

The pinned official Telegraph V2 kit is at `5fa5d68bbcf76aaa2093c5d0578f53462bc0e36e`. Its `--check-data` gate is run by the dedicated CI diagnostic workflow on the generated **training split only**. Even a successful result proves only that the machine-learning dataset shortcut checks were met. It does not establish expert correctness, domain novelty, model accuracy, or network acceptance.

## Human evidence-promotion checklist

1. Security specialist independently verifies the complete advisory, package range and exploit conditions, plus actual release history when relevant.
2. Reviewer assesses each hypothetical task/answer pair for technical truth, evidence sufficiency, and whether incorrect alternatives are genuinely plausible.
3. Editorial review removes templated pairs, expands coverage into genuine PRs, source code, auth/permissions, deployment context and secret leakage, and tracks surface-answer bias.
4. Freeze train/validation/holdout at the advisory **and package** family level. Holdout cases must not be inspected for tuning.
5. Run upstream data gate on approved data, then tokenizer-conformance and ModernBERT evaluation. Mark rows eligible only after actual Telegraph/Anjoman acceptance.

**Current status:** automated candidate extraction only. Zero human-reviewed pairs, no trained model, no WASM scorer, no network acceptance. The goal of this milestone is to verify whether a reproducible, source-traceable corpus can clear the basic minimum size without faking approval.
