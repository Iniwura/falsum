# Phase 5AU — Solana Anchor advisory coverage

**Target:** SECURITY_REVIEW_GENERAL evaluation material supporting Solana application dependency review. Mission 14 relevance: security intelligence used by on-chain applications. This is not an Apps & Agents entry, mainnet purchase, deployed Solana program, or accepted integration. Separate eligibility under any Solana-specific announcement remains unverified.

## Original public evidence

- [Anchor maintainer advisory GHSA-c6rc-8jpp-2fgc](https://github.com/otter-sec/anchor/security/advisories/GHSA-c6rc-8jpp-2fgc).
- [RustSec RUSTSEC-2026-0144](https://rustsec.org/advisories/RUSTSEC-2026-0144.html), which identifies affected anchor-lang versions starting at 1.0.0 and patched versions starting at 1.0.2.
- [Pinned GitHub-reviewed record](https://github.com/github/advisory-database/blob/620ebeed9f80c494459e0d84d9a1d5bbd25c9796/advisories/github-reviewed/2026/05/GHSA-c6rc-8jpp-2fgc/GHSA-c6rc-8jpp-2fgc.json).
- [Advisory-cited affected source](https://github.com/otter-sec/anchor/blob/5ff3f96eeda91cc54b7fa525631eb8c1394fda04/lang/src/accounts/program.rs) and [upstream fix](https://github.com/otter-sec/anchor/commit/3eb1fb0427d4fed0e944b627aef76db651a93aab) with original regression test definitions. No upstream Rust test was executed by this contribution.

## What is measured

The immutable protocol was [committed before implementation](https://github.com/Iniwura/falsum/commit/7480a00030c12e70c012fc1814a2c4fc1cf41588). It fixes three original Git blob identities and twelve author-constructed queries: affected, patched, before introduction, hypothetical later versions, wrong package/ecosystem, unknown advisory, prerelease, unresolved range and missing version. Cases are exact query inputs, not observed Miner outputs or evidence that those version numbers were published. The naive citation-only baseline has the same reference and target inputs but ignores package/version. Expected 3/12 versus 12/12, with nine unsupported applicable decisions versus zero; pending actual CI. A range-aware reference baseline would be equivalent to the bounded evaluator. This is new Rust/Solana advisory coverage, not general security intelligence accuracy or network ranking improvement.

## Reproduce without keys

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_phase5au_solana_anchor_evidence.py' -v
PYTHONPATH=src python -m falsum.phase5au_solana_anchor_evidence --out solana-anchor-report.json
```

This fetches original public source bytes and verifies Git blob identities; it outputs only source pointers and per-case decisions. The report authenticates original upstream test definitions but does not claim runtime results. Inapplicable means only that this pinned advisory does not apply to the supplied exact version; it is never security clearance. This does not inspect a live program, verify dependencies of a deployed binary, prove coverage of all Anchor advisories, or run a transaction. No model inference, independent adoption, paid intelligence purchase, or expert human labels claimed. Existing FALSUM historical measurements unchanged.
