# Phase 5AV — original Anchor Rust regression execution

The Phase 5AU advisory evaluator is merged ([PR #110](https://github.com/Iniwura/falsum/pull/110)). Phase 5AV adds the actual upstream test execution as a separate reproducible proof. No runtime result is claimed before the CI report is verified.

The immutable lock pins the advisory-cited affected revision and upstream fixed revision, both original source files, Cargo workspace and package manifests, Cargo locks, and the Rust toolchain. The fixed source's four original Rust tests execute unchanged on the fixed revision. The identical original test module is appended to the affected source file; no affected implementation is replaced. The runner requires all four fixed tests to pass and exactly one original assertion to fail on the affected revision, with all other controls passing. A compile error, unexpected failure, missing test, or changed dependency lock is not valid evidence.

Reproduction (requires Git, Rust 1.94.1, Python 3 and network access for Cargo dependencies):

```bash
git clone https://github.com/otter-sec/anchor.git upstream-affected
git -C upstream-affected checkout 5ff3f96eeda91cc54b7fa525631eb8c1394fda04
git clone https://github.com/otter-sec/anchor.git upstream-fixed
git -C upstream-fixed checkout 3eb1fb0427d4fed0e944b627aef76db651a93aab
rustup toolchain install 1.94.1 --profile minimal
python3 src/falsum/phase5av_solana_anchor_runtime.py upstream-affected upstream-fixed runtime-evidence
```

The workflow preserves the outcome receipt and actual Rust logs. This is a local library regression experiment, not a transaction, deployed program audit, independently accepted integration, or improved network model ranking. The affected revision is the advisory-cited revision, not asserted to be the direct parent of the fix.
