# Phase 5AE — Windows raw-byte source lock reproducibility

**FALSUM · 21 November 2026 · Second outside technical review (privately supplied)**

## Review evidence and confirmed defect

The project owner supplied a second detailed technical review. The reviewer reported Windows 11 / PowerShell 7 / Python 3.12, auditing git commit `544d902`. They reported **two failing source-lock unit tests** when cloning with `core.autocrlf=true`, and a broader local discovery result of **144 errors and 6 failures across 1,061 tests**, before resetting to LF and observing 13/13 original targeted tests pass.

The review text contains the reported failure trace and before/after lock hashes, but no independently attributable GitHub fork/workflow URL, commit-level diff, test artifact or public review identity. Thus its reproduction numbers are *reviewer-reported*, not automatically independently authenticated. The independently verifiable defect in the source tree is that no root `.gitattributes` file previously existed, while `phase5ab_original_receipt_comparability.frozen()` hashes `(root / LOCK).read_bytes()` against its exact published Git blob fingerprint.

Git for Windows can replace `LF` with `CRLF` at checkout. The resulting working-tree bytes no longer match the immutable repository Git blob and cause a **false provenance-integrity failure** on Windows even though the committed Git source was unchanged.

## Fix (no relaxed validation)

The new repository-root [`.gitattributes`](../.gitattributes) makes all detected text files checkout as LF, with explicit `*.json`, `*.py`, `*.md`, `*.yml`, `*.yaml`, `*.toml` and other text source rules. Git still treats binary files as binary. The historical raw-byte `Git blob SHA-1` and pinned source locks remain mandatory and unchanged: **no Unicode normalization, line-ending normalization inside the verifier, skip-if-Windows exceptions, hash overrides, or bypass flags** are introduced.

The [new Windows CI workflow](../.github/workflows/windows-lf-original-source-replay.yml) intentionally configures `git config --global core.autocrlf true` **before** `actions/checkout` on `windows-latest`. It:
1. Asserts Git's actual `eol: lf` effective checkout attribute for representative source and lock files.
2. Inspects their raw bytes and refuses a CRLF worktree lock.
3. Recomputes the locked Git blob SHA-1 from the actual Windows checkout and compares it to the unchanged original fingerprint.
4. Runs the *same targeted Phase 5AB unittest command* the reviewer reported failing.
5. Runs historical Phase 5Y, Phase 5Z and Phase 5AA regression suites and the complete stdlib unittest discovery suite, requiring zero failures.

The CI should be interpreted as **first-party Windows technical verification**, not a public independent developer's fork run. A genuine reviewer-owned fork run with URL, original SHA and output hashes remains the next stronger evidence.

## Existing Windows clones

A fresh `git clone` from a commit containing `.gitattributes` will apply the LF policy. A clone that was created before the fix may already have CRLF in checked-out files. The safest retry is a **fresh clone to a new folder** after this commit is merged; do not run `git reset --hard` over a working directory containing uncommitted work. The targeted command remains:

```powershell
$env:PYTHONPATH = 'src'
python -m unittest discover -s tests -p 'test_phase5ab_original_receipt_comparability.py' -v
```

The CLI still requires the usual network only when replaying the externally Git-pinned public source files; unit tests can verify the frozen local lock without network secrets, wallet access or paid provider requests.

## Other actionable second-review findings

- **Python 3.12+ syntax warning:** The literal `\` ` escape in `phase5n_published_candidate_runner.parse_choice()` was unnecessary and invalid. Remove the backslash before the backtick, preserving exact stripping behavior.
- **Historical contract vs generalized evaluator:** The exact six-reference lodash snapshot, original fixed reported Miner IDs, exact package/version and preregistered 5/1 output partition are **historical forensic assertions**, not a general-purpose dynamic security scanner. Keep them; do **not** silently loosen them to pretend new accuracy or adoption. See [separate medium-priority generalization scope](https://github.com/Iniwura/falsum/issues/89).
- **OSV range complexity:** The original Phase 5Y `semver()` and `interval()` deliberately only handle frozen three-integer component historical ECOSYSTEM intervals. Their strictness is an **explicit limitation**, not a correct generalized OSV interpreter. `src/falsum/osv.py` already has a wider `version_status` implementation (with its own fail-closed unknown behavior). Extending version handling safely requires a **separate independently tested generalized path**, including prereleases, multiple disjoint intervals, partial/unfixed source versions, update conflicts, and evidence provenance; it cannot be claimed from the original six-source replay.
- **Review provenance:** The reviewer's own Windows reproduction claim is useful and attributable to the privately shared text, but no publicly verifiable external run is available. This project should not count the internal CI as independent developer adoption, expert AppSec gold, measured unseen-case accuracy or an accepted external integration.

## Merge gate

Merge the Windows fix only if the **actual Windows checkout and targeted unit tests pass**, together with relevant existing Linux and release CI checks on the exact PR head. On `main`, inspect any completed post-merge checks and report their actual status. No production redeploy or extra paid Telegraph requests are required for this platform-focused fix.
