# Five-minute independent reviewer route

This is the shortest useful FALSUM check. It needs Python 3.11+, public
network access to pinned GitHub blobs, and no wallet, API key, payment or
model download.

From a fresh clone:

```bash
git clone --depth 1 https://github.com/Iniwura/falsum.git
cd falsum
PYTHONPATH=src python -m unittest tests.test_phase5bp_public_answer_quality -q
PYTHONPATH=src python -m falsum.cli audit-public-answer-quality --out reviewer-answer-quality.json
```

On PowerShell:

```powershell
git clone --depth 1 https://github.com/Iniwura/falsum.git
Set-Location falsum
$env:PYTHONPATH = 'src'
python -m unittest tests.test_phase5bp_public_answer_quality -q
python -m falsum.cli audit-public-answer-quality --out reviewer-answer-quality.json
```

Expected result: six public PR Guard response blobs are authenticated; the
source-bound policy reports 18/24 checks passed, fully supports 2/6 complete
actions, and holds 4/6 incomplete responses for review. Open the JSON and
inspect one row's `target_code_sha256`, `claimed_rules`, exact-evidence count,
recommendation count and action. The controls count only a raw verdict or
finding presence, so a confident but incomplete answer must not become a
production action.

The provider roster is frozen to PR Guard commit
[`99d2e3c93890a8fc083947bde4f21217516b7a5f`](https://github.com/anvithagowda098/pr-guard/tree/99d2e3c93890a8fc083947bde4f21217516b7a5f).
This is public-provider evidence and a bounded static-pattern audit, not human
AppSec gold, a blind holdout, independent adoption, a Telegraph ranking or a
paid transaction. A reviewer can report a mismatch or negative finding in the
public [independent review issue](https://github.com/Iniwura/falsum/issues/25).
