# Phase 2X — Machine-derived Python AST evidence versus AppSec claims

**Verified 1 November 2026. Research-only.**

Phase 2W verified that a developer's cited application source existed at a SHA-256 and line range but could not independently check the *meaning* of that citation. Phase 2X adds a conservative local Python AST parser and claim reconciler.

## What works

[Machine AST observer](../src/falsum/phase2x_ast_observer.py) reads explicitly selected local Python files, verifies whole-file SHA-256, parses syntax without executing code, records exact call-line excerpts and AST hashes, and recognizes only three narrowly scoped patterns.

| Historical vulnerability project | Recognized call syntax | Proven *local syntax* | What is NOT proven |
| --- | --- | --- | --- |
| aiohttp | app.router.add_static with literal follow_symlinks=True or False | Literal boolean argument on this call | The receiver is actually aiohttp; call executes; full app has no other route |
| Tornado | self.set_cookie with integer max_age | Numeric integer argument on this call | Callee is Tornado; no other risky call sites; code is reachable |
| Python websockets | qualified websockets.serve with compression=None or "deflate" | Explicit local keyword value | Name is correctly imported, compression was negotiated, or the server is deployed |

Dynamic values, keyword expansion, omitted keywords, unsupported calls, unbound aliases and absent calls remain undetermined. A single local False or None does not prove application-wide absence of a vulnerability.

[AST claim reconciler](../src/falsum/phase2x_reconcile.py) recomputes the AST from live source and refuses forged machine reports. It compares machine observations against submitter assertions **only if both cite the same source file SHA, line intersection and requirement**. A contradiction blocks that claim for human review; matching source syntax never promotes a claim to independently validated security fact.

## Local usage

Create a Python application file (e.g., app.py) containing:

~~~python
app.router.add_static("/assets", "/var/www/assets", follow_symlinks=False)
~~~

Create selection.json:

~~~json
{"status":"EXPLICIT_AST_FILE_SELECTION_UNREVIEWED","files":["app.py"]}
~~~

Run the AST observer from a FALSUM repository checkout:

~~~bash
PYTHONPATH=src python -m falsum.phase2x_ast_observer \
  --catalog data/phase2w-applicability-rules.json \
  --old-queue data/real-fix-queue.json \
  --train-queue data/real-fix-train-candidates.json \
  --fresh-spec data/phase2u-fresh-transfer-cases.json \
  --case-id real-aiohttp-static-traversal \
  --root /path/to/app \
  --paths-json selection.json \
  --out /tmp/falsum-ast-observations.json
~~~

Follow the [Phase 2W application capture instructions](PHASE2W.md) to prepare a SHA-bound submission and evidence batch. Turn the unchanged AST report into an array:

~~~python
import json
from pathlib import Path

a = json.loads(Path("/tmp/falsum-ast-observations.json").read_text())
Path("/tmp/falsum-ast-packets.json").write_text(json.dumps([a], indent=2))
~~~

Run the reconciler:

~~~bash
PYTHONPATH=src python -m falsum.phase2x_reconcile \
  --catalog data/phase2w-applicability-rules.json \
  --old-queue data/real-fix-queue.json \
  --train-queue data/real-fix-train-candidates.json \
  --fresh-spec data/phase2u-fresh-transfer-cases.json \
  --batch /tmp/falsum-batch.json \
  --ast-packets /tmp/falsum-ast-packets.json \
  --root /path/to/app \
  --out /tmp/falsum-reconciled-report.json
~~~

A contradiction yields BLOCKED_AST_SYNTAX_CONFLICT_REQUIRES_HUMAN_REVIEW; a consistent observation yields UNREVIEWED_ORIGINAL_RESULT_NOT_PROMOTED. Neither confirms a real exploit or security correctness.

## Verified results

[Actual end-to-end CI run 41288248962](https://github.com/Iniwura/falsum/actions/runs/41288248962) passed 49 tests: 20 AST/claim adversarial tests, 20 original proof-gate tests and 9 real excerpt-capture tests. Tested dynamic arguments, absent keywords, shadowing ambiguity, malformed Python, forged AST packets, stale files, tampered quotes, path escapes, symlinks and exact citation overlap.

The illustrative application falsely asserted that aiohttp follow_symlinks was enabled. FALSUM read the source, verified SHA-256, independently parsed its actual call with False, and blocked the unsupported claim for human review. The claimed application was an illustrative fixture, not a real production audit.

[Original execution and machine-evidence artifact](https://github.com/Iniwura/falsum/actions/runs/41288248962/artifacts/13075957276) is retained temporarily.

## Boundary and next step

Phase 2X proves narrow *source-syntax* facts, not runtime call identity, library versions, data flow, reachability, exploitability, whole-app safety, or expert quality. Developer-submitted assertions are unreviewed even when their quotes are authentic.

The next upgrade is verified Python import/name resolution and bounded call-site reachability for one framework, including false-positive controls, before attempting new model training. Current Phase 2X has **zero expert-reviewed labels, zero confirmed exploits, zero accepted Anjoman evaluation rows and no registered Telegraph evaluator**.
