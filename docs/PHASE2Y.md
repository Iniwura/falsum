# Phase 2Y — Python import-declaration evidence and bounded call paths

**Verified 1 November 2026. Research only; not network eligible.**

## Objective

Phase 2X detected contradictory literal source code in Python calls but could not distinguish an imported aiohttp application from an unrelated object with a similar method name. That could inflate a misleading "security contradiction" report. Phase 2Y makes the reviewer **abstain** unless explicit local framework import/constructor/subclass structure can be established and a narrow syntactic invocation path is visible.

This is not general Python control-flow analysis. It is a static, fail-closed subset. The checker never executes imports or application code. A static import statement does not prove which Python package would actually load in the runtime environment; a module-level call expression does not prove the file executes in production.

## Implemented source analysis

[Static binder and call-path analysis](../src/falsum/phase2y_bindings.py) reads exactly selected Python files within an explicit application root. It verifies SHA-256 for the entire file, parses Python syntax without executing it, retains exact original lines and call AST hashes, and recognizes:

| Case | Accepted syntactic evidence | Conservative invocation classification |
| --- | --- | --- |
| aiohttp traversal prerequisite | Unshadowed top-level "from aiohttp import web" declaration (optionally aliased), followed by one un-reassigned "app = web.Application()" and "app.router.add_static(..., follow_symlinks=<literal>)" | Module-level expression call, direct zero-arg invocation of a simple local setup function, or unresolved/guarded path |
| websockets deflate prerequisite | Unshadowed top-level "import websockets" or "from websockets import serve" (optionally aliased), with a matching serve call and explicit compression keyword | Module-level/direct zero-arg function call syntax, or unresolved/guarded path |
| Tornado cookie prerequisite | Top-level "from tornado.web import RequestHandler" (optionally aliased), simple direct subclass, undecorated method and self.set_cookie with explicit max_age keyword | Framework callback invocation **unverified**, regardless of matching class name |

The original [Phase 2X literal analyzer](PHASE2X.md) remains unchanged. The new Phase 2Y bindings use its narrow literal checks but add more provenance requirements. Unsupported keyword values, keyword expansion, omitted flags, shadowed imports, reassignment, global/nonlocal rebinding, wildcard imports, exec/eval, setattr and selected module-attribute monkeypatches result in conservative abstention.

A syntactically direct module-level call is reported as MODULE_TOP_LEVEL_CALL_SYNTAX, **not executed in production**. A simple function containing a direct call, followed by exactly one unconditional top-level invocation without arguments, is classified DIRECT_MODULE_CALL_TO_LOCAL_FUNCTION_SYNTAX. If the function is not directly invoked, or it is behind a conditional/try/loop, the status is unresolved. No inter-file reachability, import loading, environment behavior or dynamic call graph is inferred.

## Claim cross-checker

[Binding-aware claim guard](../src/falsum/phase2y_claim_guard.py) replays the existing Phase 2W evidence check and **recomputes the complete Phase 2Y AST report** from the unchanged local checkout. For an exact cited source line and SHA, it only issues a localized syntax contradiction when a supported, import-backed call shape matches and has a resolved literal keyword.

This avoids false flags from impostor objects. Examples:

- An explicitly imported aiohttp web.Application object used in a local route setup call with literal follow_symlinks=False, while a developer claims that call's flag is enabled: STATIC_SYNTAX_CONTRADICTION_HUMAN_REVIEW_REQUIRED.
- An unrelated dummy.router.add_static call with the same literal False and the same developer claim: ABSTAIN_NO_BINDING_QUALIFIED_CONTRADICTION.
- An imported aiohttp setup function defined but never directly called from module-level statements: UNRESOLVED_STATIC_INVOCATION_PATH.
- A dynamic follow_symlinks=config.enabled expression: DYNAMIC_OR_UNDETERMINED_AST_LITERAL.

Even when a declaration is strongly supported, the output explicitly sets actual_framework_runtime_binding_verified=false, actual_exploits_proven=0, human_approved_labels=0 and network_eligible=false. The result is a research-only **local syntactic review flag**, not a vulnerability verdict or proof that a route is exploitable.

## Reproduce locally

From the FALSUM checkout, create selection.json:

~~~json
{"status":"EXPLICIT_AST_FILE_SELECTION_UNREVIEWED","files":["app.py"]}
~~~

Analyze a selected application file (change the case ID to one of the three supported Phase 2X cases):

~~~bash
PYTHONPATH=src python -m falsum.phase2y_bindings \
  --catalog data/phase2w-applicability-rules.json \
  --old-queue data/real-fix-queue.json \
  --train-queue data/real-fix-train-candidates.json \
  --fresh-spec data/phase2u-fresh-transfer-cases.json \
  --case-id real-aiohttp-static-traversal \
  --root /path/to/application \
  --selection selection.json \
  --out /tmp/falsum-phase2y-bindings.json
~~~

First generate an unreviewed, hash-verified claim manifest using the [Phase 2W capture workflow](PHASE2W.md), then embed that exact manifest in an application batch. For the guard, provide a JSON array containing the *unchanged* static binding output:

~~~python
import json
from pathlib import Path

packet = json.loads(Path("/tmp/falsum-phase2y-bindings.json").read_text())
Path("/tmp/falsum-phase2y-packets.json").write_text(json.dumps([packet]))
~~~

~~~bash
PYTHONPATH=src python -m falsum.phase2y_claim_guard \
  --catalog data/phase2w-applicability-rules.json \
  --old-queue data/real-fix-queue.json \
  --train-queue data/real-fix-train-candidates.json \
  --fresh-spec data/phase2u-fresh-transfer-cases.json \
  --batch /tmp/falsum-batch.json \
  --binding-packets /tmp/falsum-phase2y-packets.json \
  --root /path/to/application \
  --out /tmp/falsum-phase2y-claim-review.json
~~~

The guard rejects stale source content and forged "machine verified" fields by rerunning the analysis from the application root. Input paths must be relative to the explicitly selected root, not absolute or symlinked.

## Actual CI evidence

[Verified 89-test Phase 2Y CI run](https://github.com/Iniwura/falsum/actions/runs/41289002820) passed:

- **28** direct Python import, shadowing, literal, source path, model status and bounded call-path regression tests.
- **12** binding-aware claim guard tests, including fake framework lookalike abstention and forced recomputation of supplied reports.
- **20** Phase 2X AST claim tests, **20** Phase 2W proof tests and **9** local exact-source capture tests.
- End-to-end original Python example files for aiohttp application setup, an aliased websockets serve import and a Tornado RequestHandler subclass.
- A dedicated side-by-side check: one locally import-backed aiohttp call with a false developer assertion was **flagged for review**, whereas an equivalent-looking unbound fake router call **abstained**.
- Both foundation tests and Telegraph's original diagnostic data gate passed on the implementation branch.

[Temporary source-evidence artifacts from the actual CI run](https://github.com/Iniwura/falsum/actions/runs/41289002820/artifacts/13076218012).

## Quality constraints and next step

These 89 checks establish that the implementation behaves as designed on explicitly controlled fixtures. They do **not** measure precision, recall, exploitability, deployment reachability or correct network evaluator outcomes on real applications. No additional ground-truth annotations were gathered.

The next useful phase is a **genuinely independent application pilot** with real dependency import environments and scoped runtime instrumentation/test traces, using trustworthy reviewer feedback. Before any evaluator registration, establish independent label quality and test generalization on unrelated projects. Do not spend resources retraining the same eight AI-authored comparison pairs.

FALSUM remains research-only: no confirmed real-world exploits, no independently expert-validated labels, no accepted Anjoman evaluation rows and no registered Telegraph evaluator.
