# Phase 2Z — Real installed aiohttp runtime, source-to-route evidence

**Verified 1 November 2026. Controlled framework integration, not a security accuracy benchmark.**

## Why this experiment

The previous Phase 2Y Python analyzer correctly checked narrow import declarations and call syntax but deliberately declined to claim a real imported package, production call execution or library-version identity. Phase 2Z tests that boundary using a **real installed framework** and three deliberately controlled application source files. We now have concrete real runtime observations for these small fixtures without trusting a model's preferred essay.

CVE-2024-23334 / [GHSA-5h86-8mv2-jq9f](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-5h86-8mv2-jq9f) affected historical aiohttp versions older than **3.9.2**, with the risky static route configuration involving \`follow_symlinks=True\`. The official patched release for that advisory is 3.9.2. The pilot pins **aiohttp==3.10.11**, a later patched version, and does not attempt to reproduce the older vulnerability. Importantly, using \`follow_symlinks=True\` on a *patched* version does not by itself prove exploitation; it can still be a risky configuration depending on how a filesystem and application are deployed.

## Exact, limited implementation

[Three controlled application fixtures](../examples/phase2z_runtime_pilot/) each register a real aiohttp StaticResource route using a real imported \`aiohttp.web.Application\`. They contain:

- \`secure_static.py\`: a literal \`follow_symlinks=False\`.
- \`permissive_static.py\`: a literal \`follow_symlinks=True\` on the **patched** framework, without any CVE reproduction.
- \`dynamic_static.py\`: a module variable whose runtime value is False, which our static AST correctly classifies as **UNDETERMINED**, not automatically False.

The [Phase 2Z runtime pilot](../src/falsum/phase2z_runtime_pilot.py) is restricted to these exact three module names and full expected source file paths. Its [immutable research contract](../data/phase2z-aiohttp-pilot-contract.json) pins actual Git source blob SHA-1 identifiers for all three Python source files and for the harmless public test asset. Before import, it checks the byte-exact Git hashes to **reject altered executable source**. During evaluation it also computes independent SHA-256 whole-file evidence and checks the source AST node hash.

After importing the actual installed \`aiohttp==3.10.11\` package, the pilot verifies package version both via \`aiohttp.__version__\` and Python's installed distribution metadata; confirms the registered object is exactly the real aiohttp Application and its route is exactly a StaticResource; inspects the route's actual stored boolean \`_follow_symlinks\`; records SHA-256 of the installed \`aiohttp.web_urldispatcher\` source file; and performs two genuine HTTP calls on 127.0.0.1 using \`aiohttp.test_utils.TestServer\` and \`TestClient\`:

1. \`GET /assets/public.txt\` must return **200** with the exact checked-in public asset bytes.
2. \`GET /assets/not-a-file.txt\` must return **404**.

This runs for all three source fixtures, for **six actual loopback HTTP requests total**. There is **no external HTTP request**, no public listening address, no scanned production host and no attempt to retrieve private files. The code never accepts arbitrary application modules for runtime import. The exact installed dependency set is archived with each CI run via \`pip freeze\`; the **aiohttp top-level package is exact-version pinned**, but not every transitive package is hash-locked, so this is not a fully reproducible supply-chain-attested dependency lock.

### Actual observed outcome

[Successful actual CI run 41289904581](https://github.com/Iniwura/falsum/actions/runs/41289904581):

| Source fixture | Static Phase 2Y implication | Real patched aiohttp route flag | Loopback HTTP |
| --- | --- | --- | --- |
| Explicit False | SYNTACTIC_ABSENT | False | 200 normal, 404 missing |
| Explicit True | SYNTACTIC_PRESENT | True | 200 normal, 404 missing |
| Variable-controlled False | UNDETERMINED | False | 200 normal, 404 missing |

All three module/source pairs matched, all route flags were observed through the **actual imported framework**, and the dynamic third sample was **not given fake static certainty**.

The final workflow completed **15 Phase 2Z provenance/contract tests**, **28 Phase 2Y binding tests**, and **12 Phase 2Y claim-guard tests**, for **55 focused passing tests**. Prior foundation and official Telegraph data gate runs also remained green. One earlier failing adversarial test exposed a surplus-contract-field bypass; it was fixed, reverified and is part of the final passing result. Source fixture hash pins were further hardened so tampered runnable files fail before import.

[Actual runtime report and pip freeze artifact 13076666791](https://github.com/Iniwura/falsum/actions/runs/41289904581/artifacts/13076666791). Artifacts are time-limited, so the observed facts are also preserved in [permanent evidence](../evidence/phase2z-2026-11-01.json).

## Local reproduction

Only run the checked-in source-owned FALSUM fixture modules, in a disposable Python 3.11 virtual environment. From the repository checkout:

~~~bash
python -m venv .venv-phase2z
source .venv-phase2z/bin/activate
python -m pip install 'aiohttp==3.10.11'
PYTHONPATH=src python -m falsum.phase2z_runtime_pilot \
  --contract data/phase2z-aiohttp-pilot-contract.json \
  --catalog data/phase2w-applicability-rules.json \
  --old-queue data/real-fix-queue.json \
  --train-queue data/real-fix-train-candidates.json \
  --fresh-spec data/phase2u-fresh-transfer-cases.json \
  --root . \
  --out /tmp/falsum-phase2z-local-runtime.json
~~~

This does NOT support arbitrary reviewer-submitted code execution. For a real third-party application, we would first need explicit sandboxing, dependency resolution, provenance and execution authorization plus a reviewed non-production data environment. The current pilot cannot claim that.

## What the pilot does NOT prove

- It does not test a historically vulnerable aiohttp version, reproduce directory traversal or confirm any vulnerability.
- It does not establish that the three fixtures generalize to a separate third-party application.
- It does not prove attacker-controlled inputs can reach a production static route.
- A literal \`follow_symlinks=False\` in one installed test route does **not** establish overall application security; one module's \`True\` on a patched release does not establish this historical CVE.
- It does not create independent expert-reviewed security preference labels, independent model-quality results, actual eligible Telegraph evaluations or network registrations.

**Confirmed exploited apps: 0. Human-reviewed ground truth labels: 0. Accepted Anjoman evaluation rows: 0. Registered evaluators: 0.**

## Next evidence worth collecting

The next meaningful step is a **separate, consented and independently reviewable public application or upstream integration test** with pinned source revision, verified package environment and bounded runtime traces. The best evaluation would distinguish candidate and negative cases using actual application behavior with an independent human reviewer adjudicating any gray areas. Do not train or submit on the strength of these three controlled fixtures.
