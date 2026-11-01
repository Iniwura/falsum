# Phase 3A — Real independent public application source pilot

**1 November 2026. Git-verified external project source, NOT an exploit test or verified vulnerability accuracy benchmark.**

## Why we changed the evaluation set

The earlier Phase 2Z experiment genuinely executed installed, patched **aiohttp 3.10.11** against three controlled FALSUM-owned applications and observed their registered route options. The static analyzer correctly abstained on a dynamic argument, but those fixtures were authored by the FALSUM team, so they did not establish generalization to software built by someone else.

Phase 3A inspects *actual, independently maintained source code* at three public repositories, each pinned by a full commit SHA and exact historical Git file blob SHA-1. The source is fetched from \`raw.githubusercontent.com\` over HTTPS and rejected if any actual bytes mismatch. This is **no longer a synthetic source sample**. However, only Python's AST parser reads it: **none of the three outside projects are imported, executed, served, tested as running applications, or copied into the artifact**. That distinction is essential.

## Three genuinely external projects

| Application and immutable source | Source call and line | AST-level observation |
| --- | --- | --- |
| [Perspective example Python aiohttp server](https://github.com/perspective-dev/perspective/blob/444865accd46bcfdeb552960ce4f63fe8286de42/examples/python-aiohttp/server.py) | Line 47 | \`follow_symlinks=True\`, exact literal |
| Same Perspective source | Line 48 | \`follow_symlinks\` option omitted |
| [NLWeb static routes](https://github.com/nlweb-ai/NLWeb/blob/b423f15d9aeaa023ce75993ac9deed2354597043/AskAgent/python/webserver/routes/static.py) | Lines 45 and 56 | Two explicit \`follow_symlinks=False\` calls |
| [Maubot server](https://github.com/maubot/maubot/blob/f20825b5e3031a89eb5b2edea7f6f7726ada9a10/maubot/server.py) | Line 112 | \`follow_symlinks\` option omitted |

Source blobs recorded in the [machine-readable permanent evidence](../evidence/phase3a-2026-11-01.json), and also pinned independently in the checked-in [source identity contract](../data/phase3a-external-source-cases.json).

**These results are not security labels.** A Python keyword set to True establishes only that the source code contains that literal. Historical CVE-2024-23334 requires an affected aiohttp version **earlier than 3.9.2** and the relevant application/exposure facts. This phase did not establish which aiohttp version was actually installed or deployed in these three external applications. A literal False at one call site does not prove the entire application safe, and an omitted keyword is classified **OMITTED_OPTION**, not automatically False or safe. Even a trusted-looking receiver chain may be rebound; Phase 3A conservatively does not assert actual runtime call identity.

## What was verified

[The source verifier](../src/falsum/phase3a_external_sources.py) has an in-code allowlist in addition to the separate data contract. It refuses an altered Git commit, unexpected path, altered expected call, spoofed eligibility/ground-truth metadata or an attempt to switch the source to a private or arbitrary repository.

For each file, it downloads at the full immutable Git commit, checks complete content against the exact upstream Git blob hash, decodes/parses the Python source **without importing it**, and collects bounded AST call-site facts. It records whole-file SHA-256, exact line positions, hashed AST call nodes, and the literal/omitted/dynamic classification. No downloaded raw source is archived.

[Completed Phase 3A source verification CI run](https://github.com/Iniwura/falsum/actions/runs/41290675846) confirmed:

- **3 distinct public repositories** and exact verified historical Git blob bytes
- **5 real source call sites**: 1 explicit True, 2 explicit False and 2 omitted options
- **15 adversarial external-source tests**, 15 previous Phase 2Z runtime-contract tests and 3 permanent prior-runtime evidence tests: 33 passing focused checks
- Foundation tests and Telegraph's original diagnostic data gate also passed
- **0** third-party projects executed, **0** dependency versions validated in deployment, **0** human expert-reviewed labels, **0** confirmed exploits, **0** accepted Anjoman evaluation records

[Temporary verified external-source report artifact](https://github.com/Iniwura/falsum/actions/runs/41290675846/artifacts/13076967118). It records hashes and AST descriptors only, without external projects' full source.

## Run it again

From the FALSUM checkout with Python 3.11 or newer (network access is only for retrieving the three pinned, public GitHub source files):

~~~bash
PYTHONPATH=src python -m falsum.phase3a_external_sources \
  --contract data/phase3a-external-source-cases.json \
  --out /tmp/falsum-independent-sources.json
~~~

Outputs are refused if they already exist, if expected source bytes changed, if the approved source repos/commits/paths were edited or if any security verdict tries to become eligible by changing the contract.

## What remains to become a valid evaluator

The three third-party source samples improve *source diversity*, but they do not constitute a blinded or expert-labeled independent benchmark. They were identified by looking for aiohttp static routes, so there is selection bias. In particular, the source code alone does not establish version, call reachability, attacker control, actual exploitability or the correctness of proposed vulnerability verdicts.

A credible next step is to **pin third-party dependency declarations** from the same commits and carefully distinguish declared requirements from actual deployment versions. Then obtain permission and an isolated non-production environment for bounded runtime traces from a real outside application, and have an independent reviewer adjudicate any proposed security labels. Until then, this is verified external-source fact extraction, **not security model accuracy**.

FALSUM has **no accepted Telegraph/Anjoman evaluator contribution or registered live evaluator** from this work.
