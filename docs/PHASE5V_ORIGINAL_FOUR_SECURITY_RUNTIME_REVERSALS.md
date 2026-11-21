# Phase 5V — Execute the affected and fixed original security code

**FALSUM · Telegraph Season II Evaluators · SECURITY_REVIEW_GENERAL · 21 November 2026**

## Why this matters

Phase 5U authenticates eight source-file versions and eight corresponding original upstream security-test files from **four previously unexamined security-fix projects**. Verifying file hashes is useful but does not prove how the code runs.

Phase 5V goes further: it checks out the exact historical original Git commits and **executes the affected and patched code in isolated Node.js 22 processes**. Each project has a focused behavioral probe adapted from its original published regression test and a separate unrelated safe-control check. The CI only succeeds when the unsafe behavior is observed in the historical affected revision, absent in the fixed revision, and both benign controls work.

The study was frozen before writing its code probes: [pre-execution contract](../data/phase5v-preexecution-four-new-original-regression-probe.json), original commit `54f92d155b986248ce2b006f7519e156fa7d3e26`, Git blob SHA-1 `7d14b5fa125449e18557e45429a77267f60cf125`. It specifies **four exact source projects × affected/fixed = eight Node executions**, with expected vulnerable behavior before and no vulnerable behavior after each real historical fix.

## Original source-runtime probes

| Project | Focused original security behavior | Harmless baseline |
| --- | --- | --- |
| [minimist](https://github.com/minimistjs/minimist) | Nested argument constructor traversal can mutate a Function prototype property before the fix; the patched parser stops it | Normal numeric CLI flag parsing |
| [JSON5](https://github.com/json5/json5) | Assigning the `__proto__` property modifies the parsed object's prototype before the fix; the patched parser creates a normal own data property | Normal JSON5 object parsing |
| [tough-cookie](https://github.com/salesforce/tough-cookie) | Domain `__proto__` can pollute a JavaScript object during cookie storage before the fix; patched domain indices have no prototype | Normal cookie set/get in a clean isolated cookie jar |
| [follow-redirects](https://github.com/follow-redirects/follow-redirects) | A custom Sensitive-A request header remains across a local cross-host redirect before the fix; patched `sensitiveHeaders` removes it | Normal non-sensitive header forwarded and built-in Authorization stripped |

Each GitHub Actions matrix job:
1. Retrieves **exactly** the pinned upstream Git commit and checks its `HEAD` identity.
2. Recomputes the full Git SHA-1 for the actual source file **and** original upstream test file and checks both against the committed frozen manifest.
3. Runs the original library's affected or fixed implementation using a safe local focused test under Node 22; an unrelated normal-behavior control must pass.
4. Writes one machine-checkable, write-once original source runtime receipt containing only the original commit, source/test hashes, role, boolean outcome and scope limits. No sensitive header value, third-party source body or private question is archived.
5. Aggregates all eight independent receipts and rejects missing, duplicated, wrong-hash, invented-success, failed-control or mislabeled revisions before asserting four complete historical source behavior reversals.

The redirect test uses **loopback only**, not a remote host. The prototype pollution checks run in ephemeral isolated Node processes and explicitly delete the local marker in a `finally` block.

## Reproduce / audit

See [Phase 5V GitHub Actions](../.github/workflows/phase5v-original-historical-security-fix-execution.yml). The matrix itself is the reproducible command sequence: `git fetch` exact commit, `git hash-object` original code and tests, then `node tests/phase5v_original_node_security_probe.cjs` with exact revision and original hashes. The eight original results are joined by `python -m falsum.phase5v_historical_runtime_verifier --input-dir original-reports/ --out original-reversals.json`. The Python receipt verifier also has a separate strict adversarial suite on 3.11, 3.12 and 3.13.

The **actual original CI run and artifact hashes** must be documented here only after all real jobs succeed. No unit-test-generated simulated receipt can stand in for the original eight runtime executions.

## Accurate limitations

- These are **focused executable tests adapted from publicly pinned original upstream regression evidence**, not reruns of the complete original upstream test suites. The original test files have verified identity but their full suites are not claimed executed.
- Four known original historical fixes are **not** four unseen vulnerabilities or private holdout questions. This strengthens independent reproducibility of source facts, not independence of source selection.
- These probes establish narrow affected-vs-fixed historical code behavior only, **not** universal security, deployed production exploitability, model prediction quality, external AppSec gold, unbiased model comparisons or Telegraph network ranking improvements.
- No original third-party paid response body, private evaluation pool, live remote target, model training, independent adopter or registered Telegraph scoring adapter is used. No hackathon submission or demo is made.

**Next critical milestone:** use these actually verified source behaviors as supporting reference evidence in a valid independent-model comparison, then obtain fair same-request multi-miner responses and expert adjudication if available. The source-runtime proof alone cannot justify a 90+ competitive judge score.

## Verified original historical runtime execution

All **12 actual GitHub Actions jobs** passed in [the authentic original execution run](https://github.com/Iniwura/falsum/actions/runs/44902503049): three Python 3.11–3.13 verifier suites, **eight actual separate original historical Git-source Node processes**, and the final source-reversal receipt aggregator.

For each of minimist, JSON5, tough-cookie and follow-redirects, the affected historical source showed the exact expected unsafe behavior and the fixed original source did not. All **eight unrelated benign controls passed**. The exact source file and corresponding historical upstream test file SHA1 were revalidated at each checkout before execution.

The first attempted run's tough-cookie benign control was invalidated by checking the same cookie jar *after* deliberately polluting it; the check was isolated in a separate clean jar before mutation without changing the preregistered affected/fixed security assertion. This correction is covered by [the successful subsequent full matrix](https://github.com/Iniwura/falsum/actions/runs/44902503049). No failed predecessor is counted as a successful original run.

- Original GitHub Actions artifact ID **14706407714**.
- Original aggregate ZIP SHA-256: `677ffdc66ac827a6f88eafca1e5ac88e7d88b6ba3760d41ee6b9d46ae396cff9`.
- Embedded original eight-source-run aggregate JSON SHA-256: `dca4f43f8d22951111320eac59832b5511fac3f458fdee22659c040a990e03b1`.
- [Original immutable runtime evidence digest index](../evidence/phase5v-2026-11-21-actual-four-original-js-security-fix-reversals.json).

**Interpretation:** the additional source coverage now has **actual confirmed historical runtime source behavior** across all four newly selected original security fixes. These are **focused local reproduction probes**, not complete executions of every original upstream test. They are not independent expert gold or a model's source-reasoning accuracy.
