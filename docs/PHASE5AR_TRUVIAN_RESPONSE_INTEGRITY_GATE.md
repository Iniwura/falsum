# Phase 5AR — external developer feedback to executable response-integrity gate

[Truvian Shield's maintainer](https://github.com/Iniwura/falsum/issues/97#issuecomment-7132041935) checked two historical fixtures against their stored memos and confirmed the parsed fields: the first lacked code and issues; the second lacked code but listed an issue despite a Secure/zero-count response. These are developer-parsed fields, not raw HTTP captures. This independently corroborates FALSUM's findings, not adoption or an integration.

## Direct comparison, not a claim of model accuracy

Re-fetch the already pinned original Truvian test file. Parse **all nine direct security fixture declarations** with a restricted literal grammar; one original spread is explicitly resolved. The set includes the two maintainer-confirmed answers, a third reported live response with node-shaped fields, other scan/review fixtures, a derived generic regression and a constructed honeypot regression. Nine declarations do not mean nine distinct live requests. The source was inspected before implementation.

The original inspected third missing-source record is `securityWethTxLensLive`: Secure/count three, with the published fixture explicitly noting node shaping. On the three explicitly missing-code cases, the verified retrospective comparison ([successful original-source CI replay](https://github.com/Iniwura/falsum/actions/runs/45476259143); PR #106 passed 21/21 checks and merged):

| Consumer policy | Clean candidates on missing-code cases |
| --- | ---: |
| Verdict only | 3/3 |
| Secure + count zero | 2/3 |
| Response integrity gate | 0/3 |

The gate also routes issue-bearing Secure answers to review rather than erasing the reported concerns. This does **not** claim that issue count is the vulnerability count, that a listed informational concern is an actual vulnerability, or that FALSUM is superior to Shield's own existing guard. Its original app guard belongs to Truvian. A generic answer without an explicit missing-code phrase can still slip through; the gate does not implement target identity or semantic review. Negative verdicts stay flagged. A clean candidate never grants security clearance.

## Use the portable integration entrypoint

```bash
PYTHONPATH=src python -m falsum.phase5ar_response_integrity --out phase5ar-report.json
printf '%s' '{"verdict":"Secure","vulnerability_count":0,"issues":["Reported issue"],"summary":"The supplied source was reviewed."}' | PYTHONPATH=src python -m falsum.phase5ar_response_integrity --stdin
```

No install, token, model or payment. A JSON object with decision and reasons is printed. Downstream callers may route REVIEW into their existing review/second-opinion workflow and FLAG into their established escalation path. CLEAN_CANDIDATE means only that these bounded checks did not identify a contradiction; it must never auto-release funds or approve a contract. Missing or malformed JSON is an error; a caller must fail closed on nonzero exit.

The 129-case historical benchmark remains unchanged and ties verdict-only on its published labels. This new measurement is response-integrity coverage on original, deliberately selected historical app fixtures; it is not a blind holdout, qualified expert gold, proof of ranking improvement, new inference, or independently accepted integration.
