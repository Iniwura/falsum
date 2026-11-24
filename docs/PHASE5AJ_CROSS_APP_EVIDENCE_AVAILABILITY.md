# Phase 5AJ — cross-application security evidence availability

**In progress: author CI must authenticate and replay the frozen originals before any new measured outcome is claimed.** This is an Evaluators contribution for `SECURITY_REVIEW_GENERAL`; not a new Apps & Agents entry.

## Real downstream failure and contribution

Two separate Season II Mission 14 applications have publicly reported meaningful security-intelligence failures. [Truvian Shield's progress](https://github.com/telegraphprotocol/bounties/issues/202#issuecomment-7050330386) describes a ranked answer saying Secure while admitting it did not receive code to review. Its developer already fixed the app's guard. [Gig Guard's progress](https://github.com/telegraphprotocol/bounties/issues/202#issuecomment-7060546474) records missing security-review responses during planted-bug ship-gate testing, including the developer's own parser improvement. Those are the developers' results and fixes, not FALSUM's existing customer adoption.

FALSUM adds a separate reproducible evaluation-material audit: measure **availability on all published decisions**; distinguish reported failures from decisions with no recorded answer; bind recorded purchases to exact historical receipt-status archives; and expose the narrow explicit contradiction between a Secure/zero-vulnerability response and its own admission of missing input. This is a measurement of observable evidence defects, not an attack on a provider or a test of code exploitability.

The [preimplementation protocol](../data/phase5aj-cross-app-evidence-protocol.json) fixes seven complete original upstream Git identities, both Truvian reported-live fixture variable names and all 12 planted + all 22 audited-v7 recorded Gig Guard decisions. Protocol commit `7e126cdf7740c726d59993d85501492f3a87f9ee`, Git blob `e7d746f957b139993681fbc7167f640d118ea8f0`. The public records were already read; this is a frozen historical retrospective replay, not blinded model validation.

## Reproduce

Python 3.11+, internet access to raw.githubusercontent.com, no API token, no wallet or payment.

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_phase5aj_cross_app_evidence.py' -v
PYTHONPATH=src python -m falsum.phase5aj_cross_app_evidence --out phase5aj-original-report.json
```

On PowerShell set `$env:PYTHONPATH = 'src'` once, then run the commands without the leading environment assignment. The report is create-only. [Fork and manually run the dedicated GitHub Actions workflow](../.github/workflows/phase5aj-cross-app-evidence.yml) for a public-safe result artifact. No external source code is executed. The source bytes must match each original Git object before parsing.

## What the frozen protocol is designed to test

| Source population | Expected answer availability | Distinction |
| --- | --- | --- |
| Truvian: two selected reported-live security fixtures | 2 categorical Secure/zero-count responses explicitly disclaim evidence | Explicit contradiction; no claim about every provider or all security answers |
| Gig Guard original planted decision set (12 cases) | 2 security answers, 10 explicit failures | Includes one recorded SHIP with a known planted bug and no security answer; missing review is not evidence of safety |
| Gig Guard audited-v7 recorded decision set (22 cases) | 15 security answers, 7 no answer records | Missing record is **not** a reported provider failure; audited controls are not independently proven bug-free |

The counts above are preregistered expected results from the independent developers' published records, not yet a new FALSUM CI outcome. The report keeps request/settlement Miner namespaces distinct, checks archived receipt hashes, amount, Intent and epoch, and verifies that every labelled decision and purchase is accounted for. It does not fetch the live receipt node or make a new request. An archived receipt-status check is not fresh settlement proof.

## Reviewer next step

A separate developer can rerun the entire check, then challenge any original field, case association, missing-answer denominator or receipt join. A mission-app builder can evaluate whether its own historical decision logs would benefit from this distinction. No endorsement, customer integration, independent AppSec expert gold or ranking improvement is claimed; source provenance is not proof of correctness of an outside claim.

The original Truvian source files and Gig Guard ledger files remain hosted at the pinned external URLs in the frozen protocol. We credit their maintainers. We publish bounded result metadata, not full response bodies or private evaluation material.
