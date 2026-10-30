# Phase 2d — pinned guidance / no network eligibility claims

The 12 realistic application-security scenarios remain **draft**; they were not independently reviewed and are not accepted Telegraph material.

Four security guidance sources now have immutable upstream Git commit links and locally archived, SHA-256 checked excerpt manifests. These curated excerpts were verified against primary source files; they are **not** snapshots of the complete upstream docs, and local integrity is **not** verification of the scenario labels.

| Source | Pinned upstream revision |
|---|---|
| django-checklist | `3bdcd29a61be034b9c9a1cea744371c12339c48e` |
| owasp-ssrf | `920293be317721982fa50324a6f26af3f29dc45e` |
| github-actions | `5ecebc9f4d708c7cfda4d3ba80224815dd6a7f1d` |
| node-tls | `97aed16adb90a720308d7ebea417c9a9db81ea26` |

## Run

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m falsum audit-scenarios data/draft-scenarios.json
PYTHONPATH=src python -m falsum check-scenarios data/draft-scenarios.json
```

The audit fails if source excerpt bytes or provenance change; the status report is fail-closed without reading source bytes. `submission_ready` always remains false until network eligibility has been independently established.

## Before training or submission

An independent domain reviewer must check the full pinned source context, each case's assumptions and selected preference, and the exact request/response presentation. A larger, balanced dataset across genuinely distinct evidence groups is still necessary. Then run the upstream Telegraph V2 `train_adapter --check-data` on reviewed triplets. No live miner or adapter results are claimed.
