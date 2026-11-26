# Phase 5BD — verifySecurityReport provider preparation

On November 26 the entrant showed the Virtuals dashboard with FALSUM registered and
the verifySecurityReport offering created at USD 0.01, 30-minute SLA, text requirements
and deliverables. This is operator-observed registration metadata, not authenticated
API proof, a working provider, a graduated agent or a completed job. Console hosting
was not enabled. The /acp/join route returned 404 in the entrant's browser; the
working creation route was https://app.virtuals.io/acp/new.

## Local execution, no paid hosting

The provider now has a separate read-only preparation path for the actual offering.
A *verification service job* requests independent evaluation of an *original security
report job*. They are different jobs. The latter uses Phase 5BB's exact report-job
and deliverable structures. The offering's text requirements can carry JSON.

Required request fields: schema (falsum.acp.verify.request.v1), offering
(verifySecurityReport), report_job (Phase 5BB job), report (Phase 5BB deliverable).
Do not include trusted_custody in the request. It is a separate trusted local file,
never derived from a buyer/seller assertion or a receipt-shaped string. Without
independently verified purchase evidence, the report evaluation is HOLD.

The live-bound path is an explicit `falsum.acp.verify.request.v2` extension. It
adds `telegraph_binding` and changes the report schema to
`falsum.acp.verify.report.v2`, whose `source_response_sha256` must equal the
actual purchased Telegraph response digest. The provider accepts v2 only when
the event handler has first verified the raw Telegraph/transfer/ACP evidence
with `phase5bg_telegraph_acp_binding`; a missing or mismatched verified binding
returns HOLD and cannot reach `READY_TO_SUBMIT`. The v1 path remains available
for the earlier constructed acceptance tests and never claims live Telegraph
custody.

The local operator context is chain_id, decimal-string job_id, buyer (actual EVM
address), offering, and requirement_digest (SHA256 of the exact independently
retained request, sorted compact ASCII JSON; see Phase 5BB digest). The caller must
derive outer job identity and offering from its authenticated provider session;
a local context file by itself proves nothing. The adapter requires the exact
funded lifecycle and one buyer requirement between creation and budget, verifies
its sender and digest, and refuses submitted or terminal jobs. If the actual
sandbox history differs, stop and inspect rather than inventing a compatible event.

```sh
acp job history --job-id ACTUAL_JOB_ID --chain-id ACTUAL_CHAIN_ID --json > history.json
PYTHONPATH=src python -m falsum.phase5bd_acp_provider_prepare --context context.json --history history.json --trusted-custody custody.json
```

The event planner accepts a verified v2 manifest with `--telegraph-binding`.
It does not execute a mutation; it only emits a `READY_TO_SUBMIT` plan after
the exact funded lifecycle and the strict binding verifier both pass.

The command emits prepared=true with a structured deliverable only when the outer
job contract checks pass. It does not submit or sign anything. The report decision
is nested at deliverable.report_evaluation.recommendation. A HOLD is a valid
bounded verification result, not authority to settle. A prepared=false result is
not a deliverable. The authorized operator must check current status, scope,
expiry, buyer/provider roles and actual purchase custody before any action.
Do not accept customer jobs until a live sandbox workflow and delivery capability
are verified. Hide the offering if its public visibility permits.

## What remains

The official upstream provider submit implementation is pinned and checked in
CI, but SDK authentication, event capture, funding, real Telegraph purchase
binding and actual ACP submission remain unverified. Local tests use constructed
history and custody wrappers with an authentic pinned advisory. Never present
them as a real paid job or a live transaction. No signer or funds are necessary
for the local preparation checks. To proceed with live execution, the entrant's
own authenticated ACP CLI session is required, with any transaction separately
authorized. Do not activate Console hosting or tokenize the agent.
