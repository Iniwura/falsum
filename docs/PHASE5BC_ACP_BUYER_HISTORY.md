# Phase 5BC — independent ACP buyer workflow

## Live gate

We are pursuing use case #08 without requiring another contestant's integration.
Register the buyer and seller through the official Virtuals ACP sandbox registration
at https://app.virtuals.io/acp/new (the old /acp/join route returned 404 in the entrant's browser). Organizer guidance distinguishes the sandbox
from the dev/testnet CLI auth environment, which may require separate access.
Do not assume Base Sepolia is the correct sandbox chain: obtain the actual chain
and job ID from the registered platform. Do not fund, add signers, authorize
payments or release escrow merely to test this adapter.

Current upstream CLI 1.0.40 documents browser OAuth and a read-only v2 job
history command. Source identities are pinned in the protocol. The repository's
package metadata requires Node >=20.19.0. Read its official skill before use.
The execution environment could not resolve the npm registry; CLI auth and
actual ACP operations have not been executed.

## Read-only integration

After authorized account setup and actual job creation, retain the buyer's exact
original requirement and known job ID, chain and buyer address independently of
the seller. Capture the official read-only history:

```sh
acp job history --job-id YOUR_JOB_ID --chain-id ACTUAL_CHAIN_ID --json > history.json
PYTHONPATH=src python -m falsum.phase5bc_acp_buyer_history --expected buyer-context.json --history history.json --trusted-custody purchase-custody.json
```

Buyer context consists of buyer address and Phase 5BB job object. The offering
requirement is the job schema, target and intent fields, without the job ID
(which is assigned after creation). The seller must submit inline JSON conforming
to the Phase 5BB deliverable. The adapter requires one exact buyer-authored
requirement and a chronological created / budget / funded / submitted sequence.
It never follows seller-controlled URLs. It reads the submitted system event's
deliverable and preserves its reported hash without claiming cryptographic hash
verification. It invokes the existing source-bound acceptance evaluator and
fails closed on ambiguity. Trusted purchase custody must be independently
derived from the actual Telegraph client and purchase record; no seller-created
receipt or manually fabricated custody is accepted as evidence of a real job.
See PHASE5BB_ACP_SECURITY_ACCEPTANCE.md for the exact fields.

The history input is not authenticated by FALSUM itself. The caller must use its
own authenticated ACP client and independently verify the current job state.
Any parse error, unknown schema, unknown hash format or stale/terminal state must
be treated as HOLD. The adapter is deliberately read-only; it never generates
or executes a settlement command.

## Verification boundary

CI authenticates original upstream CLI source bytes and tests constructed history
wrappers against an authentic pinned Anchor advisory. No live ACP job, actual
intelligence purchase, real settlement, external customer adoption or official
evaluation-pool improvement is claimed. The next milestone is one actual
authorized sandbox job, followed by correct/incorrect/incomplete deliverable
replays clearly distinguished from live jobs.
