# Phase 5BE — ACP provider event integration

**Status: implementation verified on 26 November 2026; live job and settlement not verified.**

The initial direct-lookup observation recorded below showed an empty registry
`chains` array. That observation is historical and was superseded by the
current authenticated server state verified in [Phase 5BF](PHASE5BF_ACP_LIVE_EXECUTION_PREP.md),
which returns active EVM chains `4663`, `5042` and `8453`. The original probe
record remains unchanged for provenance.

## What is verified

The local checkout is synchronized with `origin/main` at `d62c862`, which
contains Phase 5BD / PR #121. The installed official tooling is:

| Component | Verified value |
| --- | --- |
| ACP CLI | `1.0.40` |
| ACP Node SDK | `@virtuals-protocol/acp-node-v2` `0.1.15` |
| API environment | mainnet (`https://api.acp.virtuals.io`) |
| direct lookup | `AcpApiClient.getAgentByWalletAddress()` → `GET /agents/wallet/{walletAddress}` |
| FALSUM | agent `01a21868-850b-7c91-80de-65e2add32087`, role `HYBRID` |
| Offering | `verifySecurityReport`, fixed `0.01`, 30-minute SLA, visible |
| agent chains | empty |
| signer policy | `ACP_ONLY` |

The direct SDK lookup authenticated by signing the exact `acp-auth:<timestamp>`
message supplied to the SDK callback. It returned FALSUM and the offering above.
The probe performed no job creation, funding, submission, settlement, token
transfer or paid Telegraph purchase. No credential, token or private key is
stored in this repository.

## Sandbox boundary

The installed CLI has a separate `IS_TESTNET=true` environment. Its read-only
chain probe returned Base Sepolia (`84532`), BNB Smart Chain Testnet (`97`),
Robinhood Chain Testnet (`46630`), Arc Testnet (`5042002`) and Solana Devnet
(`500`). That output proves a testnet API/chain configuration exists; it does
**not** prove that the official hackathon ACP sandbox is the same environment.

The older official ACP SDK example describes a dashboard sandbox with two
registered agents, a developer-wallet whitelist and a buyer-initiated test job.
The current CLI documents mainnet/testnet as configuration environments but
does not expose a flag that identifies a platform sandbox. Therefore FALSUM
does not treat Base Sepolia or `IS_TESTNET=true` as sandbox eligibility.

The next live gate is an organizer/platform-designated sandbox workflow with an
actual chain ID and job ID. Until that is available, no buyer agent is created,
no funds are added, and no job mutation is attempted.

## Prepare-only event handler

`src/falsum/phase5be_acp_provider_events.py` consumes the event envelopes
returned by `acp events drain` or an equivalent SDK event callback:

1. `job.created` is recorded and the handler waits for the later requirement
   message, as required by the official provider flow.
2. The requirement is parsed, bound to one buyer, and restricted to
   `verifySecurityReport`. The handler returns a `READY_FOR_BUDGET` plan for
   the configured `0.01` offering price; it does not call `set-budget`.
3. On `job.funded`, it requires the event's `submit` tool, an independently
   supplied authenticated history, and optional caller-verified Telegraph
   custody. It delegates to Phase 5BD and returns `READY_TO_SUBMIT` with the
   nested `ACCEPT`, `REJECT` or `HOLD` recommendation.
4. Submitted and terminal events are observed only. No plan executes an ACP
   mutation; every plan records `mutation_executed: false`.

The handler rejects duplicate requirements, changed buyers, wrong offerings,
wrong provider identity, out-of-order lifecycle events, missing history and
missing event authorization. It never accepts `trusted_custody` inside the
buyer requirement.

Reproduce the constructed event harness with:

```text
PYTHONPATH=src python -m unittest discover -s tests -p "test_phase5be_acp_provider_events.py" -v
```

The three reproducible cases are:

| Case | Custody input | Nested result | Interpretation |
| --- | --- | --- | --- |
| affected advisory, correct claim | caller-verified wrapper | `ACCEPT` | scoped applicability corroborated |
| affected advisory, contradicted claim | caller-verified wrapper | `REJECT` | pinned advisory contradicts claim |
| correct claim, no custody | absent | `HOLD` | purchase custody cannot be verified |

These are constructed fixtures using an authentic pinned advisory. They are
not a live ACP job, paid Telegraph purchase, on-chain receipt, settlement,
independent customer action or official Evaluator score.

## Competitive relevance

The official Season II rules require a real working contribution, a real
Telegraph integration, repeatable results, safe handling and accurate network
claims. For Evaluators, delivery selection prioritizes distinct commercial
missions and H2 workflows, missing mission-critical Intent coverage, and
technical quality; ties then consider proven measurement improvement or
valuable new coverage. FALSUM's defensible differentiator is the explicit
separation of event-bound job handling, source-bound security applicability and
caller-supplied Telegraph custody, with bounded `HOLD` rather than fabricated
settlement authority. No live purchase, independent adoption, competitive
ranking improvement or 90+/100 organizer score is claimed.

See [the official rules](https://hackathon.telegraphprotocol.com/rules),
[Phase 5BB](PHASE5BB_ACP_SECURITY_ACCEPTANCE.md),
[Phase 5BC](PHASE5BC_ACP_BUYER_HISTORY.md), and
[Phase 5BD](PHASE5BD_ACP_PROVIDER_PREPARE.md).
