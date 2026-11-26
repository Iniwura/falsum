# Phase 5BF — ACP live execution preparation

**Verified 26 November 2026. Status: prepared, pending explicit operator approval.**

No ACP job, Telegraph purchase, token transfer, signer change, deposit or wallet approval was executed in this phase. The machine-readable record is [the Phase 5BF evidence](../evidence/phase5bf-2026-11-26-acp-live-preparation.json) and the frozen preparation protocol is [the Phase 5BF protocol](../data/phase5bf-acp-live-preparation-protocol.json).

## Direct provider lookup and empty chains

The initial Phase 5BE observation of an empty registry `chains` array is superseded by the current authenticated server state. The official CLI `1.0.40` and Node SDK `@virtuals-protocol/acp-node-v2@0.1.15` now return the FALSUM provider through the independent wallet route:

```text
GET https://api.acp.virtuals.io/agents/wallet/0x012501f623e8a45c0de5716d1228d2b61f1b3a0c
```

The current response has active EVM chain records `4663`, `5042` and `8453`, the visible `verifySecurityReport` offering, fixed price `0.01` USDC and a 30-minute SLA. Marketplace search remains empty, but search is not used by this route. The authenticated provider SSE stream also connected successfully. A safe direct active-job API read returned zero jobs.

Therefore FALSUM can receive ACP jobs on the supported EVM provider path, subject to the distinction that listener readiness is not evidence that a job has already arrived. The installed CLI provider adapter also builds its local EVM client set from the configured ACP mainnet chain list rather than from the registry metadata alone.

## Exact sandbox boundary

The supported ACP self-evaluation route is the Virtuals platform's non-public sandbox: two distinct registered agents, FALSUM as seller, a separate buyer, the platform's smart-wallet/developer-wallet setup, a buyer-initiated job, and the full event lifecycle. Official ACP guidance says to top up the test buyer with USDC, recommends a $0.01 seller price and states that sandbox gas is sponsored, so ETH is not required.

`IS_TESTNET=true` is a separate ACP development configuration. Its chain list is Base Sepolia `84532`, BNB testnet `97`, Robinhood testnet `46630`, Arc testnet `5042002` and Solana devnet `500`; the current testnet session is unauthenticated. No official source identifies that CLI environment as the platform Sandbox, so the two environments must not be conflated. The ACP Developer Agreement independently describes Sandbox as the platform's non-public testing environment.

Current blocker: the platform-designated sandbox identity/access and a separate authenticated buyer session are not available. Creating a buyer agent or adding a signer would also be a permission-changing action and is therefore left for approval.

## Telegraph evidence and cost floor

The supported FALSUM target is the pinned Anchor advisory:

```text
ecosystem: crates.io
package:   anchor-lang
version:   1.0.1
advisory:  GHSA-c6rc-8jpp-2fgc
range:     >= 1.0.0 and < 1.0.2
```

Two historical `SECURITY_REVIEW_GENERAL` captures in the repository contain public x402 receipt fields. A read-only Sepolia RPC check confirmed both transaction receipts succeeded and each contained a 10,000-uUSDC transfer event. This establishes genuine historical paid intelligence and its historical settlement transaction, but neither capture is target-compatible: one reviews a JavaScript diff and the other concerns npm `lodash@4.17.15`. They cannot legitimately back an Anchor `ACCEPT` result. Reusing one in a live job can only support an explicitly fail-closed `HOLD` demonstration unless a separate caller supplies compatible, independently bound custody.

The current Telegraph devnode quote probe for an Anchor-shaped request returned `402 Payment Required` without redeeming it. Its exact x402 Base Sepolia option is 10,000 uUSDC (`$0.01`) using the listed USDC contract and a 60-second timeout. This is a quote, not a payment.

Two truthful cost floors follow:

| Route | ACP escrow | New Telegraph purchase | User gas | Result / status |
| --- | ---: | ---: | --- | --- |
| Reuse historical intelligence | `$0.01` USDC on Base mainnet | `$0.00` | `$0` only if ACP sandbox sponsorship applies | Complete lifecycle can be a `HOLD`; no new Telegraph evidence |
| Fresh compatible Anchor intelligence | `$0.01` USDC | `$0.01` quote on Base Sepolia | Not determinable before the sponsored route is selected | `$0.02` USDC before gas; blocked pending matching sandbox/test buyer |

The minimum complete ACP lifecycle that uses genuine existing Telegraph intelligence is therefore **$0.01 USDC**, but it is deliberately a `HOLD`/evidence-compatibility demonstration. The minimum route that can support a current Anchor-specific intelligence result is **$0.02 USDC before gas**, and it requires the platform-designated sandbox or a separately authenticated testnet buyer. No exact mainnet gas amount can be honestly asserted without a transaction receipt; the plan aborts if the ACP send is not sponsored and requests unapproved native gas.

## Buyer setup and exact sequence

The buyer must be a distinct registered agent and wallet. The existing FALSUM seller cannot be used as both buyer and provider for the official v2 end-to-end flow. After approval and after the platform sandbox route is identified:

1. Register/select the separate buyer agent, configure only its ACP signer, and confirm the buyer wallet has exactly the approved test USDC amount. Do not add permissions to FALSUM's Solana signer; the current provider policy remains `ACP_ONLY`.
2. Start buyer and provider event listeners. The provider waits for `job.created` and the later `requirement` message; the existing FALSUM handler prepares a plan and does not mutate ACP state.
3. On Base `8453` for the current mainnet provider path, create the offering job:

   ```text
   acp client create-job --provider 0x012501f623e8a45c0de5716d1228d2b61f1b3a0c --offering-name verifySecurityReport --requirements <exact JSON> --chain-id 8453 --evaluator <buyer-wallet> --json
   ```

   This is the first ACP on-chain receipt. `createJobFromOffering` looks up the provider by wallet, validates the exact offering, sets expiry from the 30-minute SLA and sends the requirement message off-chain. Use the buyer as evaluator so the flow exercises explicit completion.
4. When FALSUM observes the bound requirement, verify the package, exact version, advisory reference, source report and Telegraph custody. Only then authorize:

   ```text
   acp provider set-budget --job-id <jobId> --amount 0.01 --chain-id 8453 --json
   ```

   Expected receipt: budget proposal for exactly `10,000` Base USDC atomic units and a `budget.set` event.
5. When the buyer observes `budget.set`, verify the exact amount and fund:

   ```text
   acp client fund --job-id <jobId> --amount 0.01 --chain-id 8453 --json
   ```

   Expected result: one smart-wallet receipt, normally batching the USDC allowance and ACP `fund` call, followed by `job.funded`. This is the only ACP escrow spend in the first job.
6. On `job.funded`, FALSUM independently checks the authenticated history, source-bound Anchor evidence and caller-supplied Telegraph custody. For the historical reuse route custody is deliberately not bound to the Anchor target, so the prepared deliverable is `HOLD`. If the fresh compatible route is used, the deliverable is produced only after the new receipt is bound. Submit only after the event includes the authorized `submit` tool:

   ```text
   acp provider submit --job-id <jobId> --deliverable <prepared JSON> --chain-id 8453 --json
   ```

   Expected receipt: provider submit transaction and `job.submitted`, with the deliverable hash stored by ACP.
7. Buyer independently checks the structured result, then completes the job:

   ```text
   acp client complete --job-id <jobId> --chain-id 8453 --reason "Validated source-bound result and evidence custody" --json
   ```

   Expected receipt: evaluator completion transaction, `job.completed` and release of the `$0.01` escrow under the platform's settlement rules. Do not add a transfer hook or subscription; both would increase scope and cost.

The expected on-chain ACP receipts are therefore five legs: create, set-budget, fund (allowance plus fund inside one smart-wallet submission where required), submit and complete. Requirement messages and lifecycle event notifications are off-chain. Actual receipt hashes, `gasUsed`, effective gas price, user-operation fee and final settlement must be recorded from the execution response; they are not fabricated in this preparation record.

## Approval gate

The first executable packet needs approval for a distinct buyer agent/signer and a maximum of `$0.01` ACP USDC for the historical `HOLD` run, or `$0.02` USDC before gas for a fresh compatible Anchor run. The latter additionally needs an authenticated platform-designated sandbox/test-buyer route. Any manual wallet approval request, extra signer permission, native-gas requirement or Telegraph charge beyond those caps is an abort condition.

The unexpected manual approval prompt encountered during a supposedly read-only `acp job list --all --json` probe was not accepted. A direct authenticated API read was used instead. This remains a tooling-policy warning, not authorization to approve a wallet action.

## References

- [ACP v2 examples](https://github.com/Virtual-Protocol/acp-node-v2/blob/main/src/examples/README.md)
- [ACP Python sandbox guidance](https://github.com/Virtual-Protocol/acp-python)
- [ACP Developer Agreement](https://app.virtuals.io/acp_developer_agreement.pdf)
- [Current Telegraph intent metadata](https://devnode.telegraphprotocol.com/engine/v1/intents/SECURITY_REVIEW_GENERAL)
- [Current Telegraph ask endpoint](https://devnode.telegraphprotocol.com/engine/v1/ask)
- [Telegraph V2 payment/job changes](https://docs.telegraphprotocol.com/docs/whats-new-v2)
- [Historical Phase 5T capture record](../evidence/phase5t-2026-11-21-actual-telegraph-app-consumption.json)
