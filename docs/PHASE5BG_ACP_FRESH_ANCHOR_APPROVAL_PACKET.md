# Phase 5BG — fresh Anchor intelligence approval packet

**Status: BLOCKED_PENDING_EXPLICIT_APPROVAL_AND_SANDBOX_CONFIRMATION (27 November 2026).**

This is a read-only preparation record. No buyer agent, signer, job, deposit,
Telegraph payment, token transfer, wallet approval or ACP mutation was executed.
The proposed ceiling is **$0.02 USDC total**, not an authorization to spend.

## Decision

The preferred route is one outer FALSUM `verifySecurityReport` ACP job on the
Virtuals platform's non-public developer Sandbox, backed by one fresh Telegraph
`SECURITY_REVIEW_GENERAL` call for the pinned Anchor target. The target is:

```text
ecosystem: crates.io
package:   anchor-lang
version:   1.0.1
reference: GHSA-c6rc-8jpp-2fgc
```

The known principal floor is `$0.01` for the Telegraph call plus `$0.01` for
the FALSUM ACP escrow: `$0.02` USDC before gas. The packet authorizes no native
gas and no amount above this ceiling. If either route is not sponsored/gasless,
or if the current contract requires a second paid ACP report job, stop: the
proposed budget is insufficient.

## Exact supported Virtuals sandbox route

The current official route is the Virtuals platform, not the installed CLI's
`IS_TESTNET=true` switch:

1. Open the ACP application at `https://app.virtuals.io/acp`.
2. For the platform developer flow, use the ACP Sandbox/Sandbox Butler mode.
   The Butler documentation distinguishes `Sandbox` from `Production`; Sandbox
   can initiate jobs with sandbox and graduated agents.
3. For the SDK self-evaluation route, register two distinct agents: a separate
   buyer/requestor and FALSUM as seller/provider. Create the platform smart
   wallet and whitelist the developer wallet where required. The buyer must
   initiate a job before a sandbox agent appears in the sandbox view.

The public official guidance says sandbox gas is not required and recommends a
`$0.01` service price. The Butler wallet guide says its USDC deposit is on Base
mainnet only. This pins the approved ACP target to **Base mainnet, chain 8453**
for the current FALSUM offering, subject to one read-only confirmation in the
actual sandbox session before any signing. `IS_TESTNET=true` exposes a separate
CLI/API configuration including Base Sepolia `84532`; it is not evidence that
the platform Sandbox is that environment.

No platform-designated sandbox identity or authenticated separate buyer is
available in the current local session. This is the external blocker; creating
the buyer or signer would be a permission-changing action and is left for
approval.

## Empty `chains` array and receive capability

The original empty registry `chains` observation is historical. The current
authenticated direct lookup returns active EVM chains `4663`, `5042` and `8453`,
the visible offering and the FALSUM wallet. More importantly, the installed SDK
does not use the registry `chains` array as the only receive gate:

- `createJobByOfferingName` resolves the provider by wallet and selects its
  offering; it does not reject solely because registry metadata once had an
  empty `chains` array.
- The provider listener advertises its locally configured supported chain IDs in
  the SSE `x-supported-chains` header. The current FALSUM mainnet adapter has
  `8453` configured.
- The authenticated FALSUM SSE listener connected successfully, but no live job
  has been observed. Therefore this is a capability/readiness conclusion, not
  proof of a received or completed commercial job.

FALSUM can receive a job on the current mainnet ACP path despite the historical
empty metadata. It cannot be declared ready for a Base Sepolia job merely from
the CLI testnet chain list; a separate authenticated testnet seller or the
platform Sandbox route would be required.

## Buyer setup, with no secrets stored

The buyer is a new, distinct **Requestor** agent and wallet. It must not reuse
FALSUM's provider identity or signer. The buyer setup after approval is:

- register the buyer in the Virtuals ACP Sandbox;
- create/confirm its platform smart wallet and developer-wallet whitelist;
- add only the ACP-restricted signer required by the platform; never use an
  unrestricted signer and do not modify FALSUM's `ACP_ONLY` or Solana
  `DENY_ALL` policies;
- configure the official ACP v2 buyer listener with the buyer wallet, wallet ID,
  signer and Base `8453` chain;
- configure an official Privy/x402 EVM client for the same buyer wallet on
  Telegraph's quoted network only if the wallet passes a read-only typed-data
  compatibility check. No alternate signer is authorized by this packet.

The buyer's self-controlled run is a **constructed self-evaluation**, not
independent customer adoption, and must be labelled that way in all evidence.

## Networks, assets and recipients

| Leg | Network | Asset | Exact recipient / contract | Amount |
| --- | --- | --- | --- | ---: |
| Telegraph quote/payment | Base Sepolia, `eip155:84532` | Circle USDC `0x036CbD53842c5426634e7929541eC2318f3dCF7e`, 6 decimals | `0xC0A3FB6dF3F1f4B54617d29ffbdA4663Af5F96e2e` | `10,000` uUSDC = `$0.01` |
| ACP job | Base mainnet, `8453` | USDC `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`, 6 decimals | ACP contract `0x238E541BfefD82238730D00a2208E5497F1832E0` | `10,000` raw units = `$0.01` |

These are different networks and, on Base Sepolia, different USDC registries.
They must be funded and verified separately. Do not substitute the ACP testnet
USDC `0xECc22a...` or the Base mainnet token into the Telegraph payment.

## Exact transaction and evidence sequence

All steps below are gated by approval and the preflight checks. The sequence is
not permission to execute it.

### Preflight — read-only, abort on any failure

1. Confirm the Virtuals UI is the official ACP Sandbox/Sandbox Butler route and
   that FALSUM's `verifySecurityReport` offering resolves by wallet on the same
   ACP chain selected for the job.
2. Confirm buyer and seller wallets are distinct, the seller is FALSUM, the
   provider SSE listener is connected, and the seller offering is exactly
   `$0.01`, 30 minutes and `requiredFunds=false`.
3. Confirm the platform reports sponsored/no-native-gas execution for the buyer
   and seller. For every ACP smart-wallet send, require a sponsored/user-op
   result or equivalent fee of zero before allowing the next action. A balance
   read alone is not proof of sponsorship.
4. Confirm the Telegraph x402 challenge still offers the exact Base Sepolia
   option above, `scheme=exact`, `amount=10000` and `maxTimeoutSeconds=60`.
5. Confirm the buyer's wallet can sign the EIP-3009 x402 authorization on Base
   Sepolia without a native-gas transaction. If the buyer smart wallet is not
   accepted by the x402 client/facilitator, stop; do not add a second signer.
6. Confirm whether Phase 5BD's `report_job` is allowed to be a Telegraph report
   descriptor. If Virtuals/FALSUM requires a second paid ACP report job, the
   floor becomes `$0.03` (`$0.01` Telegraph + two `$0.01` ACP jobs), so the
   `$0.02` cap fails and no job may be created.

### Telegraph — fresh genuine intelligence, one payment

7. Send the exact canonical request body, with bytes preserved:

   ```json
   {"intent":"SECURITY_REVIEW_GENERAL","params":{"target":"Review anchor-lang 1.0.1 for GHSA-c6rc-8jpp-2fgc applicability"}}
   ```

   Its current canonical UTF-8 SHA-256 is
   `27fec1e82b8a4aab3a930a0092f33f9e63d07e604474fe4526408ec57d750386`.
8. Select only the exact Base Sepolia requirement. Sign the EIP-3009 payment
   authorization and retry the same request. Do not pay any alternate quote.
9. Preserve the raw request bytes, 402 requirements, signed payment envelope,
   raw 200 response bytes, `payment-response` header, `x-telegraph-receipt`
   header and the Base Sepolia transaction receipt. Independently verify the
   receipt status, token, amount, recipient, network and transaction hash.

### ACP — one outer verification job

10. Construct the requirement from the exact FALSUM schema. The outer job must
    use the buyer as evaluator and a report descriptor that is distinct from the
    outer ACP job. The requirement digest is computed from the exact transmitted
    compact JSON, not from a reconstructed object.
11. Create the job with the official v2 equivalent of
    `createJobByOfferingName(8453, "verifySecurityReport", FALSUM_WALLET, ...)`.
    Expected result: an ACP `job.created` receipt/event and one buyer requirement
    message. The request must not contain `trusted_custody`.
12. FALSUM accepts the requirement event, verifies the exact buyer and offering,
    and proposes `setBudget(USDC(0.01, 8453))`. Expected result: `budget.set`.
13. Buyer verifies the exact budget and calls `fund(USDC(0.01, 8453))`. For EVM
    ACP this may be a sponsored smart-wallet batch containing `approve(10,000)`
    to the ACP contract followed by `fund(10,000)` to the ACP contract. Expected
    result: `job.funded`; no transfer hook or subscription is used.
14. On `job.funded`, run the source-bound Anchor check and the independent
    Telegraph binding check. Only a fully bound result may be submitted. The
    provider then calls `submit(deliverable)`; expected result: a submit receipt
    and `job.submitted`.
15. The buyer/evaluator checks the structured deliverable and calls
    `complete(reason)`. Expected result: completion receipt, `job.completed` and
    release of the `$0.01` ACP escrow. `reject` is used instead if the binding
    check fails; never complete a HOLD as ACCEPT.

Expected ACP receipts are `create`, `setBudget`, `fund` (possibly allowance plus
fund in one smart-wallet submission), `submit` and `complete`. Record every
transaction hash, status, gas-used, effective gas price, user-operation fee and
final escrow state. No value is inferred from an event label.

## Telegraph-to-Anchor-to-ACP binding verdict

The existing historical Telegraph receipts are not compatible: they concern a
JavaScript diff and `lodash@4.17.15`. Their public receipt fields prove historical
payment and a transaction, but do not bind a new Anchor request, a new response
or an ACP job.

The current FALSUM acceptance gate also intentionally accepts a caller-supplied
five-field custody wrapper and documents that it does not authenticate settlement.
The x402 receipt itself contains intent, amount, chain, payer/miner, receipt hash
and transaction hash; it does not carry the exact Anchor request digest, response
digest or ACP job ID. Consequently **the binding is not independently verified
yet**.

The fresh run may claim binding only if an independent evidence bundle recomputes
all of these links:

```text
Telegraph request bytes
  -> request_sha256
Telegraph response bytes + receipt headers + verified token transfer
  -> response_sha256 + receipt_hash + tx_hash
ACP requirement bytes
  -> requirement_sha256 containing the exact report target and custody reference
ACP authenticated job history
  -> outer chain_id/job_id + requirement_sha256
FALSUM response
  -> response_sha256 and the same receipt_hash
```

If any link is absent, seller-supplied, or only asserted by a receipt-shaped
JSON string, FALSUM must return `HOLD`; it must not claim independent binding or
security clearance.

## Approval boundary and blockers

Approval would be needed for only the following external actions: create the
distinct buyer agent, configure its restricted ACP signer, fund exactly the two
approved USDC balances on their respective networks, issue the one Telegraph
x402 payment, and run one outer ACP verification job. Approval does **not**
authorize native gas, a second signer, a second ACP report job, alternate
Telegraph quotes, tokenization, hosting or mainnet spending beyond the stated
cap.

Current blockers are concrete:

- the platform Sandbox identity/access and separate authenticated buyer are not
  present locally;
- live sponsor confirmation is not exposed by the read-only CLI/SDK session;
- the existing FALSUM custody schema does not itself cryptographically bind a
  Telegraph request/response to an ACP job;
- if the platform requires an actual second ACP report job, the proposed `$0.02`
  ceiling is mathematically insufficient.

No transaction should be executed until these are resolved and the operator
explicitly approves the bounded packet.

## Sources

- [ACP Tech Playbook](https://whitepaper.virtuals.io/builders-hub/acp-tech-playbook.md)
- [Sandbox Butler route](https://whitepaper.virtuals.io/acp/acp-dev-onboarding-guide/customize-agent/simulate-agent-with-sandbox-butler)
- [Butler Base-mainnet wallet guide](https://whitepaper.virtuals.io/info-hub/user-hub/butler-quick-start-guide.md)
- [Official ACP v2 examples](https://github.com/Virtual-Protocol/acp-node-v2/blob/main/src/examples/README.md)
- [Official ACP CLI](https://github.com/Virtual-Protocol/acp-cli)
- [Current Telegraph quote endpoint](https://devnode.telegraphprotocol.com/engine/v1/ask)
- [Current Telegraph intent metadata](https://devnode.telegraphprotocol.com/engine/v1/intents/SECURITY_REVIEW_GENERAL)
- [Historical Phase 5T capture record](../evidence/phase5t-2026-11-21-actual-telegraph-app-consumption.json)
