# Phase 3O — historical 20-row eligibility milestone (superseded by Phase 3P)

**Historical checkpoint; updated after the bounty comment was posted:** [Phase 3P public verified receipt](../evidence/phase3p-2026-11-02-bounty-claim.json) confirms that [the `/submit` comment](https://github.com/telegraphprotocol/bounties/issues/96#issuecomment-6588168396) is **already posted**. Its maintainer review is **pending**. The remaining text below documents the earlier preparation stage, not the current “submit pending” status.

**2 November 2026: first confirmed eligibility milestone for FALSUM.** The operator supplied a new screenshot of their signed-in Anjoman [Evaluators](https://anjoman.ai/dashboard/eval) page for **`SECURITY_REVIEW_GENERAL`**. The account's own history now displays **`Eligible: 20`** and the newest 10 of its 20 rows are each labeled **Eligible**. This follows the same batch's prior **20 stored, zero duplicates and zero refused** receipt and **20 Admitted** history.

This is **user-interface evidence of 20 eligible rows**, satisfying the network status condition for an evaluation-material contribution under [Telegraph bounty #96](https://github.com/telegraphprotocol/bounties/issues/96). It is **not** an independently downloaded node API receipt, a posted or maintainer-approved bounty claim, an evaluator adapter registration, or a final hackathon submission. The user privately controls the account.

### Evidence and privacy boundary

[Permanent redacted status-only record](../evidence/phase3o-2026-11-02-20-eligible.json) says exactly what the account UI showed. The actual screenshot, wallet address, login email, hidden case text, hidden answers, submission signatures and row hashes are **not in the public GitHub repository**. Do not attach any of these private materials to bounty comments. Never expose hidden evaluation pool prompts or exact wrong answers in demo, docs, clips, issues or README.

The 20 rows were **AI-assisted, declared with `source_kind: llm`, provenance class unverified**. Pool `eligible` does not retroactively certify expert security review. The original and Phase 3K LoRAs still failed context-dependent preference tests and remain research-only.

### Next necessary user approval: `/submit` to bounty #96

The [bounty](https://github.com/telegraphprotocol/bounties/issues/96) requires a public `/submit` comment with the exact **contributor wallet address** (or a module registration identifier for the separate adapter path). FALSUM's evaluation material is now eligible and is ready to *claim*, but the publicly posted contributor address must be approved by the operator. Use the **actual contributor account wallet shown by Anjoman**, not another wallet or a partial UI alias.

**Prepared comment template. Do not publish the placeholder and do not claim maintainer approval.**

```text
/submit

SECURITY_REVIEW_GENERAL — evaluation material contribution.

My Anjoman contributor address: <OPERATOR-CONFIRMED-CONTRIBUTOR-WALLET-ADDRESS>

20 source-referenced, AI-assisted (`source_kind: llm`) evaluation preference pairs were submitted on 2 November 2026. My Anjoman Evaluators account now shows Eligible: 20 after the epoch rollover. The material is already marked eligible in my account.

Public research repo and provenance methodology: https://github.com/Iniwura/falsum
Public eligibility checkpoint (no hidden evaluation content): https://github.com/Iniwura/falsum/blob/main/evidence/phase3o-2026-11-02-20-eligible.json

This claim covers the evaluation-material contribution only, not a registered evaluator adapter. Please independently verify the eligible rows under the contributor address and mark the contribution verified if the rules are met.
```

Once posted, preserve its actual GitHub comment URL and wait for the bounty maintainer's verification response. The issue is allowed to remain open until *all* deliverables have been completed by all contributors, and passing the bounty condition **does not guarantee a Season II hackathon prize**.

### Winning-track next work, separate from this claim

Prepare a strong judge-facing submission with a concise, reproducible security evaluation methodology, verifiable upstream patch/test evidence, safe synthetic demonstration and results, clearly separated from hidden network evaluation material. Before attempting another evaluator adapter submission, address the old model's repeated failure to reverse preference rankings when the security context changes. The main hackathon deadline was documented as **1 December 2026 23:59 UTC**; verify the latest official requirements and submit a separate final hackathon entry before the deadline.

**Current gates:** 20 user-UI eligible, `/submit` **not posted**, bounty maintainer approval **not received**, evaluator adapter **not registered**.
